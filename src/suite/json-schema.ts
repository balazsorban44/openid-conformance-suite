/**
 * JSON schema validation as upstream does it (util/validation/JsonSchemaValidation on the networknt validator): a
 * JSON schema validator (draft-04 to 2020-12) with networknt's error messages and instance paths, the result's split
 * into structural and unknown-property errors (JsonSchemaValidationResult), and JsonSchemaValidationException.
 */
import { readFileSync } from "node:fs";
import { isIP } from "node:net";
import { NamedError } from "./errors.ts";
import { isJsonArray, isJsonObject, jsonEquals, parseJson, type JsonObject, type JsonValue } from "./json.ts";

/**
 * Replaces networknt `com.networknt.schema.path.NodePath`: a path of property names (strings) and array indexes /
 * composite branch indexes (numbers). `toString()` renders the networknt `PathType.LEGACY` form
 * (`$.credentials[0].unexpected`) for instance locations.
 */
export class NodePath {
	private readonly elements: readonly (string | number)[];

	constructor(elements: readonly (string | number)[] = []) {
		this.elements = elements;
	}

	getNameCount(): number {
		return this.elements.length;
	}

	getElement(index: number): string | number {
		return this.elements[index];
	}

	getParent(): NodePath | null {
		return this.elements.length === 0 ? null : new NodePath(this.elements.slice(0, -1));
	}

	append(element: string | number): NodePath {
		return new NodePath([...this.elements, element]);
	}

	equals(other: unknown): boolean {
		return (
			other instanceof NodePath &&
			other.elements.length === this.elements.length &&
			other.elements.every((e, i) => e === this.elements[i])
		);
	}

	/** A string usable as a map key (distinguishes "0" from 0). */
	key(): string {
		return JSON.stringify(this.elements);
	}

	toString(): string {
		let s = "$";
		for (const e of this.elements) {
			if (typeof e === "number") {
				s += "[" + e + "]";
			} else {
				s +=
					"." +
					e
						.replace(/\n/g, "\\n")
						.replace(/\t/g, "\\t")
						.replace(/\r/g, "\\r")
						// oxlint-disable-next-line no-control-regex
						.replace(/\u0008/g, "\\b")
						.replace(/\f/g, "\\f");
			}
		}
		return s;
	}
}

/**
 * Replaces networknt `com.networknt.schema.Error`: one validation error. `getMessage()` is the networknt message
 * without the location prefix (e.g. "integer found, string expected").
 */
export class SchemaValidationError {
	readonly keyword: string;
	readonly message: string;
	readonly property: string | null;
	readonly instanceLocation: NodePath;
	readonly evaluationPath: NodePath;
	readonly instanceNode: JsonValue | undefined;

	constructor(
		keyword: string,
		message: string,
		instanceLocation: NodePath,
		evaluationPath: NodePath,
		property: string | null = null,
		instanceNode?: JsonValue,
	) {
		this.keyword = keyword;
		this.message = message;
		this.instanceLocation = instanceLocation;
		this.evaluationPath = evaluationPath;
		this.property = property;
		this.instanceNode = instanceNode;
	}

	getKeyword(): string {
		return this.keyword;
	}

	getMessage(): string {
		return this.message;
	}

	getProperty(): string | null {
		return this.property;
	}

	getInstanceLocation(): NodePath {
		return this.instanceLocation;
	}

	getEvaluationPath(): NodePath {
		return this.evaluationPath;
	}

	toString(): string {
		return this.instanceLocation.toString() + ": " + this.message;
	}
}

class Partition {
	readonly structural: SchemaValidationError[] = [];
	readonly unknown: SchemaValidationError[] = [];
}

function isUnknownPropertyError(m: SchemaValidationError): boolean {
	const type = m.getKeyword();
	return "additionalProperties" === type || "unevaluatedProperties" === type;
}

/**
 * Drops `unevaluatedProperties` errors that fired only because a subschema for that very
 * property failed. `unevaluatedProperties` works off the property-name annotations the
 * sibling subschemas produce, and a subschema that fails produces none - so a spec-defined
 * member contributed by, say, an `allOf`/`if`/`then` branch is reported as
 * "unevaluated" as soon as anything inside it is invalid, on top of the error that is inside
 * it. Reporting the container as an unknown property is wrong: the schema plainly knows it.
 *
 * <p>An error located strictly inside property P is the marker for that, because it can only
 * exist if some subschema applied to P (and failed). When nothing applies to P - the case
 * `unevaluatedProperties` is meant to catch - nothing can produce an error inside it,
 * so a genuine unknown-property report is never dropped here.</p>
 */
function withoutCascadedUnevaluatedErrors(errors: SchemaValidationError[]): SchemaValidationError[] {
	const kept: SchemaValidationError[] = [];
	for (const error of errors) {
		if (
			"unevaluatedProperties" === error.getKeyword() &&
			error.getProperty() != null &&
			hasErrorInsideProperty(errors, error.getInstanceLocation(), error.getProperty() as string)
		) {
			continue;
		}
		kept.push(error);
	}
	return kept;
}

function hasErrorInsideProperty(errors: SchemaValidationError[], objectLocation: NodePath, property: string): boolean {
	const depth = objectLocation.getNameCount();
	for (const error of errors) {
		const location = error.getInstanceLocation();
		if (location.getNameCount() <= depth || property !== location.getElement(depth)) {
			continue;
		}
		let sameObject = true;
		for (let i = 0; i < depth; i++) {
			if (objectLocation.getElement(i) !== location.getElement(i)) {
				sameObject = false;
				break;
			}
		}
		if (sameObject) {
			return true;
		}
	}
	return false;
}

function classify(errors: SchemaValidationError[], fromIndex: number, partition: Partition): void {
	const compositeGroups = new Map<string, { prefix: NodePath; errors: SchemaValidationError[] }>();
	for (const error of errors) {
		const composite = compositePrefix(error, fromIndex);
		if (composite != null) {
			const k = composite.key();
			let group = compositeGroups.get(k);
			if (group == null) {
				group = { prefix: composite, errors: [] };
				compositeGroups.set(k, group);
			}
			group.errors.push(error);
		} else if (isUnknownPropertyError(error)) {
			partition.unknown.push(error);
		} else {
			partition.structural.push(error);
		}
	}
	for (const group of compositeGroups.values()) {
		classifyComposite(group.prefix.getNameCount(), group.errors, partition);
	}
}

function classifyComposite(prefixLength: number, errors: SchemaValidationError[], partition: Partition): void {
	// The composite's own summary error (oneOf reports "must be valid to one and only one
	// schema"; anyOf produces no summary in this validator) vs the per-branch errors, keyed
	// by the branch index that follows the composite keyword in the evaluation path.
	const summaryErrors: SchemaValidationError[] = [];
	const branches = new Map<string | number, SchemaValidationError[]>();
	for (const error of errors) {
		const path = error.getEvaluationPath();
		if (path.getNameCount() === prefixLength) {
			summaryErrors.push(error);
		} else {
			const branch = path.getElement(prefixLength);
			let list = branches.get(branch);
			if (list == null) {
				list = [];
				branches.set(branch, list);
			}
			list.push(error);
		}
	}
	const branchPartitions: Partition[] = [];
	for (const branchErrors of branches.values()) {
		const branchPartition = new Partition();
		classify(branchErrors, prefixLength + 1, branchPartition);
		branchPartitions.push(branchPartition);
	}
	let matchable: Partition | null = null;
	for (const candidate of branchPartitions) {
		if (
			candidate.structural.length === 0 &&
			(matchable == null || candidate.unknown.length < matchable.unknown.length)
		) {
			matchable = candidate;
		}
	}
	if (matchable != null) {
		// Some branch fails purely on unknown properties: the input was aimed at that branch,
		// so attribute its unknown properties and drop the sibling branches' artefacts.
		partition.unknown.push(...matchable.unknown);
	} else {
		partition.structural.push(...summaryErrors);
		for (const candidate of branchPartitions) {
			partition.structural.push(...candidate.structural);
			partition.structural.push(...candidate.unknown);
		}
	}
}

/**
 * The evaluation path of the outermost oneOf/anyOf applicator (at or after `fromIndex`)
 * this error was produced under, or null for an error outside any composite. The path prefix
 * includes the composite keyword itself but not the branch index.
 */
function compositePrefix(error: SchemaValidationError, fromIndex: number): NodePath | null {
	const path = error.getEvaluationPath();
	const count = path.getNameCount();
	for (let i = fromIndex; i < count; i++) {
		const element = path.getElement(i);
		if ("oneOf" !== element && "anyOf" !== element) {
			continue;
		}
		if (i > 0 && "properties" === path.getElement(i - 1)) {
			// a property literally named oneOf/anyOf, not the applicator
			continue;
		}
		if (i === count - 1) {
			if (element === error.getKeyword()) {
				return path;
			}
		} else if (typeof path.getElement(i + 1) === "number") {
			return prefixOf(path, i + 1);
		}
	}
	return null;
}

function prefixOf(path: NodePath, length: number): NodePath {
	let prefix = path;
	for (let i = path.getNameCount(); i > length; i--) {
		prefix = prefix.getParent() as NodePath;
	}
	return prefix;
}

/** upstream: util/validation/JsonSchemaValidationResult.java */
export class JsonSchemaValidationResult {
	private readonly validationMessages: SchemaValidationError[];

	// Lazily computed on first use by structuralErrors()/unknownPropertyErrors(); not synchronised,
	// so a result must not be shared across threads (conditions evaluate on a single thread).
	private partitionCache: Partition | null = null;

	constructor(validationMessages: SchemaValidationError[]) {
		this.validationMessages = validationMessages;
	}

	isValid(): boolean {
		return this.validationMessages.length === 0;
	}

	getValidationMessages(): SchemaValidationError[] {
		return this.validationMessages;
	}

	/**
	 * The validation errors that are not attributable to unknown properties: everything except
	 * direct `additionalProperties`/`unevaluatedProperties` errors and oneOf/anyOf
	 * failures whose only cause is unknown properties (see {@link JsonSchemaValidationResult.unknownPropertyErrors}).
	 * Empty iff the input would validate against a schema whose unknown-property strictness was
	 * removed.
	 */
	structuralErrors(): JsonSchemaValidationResult {
		return new JsonSchemaValidationResult(this.partition().structural);
	}

	/**
	 * The validation errors attributable to unknown properties in the input. A flat filter on the
	 * `additionalProperties`/`unevaluatedProperties` keywords is not enough: when a
	 * oneOf/anyOf fails, the error list contains every branch's errors, so the branch the input
	 * was really aimed at contributes its unknown-property errors while the sibling branches
	 * reject perfectly well-known properties as "additional". This classifies errors by the
	 * oneOf/anyOf branch recorded in their evaluation path: a composite failure is attributed to
	 * unknown properties only when some branch fails purely because of them (recursively), and
	 * then only that branch's unknown-property errors are reported; a composite where every
	 * branch has a genuine structural error is reported via {@link JsonSchemaValidationResult.structuralErrors} instead.
	 * `unevaluatedProperties` errors naming a property that something inside has already
	 * failed on are dropped first, before any of that - see
	 * {@link withoutCascadedUnevaluatedErrors}.
	 *
	 * <p>"Some branch fails purely on unknown properties" is a heuristic for "that branch is the
	 * one the input was aimed at", not an invariant: if a payload can make an <em>unintended</em>
	 * branch fail on unknown properties alone (e.g. one mixing well-known members of two oneOf
	 * branches whose only difference is which members they reject as additional), that branch's
	 * rejections of well-known properties are misreported as unknown ones - and any genuine
	 * structural error in the intended branch is dropped. The suite's schemas avoid that shape by
	 * giving every composition branch a discriminator that fails structurally (a required/type
	 * mismatch, or `false` property schemas for the other branches' members), which stops an
	 * unintended branch being attributable at all.</p>
	 *
	 * <p>Composite applications are grouped by schema evaluation path, not by instance location, so
	 * two instances failing the same oneOf are classified together; a genuine structural error in
	 * one instance then also suppresses the attribution for the other. With several instances under
	 * one composite the attributed branch is chosen for the group, so a known property rejected by
	 * the branch a <em>different</em> instance was aimed at could in principle be reported - the
	 * structural discriminators above prevent this too.</p>
	 */
	unknownPropertyErrors(): JsonSchemaValidationResult {
		return new JsonSchemaValidationResult(this.partition().unknown);
	}

	private partition(): Partition {
		if (this.partitionCache == null) {
			this.partitionCache = new Partition();
			classify(withoutCascadedUnevaluatedErrors(this.validationMessages), 0, this.partitionCache);
		}
		return this.partitionCache;
	}

	getPropertyErrors(): JsonObject[] {
		const propertyErrorsWithPaths: JsonObject[] = [];
		for (const error of this.validationMessages) {
			const propertyError: JsonObject = {};
			propertyError["error"] = error.getMessage();
			if (error.getProperty() != null) {
				propertyError["property"] = error.getProperty();
			}
			propertyError["path"] = toInstancePropertyPath(error.getInstanceLocation(), error.getProperty());
			propertyErrorsWithPaths.push(propertyError);
		}
		return propertyErrorsWithPaths;
	}
}

function isValidationResult(v: unknown): v is JsonSchemaValidationResult {
	return v != null && typeof v === "object" && "getValidationMessages" in v;
}

/** upstream: util/validation/JsonSchemaValidationException.java */
export class JsonSchemaValidationException extends NamedError {
	private readonly validationResult: JsonSchemaValidationResult | null;

	/**
	 * Java overloads `(message)`, `(message, validationResult)`, `(message, cause)` and
	 * `(message, cause, validationResult)`.
	 */
	constructor(message: string, validationResult?: JsonSchemaValidationResult | null);
	constructor(message: string, cause: unknown, validationResult?: JsonSchemaValidationResult | null);
	constructor(message: string, causeOrResult?: unknown, validationResult?: JsonSchemaValidationResult | null) {
		if (
			validationResult !== undefined ||
			(causeOrResult !== undefined && !isValidationResult(causeOrResult) && causeOrResult !== null)
		) {
			super(message, { cause: causeOrResult });
			this.validationResult = validationResult ?? null;
		} else {
			super(message);
			this.validationResult = (causeOrResult as JsonSchemaValidationResult | null | undefined) ?? null;
		}
	}

	getValidationResult(): JsonSchemaValidationResult | null {
		return this.validationResult;
	}
}

/** Port of networknt `SchemaException` (e.g. a schema without `$schema`). */
export class SchemaException extends NamedError {}

type Draft = "draft-04" | "draft-06" | "draft-07" | "2019-09" | "2020-12";

/**
 * Port of the suite's `SpecificationVersionDetector`: the JSON Schema version from the `$schema` tag.
 * @throws SchemaException
 */
function detectSpecificationVersion(schema: JsonValue): Draft {
	const schemaTag = isJsonObject(schema) ? schema["$schema"] : undefined;
	if (schemaTag == null) {
		throw new SchemaException("'$schema' tag is not present");
	}
	const value = typeof schemaTag === "string" ? schemaTag : JSON.stringify(schemaTag);
	if (value.includes("://json-schema.org/draft")) {
		if (value.includes("/draft-04/")) {
			return "draft-04";
		}
		if (value.includes("/draft-06/")) {
			return "draft-06";
		}
		if (value.includes("/draft-07/")) {
			return "draft-07";
		}
		if (value.includes("/draft/2019-09/")) {
			return "2019-09";
		}
		if (value.includes("/draft/2020-12/")) {
			return "2020-12";
		}
	}
	throw new SchemaException("'" + value + "' is unrecognizable schema");
}

/** networknt JsonType names */
function jsonType(v: JsonValue): string {
	if (v === null) {
		return "null";
	}
	if (Array.isArray(v)) {
		return "array";
	}
	if (typeof v === "number") {
		return Number.isInteger(v) ? "integer" : "number";
	}
	return typeof v; // object, string, boolean
}

function typeMatches(v: JsonValue, type: string): boolean {
	const actual = jsonType(v);
	return actual === type || (type === "number" && actual === "integer");
}

function formatSchemaValue(v: JsonValue): string {
	return typeof v === "string" ? v : JSON.stringify(v);
}

/** Format checks (only asserted for draft-07 and earlier, as networknt does by default). */
const FORMATS: Record<string, { check: (s: string) => boolean; message: string }> = {
	uri: {
		check: (s) => /^[A-Za-z][A-Za-z0-9+.-]*:/.test(s) && !/[\s"<>\\^`{|}]/.test(s),
		message: "must be a valid RFC 3986 URI",
	},
	"uri-reference": { check: (s) => !/[\s"<>\\^`{|}]/.test(s), message: "must be a valid RFC 3986 URI-reference" },
	email: { check: (s) => /^[^\s@]+@[^\s@]+$/.test(s), message: "must be a valid RFC 5321 Mailbox" },
	"date-time": {
		check: (s) =>
			/^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/.test(s) && !Number.isNaN(Date.parse(s)),
		message: "must be a valid RFC 3339 date-time",
	},
	date: {
		check: (s) => /^\d{4}-\d{2}-\d{2}$/.test(s) && !Number.isNaN(Date.parse(s)),
		message: "must be a valid RFC 3339 full-date",
	},
	time: {
		check: (s) => /^\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/.test(s),
		message: "must be a valid RFC 3339 time",
	},
	ipv4: { check: (s) => isIP(s) === 4, message: "must be a valid RFC 2673 IP address" },
	ipv6: { check: (s) => isIP(s) === 6, message: "must be a valid RFC 4291 IP address" },
	hostname: {
		check: (s) => s.length <= 253 && s.split(".").every((l) => /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(l)),
		message: "must be a valid RFC 1123 host name",
	},
	uuid: {
		check: (s) => /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(s),
		message: "must be a valid RFC 4122 UUID",
	},
	regex: {
		check: (s) => {
			try {
				return new RegExp(s, "u").flags.length >= 0;
			} catch {
				return false;
			}
		},
		message: "must be a valid ECMA-262 regular expression",
	},
};

/**
 * A minimal JSON Schema (draft-04..2020-12) validator producing networknt-style errors (same keywords, messages,
 * instance locations and evaluation paths), supporting: type, properties, patternProperties,
 * additionalProperties, required, items/prefixItems/additionalItems, enum, const, minimum/maximum,
 * exclusiveMinimum/exclusiveMaximum, multipleOf, minLength/maxLength, pattern, format (asserted only for draft-07
 * and earlier; unknown formats pass), minItems/maxItems, uniqueItems, minProperties/maxProperties, oneOf/anyOf/allOf,
 * not, if/then/else, dependentRequired, and `$ref` to `#...` JSON pointers within the same document
 * (`$defs`/`definitions`). `unevaluatedProperties`/`unevaluatedItems` and cross-document `$ref`s are not supported
 * (ignored / error).
 */
class Validator {
	private readonly root: JsonValue;
	private readonly formatAssertions: boolean;
	private readonly errors: SchemaValidationError[] = [];

	constructor(root: JsonValue, draft: Draft) {
		this.root = root;
		this.formatAssertions = draft === "draft-04" || draft === "draft-06" || draft === "draft-07";
	}

	run(instance: JsonValue): SchemaValidationError[] {
		this.validate(this.root, instance, new NodePath(), new NodePath(), this.errors);
		return this.errors;
	}

	private resolveRef(ref: string): JsonValue {
		if (!ref.startsWith("#")) {
			throw new SchemaException(
				"Reference " + ref + " cannot be resolved (only same-document references are supported)",
			);
		}
		const pointer = decodeURIComponent(ref.substring(1));
		let node: JsonValue = this.root;
		if (pointer.length === 0) {
			return node;
		}
		for (const raw of pointer.substring(1).split("/")) {
			const token = raw.replace(/~1/g, "/").replace(/~0/g, "~");
			if (isJsonObject(node) && token in node) {
				node = node[token];
			} else if (isJsonArray(node) && /^\d+$/.test(token) && Number(token) < node.length) {
				node = node[Number(token)];
			} else {
				throw new SchemaException("Reference " + ref + " cannot be resolved");
			}
		}
		return node;
	}

	private isValid(schema: JsonValue, instance: JsonValue, at: NodePath, evalPath: NodePath): boolean {
		const errors: SchemaValidationError[] = [];
		this.validate(schema, instance, at, evalPath, errors);
		return errors.length === 0;
	}

	private validate(
		schema: JsonValue,
		instance: JsonValue,
		at: NodePath,
		evalPath: NodePath,
		out: SchemaValidationError[],
	): void {
		if (schema === true) {
			return;
		}
		if (schema === false) {
			out.push(
				new SchemaValidationError("false", "schema for '" + at.toString() + "' is false", at, evalPath, null, instance),
			);
			return;
		}
		if (!isJsonObject(schema)) {
			return;
		}
		const err = (keyword: string, message: string, property: string | null = null, location: NodePath = at) =>
			out.push(new SchemaValidationError(keyword, message, location, evalPath.append(keyword), property, instance));

		if (typeof schema["$ref"] === "string") {
			this.validate(this.resolveRef(schema["$ref"]), instance, at, evalPath.append("$ref"), out);
		}

		// type
		const type = schema["type"];
		if (typeof type === "string") {
			if (!typeMatches(instance, type)) {
				err("type", jsonType(instance) + " found, " + type + " expected");
			}
		} else if (isJsonArray(type)) {
			if (!type.some((t) => typeof t === "string" && typeMatches(instance, t))) {
				err("type", jsonType(instance) + " found, [" + type.map((t) => formatSchemaValue(t)).join(", ") + "] expected");
			}
		}

		// enum / const
		if (isJsonArray(schema["enum"]) && !schema["enum"].some((e) => jsonEquals(e, instance))) {
			err(
				"enum",
				"does not have a value in the enumeration [" + schema["enum"].map((e) => JSON.stringify(e)).join(", ") + "]",
			);
		}
		if ("const" in schema && !jsonEquals(schema["const"], instance)) {
			err("const", "must be the constant value '" + formatSchemaValue(schema["const"]) + "'");
		}

		// numbers
		if (typeof instance === "number") {
			const n = (k: string) => (typeof schema[k] === "number" ? (schema[k] as number) : null);
			const minimum = n("minimum");
			const maximum = n("maximum");
			if (minimum != null) {
				const exclusive = schema["exclusiveMinimum"] === true; // draft-04 boolean form
				if (exclusive ? instance <= minimum : instance < minimum) {
					err("minimum", "must have a minimum value of " + minimum);
				}
			}
			if (maximum != null) {
				const exclusive = schema["exclusiveMaximum"] === true;
				if (exclusive ? instance >= maximum : instance > maximum) {
					err("maximum", "must have a maximum value of " + maximum);
				}
			}
			const exclusiveMinimum = n("exclusiveMinimum");
			if (exclusiveMinimum != null && instance <= exclusiveMinimum) {
				err("exclusiveMinimum", "must have an exclusive minimum value of " + exclusiveMinimum);
			}
			const exclusiveMaximum = n("exclusiveMaximum");
			if (exclusiveMaximum != null && instance >= exclusiveMaximum) {
				err("exclusiveMaximum", "must have an exclusive maximum value of " + exclusiveMaximum);
			}
			const multipleOf = n("multipleOf");
			if (multipleOf != null && multipleOf > 0) {
				const q = instance / multipleOf;
				if (Math.abs(q - Math.round(q)) > 1e-9) {
					err("multipleOf", "must be multiple of " + multipleOf);
				}
			}
		}

		// strings
		if (typeof instance === "string") {
			const length = [...instance].length;
			if (typeof schema["minLength"] === "number" && length < schema["minLength"]) {
				err("minLength", "must be at least " + schema["minLength"] + " characters long");
			}
			if (typeof schema["maxLength"] === "number" && length > schema["maxLength"]) {
				err("maxLength", "must be at most " + schema["maxLength"] + " characters long");
			}
			if (typeof schema["pattern"] === "string" && !new RegExp(schema["pattern"], "u").test(instance)) {
				err("pattern", "does not match the regex pattern " + schema["pattern"]);
			}
			const format = schema["format"];
			if (this.formatAssertions && typeof format === "string") {
				const f = FORMATS[format];
				if (f != null && !f.check(instance)) {
					err("format", "does not match the " + format + " pattern " + f.message);
				}
			}
		}

		// arrays
		if (isJsonArray(instance)) {
			if (typeof schema["minItems"] === "number" && instance.length < schema["minItems"]) {
				err("minItems", "must have at least " + schema["minItems"] + " items but found " + instance.length);
			}
			if (typeof schema["maxItems"] === "number" && instance.length > schema["maxItems"]) {
				err("maxItems", "must have at most " + schema["maxItems"] + " items but found " + instance.length);
			}
			if (schema["uniqueItems"] === true) {
				const dup = instance.some((a, i) => instance.some((b, j) => j > i && jsonEquals(a, b)));
				if (dup) {
					err("uniqueItems", "must have only unique items in the array");
				}
			}
			let start = 0;
			const prefixItems = schema["prefixItems"];
			if (isJsonArray(prefixItems)) {
				for (let i = 0; i < prefixItems.length && i < instance.length; i++) {
					this.validate(prefixItems[i], instance[i], at.append(i), evalPath.append("prefixItems").append(i), out);
				}
				start = prefixItems.length;
			}
			const items = schema["items"];
			if (isJsonArray(items)) {
				// draft-07 tuple form
				for (let i = 0; i < items.length && i < instance.length; i++) {
					this.validate(items[i], instance[i], at.append(i), evalPath.append("items").append(i), out);
				}
				const additionalItems = schema["additionalItems"];
				for (let i = items.length; i < instance.length; i++) {
					if (additionalItems === false) {
						err(
							"additionalItems",
							"index '" + i + "' is not defined in the schema and the schema does not allow additional items",
						);
					} else if (additionalItems != null) {
						this.validate(additionalItems, instance[i], at.append(i), evalPath.append("additionalItems"), out);
					}
				}
			} else if (items != null) {
				for (let i = start; i < instance.length; i++) {
					if (items === false) {
						err(
							"items",
							"index '" + i + "' is not defined in the schema and the schema does not allow additional items",
						);
					} else {
						this.validate(items, instance[i], at.append(i), evalPath.append("items"), out);
					}
				}
			}
		}

		// objects
		if (isJsonObject(instance)) {
			const keys = Object.keys(instance);
			if (isJsonArray(schema["required"])) {
				for (const r of schema["required"]) {
					if (typeof r === "string" && !(r in instance)) {
						err("required", "required property '" + r + "' not found", r);
					}
				}
			}
			if (typeof schema["minProperties"] === "number" && keys.length < schema["minProperties"]) {
				err("minProperties", "must have at least " + schema["minProperties"] + " properties");
			}
			if (typeof schema["maxProperties"] === "number" && keys.length > schema["maxProperties"]) {
				err("maxProperties", "must have at most " + schema["maxProperties"] + " properties");
			}
			const dependentRequired = schema["dependentRequired"];
			if (isJsonObject(dependentRequired)) {
				for (const [k, deps] of Object.entries(dependentRequired)) {
					if (k in instance && isJsonArray(deps)) {
						for (const d of deps) {
							if (typeof d === "string" && !(d in instance)) {
								err(
									"dependentRequired",
									"has a missing property '" + d + "' which is dependent required because '" + k + "' is present",
									d,
								);
							}
						}
					}
				}
			}
			const properties = isJsonObject(schema["properties"]) ? schema["properties"] : {};
			const patternProperties = isJsonObject(schema["patternProperties"]) ? schema["patternProperties"] : {};
			for (const key of keys) {
				let matched = false;
				if (key in properties) {
					matched = true;
					this.validate(properties[key], instance[key], at.append(key), evalPath.append("properties").append(key), out);
				}
				for (const [pattern, sub] of Object.entries(patternProperties)) {
					if (new RegExp(pattern, "u").test(key)) {
						matched = true;
						this.validate(
							sub,
							instance[key],
							at.append(key),
							evalPath.append("patternProperties").append(pattern),
							out,
						);
					}
				}
				if (!matched && "additionalProperties" in schema) {
					const additional = schema["additionalProperties"];
					if (additional === false) {
						err(
							"additionalProperties",
							"property '" + key + "' is not defined in the schema and the schema does not allow additional properties",
							key,
						);
					} else if (isJsonObject(additional)) {
						this.validate(additional, instance[key], at.append(key), evalPath.append("additionalProperties"), out);
					}
				}
			}
		}

		// composition
		if (isJsonArray(schema["allOf"])) {
			schema["allOf"].forEach((sub, i) => this.validate(sub, instance, at, evalPath.append("allOf").append(i), out));
		}
		if (isJsonArray(schema["anyOf"])) {
			const branchErrors: SchemaValidationError[] = [];
			let anyValid = false;
			schema["anyOf"].forEach((sub, i) => {
				const errors: SchemaValidationError[] = [];
				this.validate(sub, instance, at, evalPath.append("anyOf").append(i), errors);
				if (errors.length === 0) {
					anyValid = true;
				}
				branchErrors.push(...errors);
			});
			if (!anyValid) {
				out.push(...branchErrors);
			}
		}
		if (isJsonArray(schema["oneOf"])) {
			const branchErrors: SchemaValidationError[] = [];
			const validIndexes: number[] = [];
			schema["oneOf"].forEach((sub, i) => {
				const errors: SchemaValidationError[] = [];
				this.validate(sub, instance, at, evalPath.append("oneOf").append(i), errors);
				if (errors.length === 0) {
					validIndexes.push(i);
				}
				branchErrors.push(...errors);
			});
			if (validIndexes.length === 0) {
				err("oneOf", "must be valid to one and only one schema, but 0 are valid");
				out.push(...branchErrors);
			} else if (validIndexes.length > 1) {
				err(
					"oneOf",
					"must be valid to one and only one schema, but " +
						validIndexes.length +
						" are valid with indexes '" +
						validIndexes.join(", ") +
						"'",
				);
			}
		}
		if ("not" in schema && this.isValid(schema["not"], instance, at, evalPath.append("not"))) {
			err("not", "must not be valid to the schema " + JSON.stringify(schema["not"]));
		}
		if ("if" in schema) {
			if (this.isValid(schema["if"], instance, at, evalPath.append("if"))) {
				if ("then" in schema) {
					this.validate(schema["then"], instance, at, evalPath.append("then"), out);
				}
			} else if ("else" in schema) {
				this.validate(schema["else"], instance, at, evalPath.append("else"), out);
			}
		}
	}
}

/** Schema resources are resolved relative to src/suite/data/ (the classpath root equivalent). */
const RESOURCE_ROOT = new URL("./data/", import.meta.url);

/**
 * Purely syntactic transformation: walks the whole document rather than only schema keyword
 * positions, which is sufficient for the schemas owned by the test suite (it would misfire on a
 * schema declaring a property literally named "additionalProperties" with a boolean-false schema,
 * or on a `const`/`enum`/`default` whose value is an object containing these
 * keys). Only removes the boolean `false` form; schema-valued forms constrain the values of
 * extra properties and are kept.
 */
function removeUnknownPropertyStrictness(node: JsonValue): void {
	if (isJsonObject(node)) {
		removeIfFalse(node, "additionalProperties");
		removeIfFalse(node, "unevaluatedProperties");
		for (const child of Object.values(node)) {
			removeUnknownPropertyStrictness(child);
		}
	} else if (isJsonArray(node)) {
		for (const child of node) {
			removeUnknownPropertyStrictness(child);
		}
	}
}

function removeIfFalse(node: JsonObject, keyword: string): void {
	const value = node[keyword];
	if (value === false) {
		delete node[keyword];
	}
}

/**
 * Returns the json path to the actual problem instance (JsonSchemaValidation.toInstancePropertyPath)
 */
export function toInstancePropertyPath(path: NodePath, property: string | null): string {
	let propertyPath = path.toString();
	if (property != null) {
		propertyPath += "." + property;
	}

	return propertyPath;
}

/** upstream: util/validation/JsonSchemaValidation.java */
export class JsonSchemaValidation {
	// networknt 3.x's default instance-path format differs from 1.5.x; the conformance suite and its
	// tests expect the classic dotted form (e.g. $.credentials[0].unexpected), i.e. PathType.LEGACY.
	// (NodePath.toString() renders that form.)

	private readonly schemaResource: string | JsonObject;

	private ignoreUnknownPropertyStrictness = false;

	/**
	 * @param schemaResource a resource path such as "json-schemas/rfc8414/oauth_authorization_server_metadata.json"
	 *                       (resolved against src/suite/data/), or the schema itself
	 */
	constructor(schemaResource: string | JsonObject) {
		this.schemaResource = schemaResource;
	}

	/**
	 * When enabled, `"additionalProperties": false` and `"unevaluatedProperties": false`
	 * are removed from the schema before validating, so unknown properties do not cause validation
	 * failures. Filtering the resulting messages by type (see
	 * {@link JsonSchemaValidationResult.structuralErrors}) is not sufficient for this:
	 * when the strict keyword sits inside a `oneOf`/`anyOf`/`allOf` branch, an
	 * unknown property makes the whole branch fail, and the sibling branches' errors (e.g. a
	 * `type` mismatch from the other branch) escape the type-based filter. Conditions that
	 * validate structure (and run with FAILURE) enable this so that unknown properties are surfaced
	 * only by the dedicated unknown-property conditions (which run with WARNING).
	 */
	setIgnoreUnknownPropertyStrictness(ignoreUnknownPropertyStrictness: boolean): void {
		this.ignoreUnknownPropertyStrictness = ignoreUnknownPropertyStrictness;
	}

	/**
	 * Validates a JSON object or JSON string. Synchronous (schemas are read with node:fs).
	 * @throws SchemaException for an unusable schema; Error when the schema resource cannot be read
	 */
	validate(jsonInput: JsonObject | string): JsonSchemaValidationResult {
		const schemaNode = this.loadSchema();
		if (this.ignoreUnknownPropertyStrictness) {
			removeUnknownPropertyStrictness(schemaNode);
		}

		const specVersion = detectSpecificationVersion(schemaNode);

		const inputNode = typeof jsonInput === "string" ? parseJson(jsonInput) : jsonInput;

		const errors = new Validator(schemaNode, specVersion).run(inputNode);

		return new JsonSchemaValidationResult(errors);
	}

	private loadSchema(): JsonValue {
		if (typeof this.schemaResource !== "string") {
			return structuredClone(this.schemaResource);
		}
		const url = new URL(this.schemaResource.replace(/^\/+/, ""), RESOURCE_ROOT);
		return parseJson(readFileSync(url, "utf8"));
	}
}
