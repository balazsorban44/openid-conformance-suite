import type { JsonObject, JsonValue } from "../../framework/json.ts";
import { JsonSchemaValidation } from "./JsonSchemaValidation.ts";

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
	 * {@link JsonSchemaValidationResult.withoutCascadedUnevaluatedErrors}.
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

	private static isUnknownPropertyError(m: SchemaValidationError): boolean {
		const type = m.getKeyword();
		return "additionalProperties" === type || "unevaluatedProperties" === type;
	}

	private partition(): Partition {
		if (this.partitionCache == null) {
			this.partitionCache = new Partition();
			JsonSchemaValidationResult.classify(
				JsonSchemaValidationResult.withoutCascadedUnevaluatedErrors(this.validationMessages),
				0,
				this.partitionCache,
			);
		}
		return this.partitionCache;
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
	private static withoutCascadedUnevaluatedErrors(errors: SchemaValidationError[]): SchemaValidationError[] {
		const kept: SchemaValidationError[] = [];
		for (const error of errors) {
			if (
				"unevaluatedProperties" === error.getKeyword() &&
				error.getProperty() != null &&
				JsonSchemaValidationResult.hasErrorInsideProperty(
					errors,
					error.getInstanceLocation(),
					error.getProperty() as string,
				)
			) {
				continue;
			}
			kept.push(error);
		}
		return kept;
	}

	private static hasErrorInsideProperty(
		errors: SchemaValidationError[],
		objectLocation: NodePath,
		property: string,
	): boolean {
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

	private static classify(errors: SchemaValidationError[], fromIndex: number, partition: Partition): void {
		const compositeGroups = new Map<string, { prefix: NodePath; errors: SchemaValidationError[] }>();
		for (const error of errors) {
			const composite = JsonSchemaValidationResult.compositePrefix(error, fromIndex);
			if (composite != null) {
				const k = composite.key();
				let group = compositeGroups.get(k);
				if (group == null) {
					group = { prefix: composite, errors: [] };
					compositeGroups.set(k, group);
				}
				group.errors.push(error);
			} else if (JsonSchemaValidationResult.isUnknownPropertyError(error)) {
				partition.unknown.push(error);
			} else {
				partition.structural.push(error);
			}
		}
		for (const group of compositeGroups.values()) {
			JsonSchemaValidationResult.classifyComposite(group.prefix.getNameCount(), group.errors, partition);
		}
	}

	private static classifyComposite(prefixLength: number, errors: SchemaValidationError[], partition: Partition): void {
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
			JsonSchemaValidationResult.classify(branchErrors, prefixLength + 1, branchPartition);
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
	private static compositePrefix(error: SchemaValidationError, fromIndex: number): NodePath | null {
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
				return JsonSchemaValidationResult.prefixOf(path, i + 1);
			}
		}
		return null;
	}

	private static prefixOf(path: NodePath, length: number): NodePath {
		let prefix = path;
		for (let i = path.getNameCount(); i > length; i--) {
			prefix = prefix.getParent() as NodePath;
		}
		return prefix;
	}

	getPropertyErrors(): JsonObject[] {
		const propertyErrorsWithPaths: JsonObject[] = [];
		for (const error of this.validationMessages) {
			const propertyError: JsonObject = {};
			propertyError["error"] = error.getMessage();
			if (error.getProperty() != null) {
				propertyError["property"] = error.getProperty();
			}
			propertyError["path"] = JsonSchemaValidation.toInstancePropertyPath(
				error.getInstanceLocation(),
				error.getProperty(),
			);
			propertyErrorsWithPaths.push(propertyError);
		}
		return propertyErrorsWithPaths;
	}
}
