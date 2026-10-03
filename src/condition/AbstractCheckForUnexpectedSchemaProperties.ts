import {
	args,
	isJsonArray,
	isJsonPrimitive,
	NEW_ISSUE_URL,
	OIDFJSON,
	SUPPORT_EMAIL,
	type Environment,
	type JsonObject,
} from "../framework/index.ts";
import { JsonSchemaValidation } from "../util/validation/JsonSchemaValidation.ts";
import type { JsonSchemaValidationInput } from "../util/validation/JsonSchemaValidationInput.ts";
import type { JsonSchemaValidationResult } from "../util/validation/JsonSchemaValidationResult.ts";
import { AbstractJsonSchemaBasedValidation } from "./AbstractJsonSchemaBasedValidation.ts";

/**
 * Base class for conditions that check for unknown/additional properties in schema-validated JSON.
 * Reports only the errors {@link JsonSchemaValidationResult#unknownPropertyErrors()} attributes to
 * unknown properties (which excludes sibling oneOf/anyOf branches' additionalProperties artefacts).
 * Structural errors are never reported here - those are handled by the paired structural validator
 * condition - but they do not suppress this condition either: unknown properties that can still be
 * attributed reliably (the attribution errs towards under-reporting inside a structurally failed
 * oneOf/anyOf) are warned about even in an otherwise invalid input.
 *
 * Subclasses may override {@link #getAllowUnexpectedFieldsConfigKey()} to let a test configuration
 * suppress the warning for specific known-extension property names that the schema does not (yet)
 * cover - an escape hatch for servers that legitimately advertise extension metadata.
 */
export abstract class AbstractCheckForUnexpectedSchemaProperties extends AbstractJsonSchemaBasedValidation {
	/**
	 * A clean schema validation means nothing to report here, not that the input as a whole is
	 * valid - that is the paired structural validator's verdict to give. Say what this condition
	 * checked, in the same words as the failure path's equivalent outcome below.
	 */
	protected override onValidationSuccess(_env: Environment, input: JsonSchemaValidationInput): void {
		this.logNoUnknownProperties(input);
	}

	private logNoUnknownProperties(input: JsonSchemaValidationInput): void {
		this.logSuccess(
			"No unknown properties were found in the " + input.getInputName(),
			args("input", input.getJsonObject(), "schema_link", "/" + input.getSchemaResource()),
		);
	}

	protected override onValidationFailure(
		env: Environment,
		validationResult: JsonSchemaValidationResult,
		input: JsonSchemaValidationInput,
	): void {
		// Structural errors are reported by the paired structural validation condition (run with
		// FAILURE); this condition only reports the unknown properties unknownPropertyErrors()
		// can attribute reliably.
		const ignored = this.getIgnoredPropertyNames(env);
		const unknownProps: JsonObject[] = [];
		const allowListed: string[] = [];
		for (const msg of validationResult.unknownPropertyErrors().getValidationMessages()) {
			const path = JsonSchemaValidation.toInstancePropertyPath(msg.getInstanceLocation(), msg.getProperty());
			if (ignored.has(msg.getProperty() as string)) {
				allowListed.push(path);
				continue;
			}
			const entry: JsonObject = {};
			entry["property"] = msg.getProperty();
			entry["path"] = path;
			unknownProps.push(entry);
		}
		if (unknownProps.length === 0) {
			if (allowListed.length === 0) {
				this.logNoUnknownProperties(input);
			} else {
				this.logSuccess(
					"The only unknown properties found in the " +
						input.getInputName() +
						" are allow-listed in the '" +
						this.getAllowUnexpectedFieldsConfigKey() +
						"' array in the test configuration",
					args(
						"allow_listed_properties",
						allowListed,
						"input",
						input.getJsonObject(),
						"schema_link",
						"/" + input.getSchemaResource(),
					),
				);
			}
			return;
		}
		const configKey = this.getAllowUnexpectedFieldsConfigKey();
		const suppressHint =
			configKey != null
				? " If these are known extensions, add their names to the '" +
					configKey +
					"' array in the test configuration to suppress this warning."
				: "";
		throw this.error(
			"Unknown properties were found in the " +
				input.getInputName() +
				". This may indicate the sender has misunderstood the spec, or it may be using extensions the test suite is unaware of." +
				suppressHint +
				" If they are derived from a specification, please open an issue at " +
				NEW_ISSUE_URL +
				" (or, if you are unable to, email " +
				SUPPORT_EMAIL +
				") so the test suite can be updated.",
			args(
				"unknown_properties",
				unknownProps,
				"input",
				input.getJsonObject(),
				"schema_link",
				"/" + input.getSchemaResource(),
			),
		);
	}

	/**
	 * Property names to treat as known (i.e. not warn about) even though they are absent from the
	 * schema. By default this reads {@link #getAllowUnexpectedFieldsConfigKey()} from the test
	 * configuration; subclasses can override for more complex behaviour.
	 */
	protected getIgnoredPropertyNames(env: Environment): Set<string> {
		const configKey = this.getAllowUnexpectedFieldsConfigKey();
		return configKey == null ? new Set() : this.readIgnoredPropertyNamesFromConfig(env, configKey);
	}

	/**
	 * The path within the `config` object of a JSON array of property names the tester wants
	 * treated as known (not warned about). This is a deliberately "hidden" configuration field - it
	 * is not declared in any `configurationFields`, so it does not appear on the schedule-test
	 * form, but a tester can still add it to the raw test configuration JSON as an escape hatch for
	 * extension metadata their server legitimately publishes. Returns `null` (no escape hatch)
	 * by default; subclasses override to enable it.
	 */
	protected getAllowUnexpectedFieldsConfigKey(): string | null {
		return null;
	}

	/**
	 * Read a JSON array of property names from the given path within the `config` environment
	 * object, returning an empty set if it is missing or not an array.
	 */
	protected readIgnoredPropertyNamesFromConfig(env: Environment, configPath: string): Set<string> {
		const names = new Set<string>();
		const el = env.getElementFromObject("config", configPath);
		if (el != null && isJsonArray(el)) {
			for (const item of el) {
				if (isJsonPrimitive(item)) {
					names.add(OIDFJSON.getString(item));
				}
			}
		}
		return names;
	}
}
