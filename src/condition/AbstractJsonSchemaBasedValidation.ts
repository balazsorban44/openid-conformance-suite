import { AbstractCondition, args, type Environment } from "../framework/index.ts";
import { JsonSchemaValidation } from "../util/validation/JsonSchemaValidation.ts";
import { JsonSchemaValidationException } from "../util/validation/JsonSchemaValidationException.ts";
import type { JsonSchemaValidationInput } from "../util/validation/JsonSchemaValidationInput.ts";
import type { JsonSchemaValidationResult } from "../util/validation/JsonSchemaValidationResult.ts";

export abstract class AbstractJsonSchemaBasedValidation extends AbstractCondition {
	protected abstract createJsonSchemaValidationInput(env: Environment): JsonSchemaValidationInput;

	override evaluate(env: Environment): Environment {
		const input = this.createJsonSchemaValidationInput(env);

		const inputJsonObject = input.getJsonObject();
		if (inputJsonObject == null) {
			throw this.error(`${input.getInputName()} input object not found`);
		}

		const jsonSchemaValidation = this.createJsonSchemaValidation(input);
		let validationResult: JsonSchemaValidationResult;
		try {
			validationResult = jsonSchemaValidation.validate(inputJsonObject);
		} catch (e) {
			// Java: catch (IOException e) - the schema resource could not be read
			if (isIOException(e)) {
				throw new Error("JSON Schema based input validation failed", { cause: e });
			}
			throw e;
		}
		if (!validationResult.isValid()) {
			this.onValidationFailure(env, validationResult, input);
		} else {
			this.onValidationSuccess(env, input);
		}

		return env;
	}

	protected onValidationSuccess(_env: Environment, input: JsonSchemaValidationInput): void {
		this.logSuccess(
			`${input.getInputName()} input is valid`,
			args("input", input.getJsonObject(), "schema_link", "/" + input.getSchemaResource()),
		);
	}

	protected onValidationFailure(
		_env: Environment,
		validationResult: JsonSchemaValidationResult,
		input: JsonSchemaValidationInput,
	): void {
		throw this.error(
			`Found invalid entries in ${input.getInputName()} input`,
			new JsonSchemaValidationException("Schema Validation Failed", validationResult),
			args(
				"invalid_entries",
				validationResult.getPropertyErrors(),
				"input",
				input.getJsonObject(),
				"schema_link",
				"/" + input.getSchemaResource(),
			),
		);
	}

	protected createJsonSchemaValidation(input: JsonSchemaValidationInput): JsonSchemaValidation {
		const validation = new JsonSchemaValidation(input.getSchemaResource());
		validation.setIgnoreUnknownPropertyStrictness(this.ignoreUnknownPropertyStrictness());
		validation.setSchemaBuilderCustomizer(this.schemaBuilderCustomizer());
		return validation;
	}

	/**
	 * Schema registry customizer applied when the schema is built (e.g. to map cross-document
	 * $refs onto classpath resources); null (the default) for none.
	 */
	protected schemaBuilderCustomizer(): ((builder: unknown) => void) | null {
		return null;
	}

	/**
	 * Structural validators (called with FAILURE) that have a paired unknown-property condition
	 * (called with WARNING) can override this to return true so that unknown properties never fail
	 * them, not even indirectly via composite oneOf/anyOf errors; see
	 * {@link JsonSchemaValidation#setIgnoreUnknownPropertyStrictness}. Before enabling this for a
	 * schema, check it has no oneOf branches discriminated only by `additionalProperties:
	 * false` - removing the keyword would let such a payload match more than one branch.
	 */
	protected ignoreUnknownPropertyStrictness(): boolean {
		return false;
	}
}

/** Node.js system errors (e.g. ENOENT reading the schema resource) stand in for java.io.IOException. */
function isIOException(e: unknown): boolean {
	return e instanceof Error && typeof (e as NodeJS.ErrnoException).code === "string";
}
