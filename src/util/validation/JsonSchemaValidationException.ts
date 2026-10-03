import type { JsonSchemaValidationResult } from "./JsonSchemaValidationResult.ts";
import { NamedError } from "../../framework/exceptions.ts";

export class JsonSchemaValidationException extends NamedError {
	private readonly validationResult: JsonSchemaValidationResult | null;

	/**
	 * Java overloads `(message)`, `(message, validationResult)`, `(message, cause)` and
	 * `(message, cause, validationResult)`.
	 */
	constructor(message: string, validationResult?: JsonSchemaValidationResult | null);
	constructor(message: string, cause: unknown, validationResult?: JsonSchemaValidationResult | null);
	constructor(message: string, causeOrResult?: unknown, validationResult?: JsonSchemaValidationResult | null) {
		const isResult = (v: unknown): v is JsonSchemaValidationResult =>
			v != null && typeof v === "object" && "getValidationMessages" in v;
		if (
			validationResult !== undefined ||
			(causeOrResult !== undefined && !isResult(causeOrResult) && causeOrResult !== null)
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
