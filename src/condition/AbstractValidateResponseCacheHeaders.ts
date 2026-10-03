import { AbstractCondition, args, isJsonArray, OIDFJSON, type JsonObject } from "../framework/index.ts";

export abstract class AbstractValidateResponseCacheHeaders extends AbstractCondition {
	protected validateCacheHeaders(headers: JsonObject, humanReadableResponseName: string): void {
		const noStore = "no-store";

		if (!("cache-control" in headers)) {
			throw this.error(
				humanReadableResponseName + " does not contain 'cache-control' header",
				args("response_headers", headers),
			);
		}

		const cacheControl = headers["cache-control"];

		if (!this.doesHeaderContainExpectedValue(headers, "cache-control", noStore)) {
			throw this.error(
				"'cache-control' header in " + humanReadableResponseName + " does not contain expected value.",
				args("expected", noStore, "actual", cacheControl),
			);
		}

		this.logSuccess(
			"'cache-control' header in " + humanReadableResponseName + " contains expected value.",
			args("cache_control_header", cacheControl),
		);
	}

	private doesHeaderContainExpectedValue(header: string | null, expected: string): boolean;
	private doesHeaderContainExpectedValue(headers: JsonObject, headerName: string, expected: string): boolean;
	private doesHeaderContainExpectedValue(
		headerOrHeaders: string | null | JsonObject,
		expectedOrHeaderName: string,
		expected?: string,
	): boolean {
		if (expected === undefined) {
			const header = headerOrHeaders as string | null;
			if (!header) {
				return false;
			}

			for (const piece of header.split(",")) {
				if (piece.trim() === expectedOrHeaderName) {
					return true;
				}
			}

			return false;
		}

		const headers = headerOrHeaders as JsonObject;
		const headerJson = headers[expectedOrHeaderName];
		if (isJsonArray(headerJson)) {
			for (const el of headerJson) {
				const header = OIDFJSON.getString(el);
				if (this.doesHeaderContainExpectedValue(header, expected)) {
					return true;
				}
			}
			return false;
		}
		const header = OIDFJSON.getString(headerJson);
		return this.doesHeaderContainExpectedValue(header, expected);
	}
}
