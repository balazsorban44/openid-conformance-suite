import { AbstractCondition, args, type Environment } from "../../framework/index.ts";

export abstract class AbstractValidateErrorUriFromResponseError extends AbstractCondition {
	private static readonly ERROR_URI_FIELD_PATTERN_VALID = "[\\x21\\x23-\\x5B\\x5D-\\x7E]+";

	protected checkErrorUri(env: Environment, where: string): Environment {
		const errorUri = env.getString(where, "error_uri");

		if (!errorUri) {
			this.logSuccess(where + " did not include optional 'error_uri' field");
			return env;
		}

		if (!this.isValidUriSyntax(errorUri)) {
			throw this.error("'error_uri' field MUST conform to the URI-reference syntax", args("error_uri", errorUri));
		}
		if (!this.isValidErrorUriFieldFormat(errorUri)) {
			throw this.error(
				"'error_uri' field MUST NOT include characters outside the set %x21 / %x23-5B / %x5D-7E",
				args("error_uri", errorUri),
			);
		}

		this.logSuccess(where + " returned valid 'error_uri' field", args("error_uri", errorUri));
		return env;
	}

	private isValidErrorUriFieldFormat(str: string): boolean {
		const validPattern = new RegExp(
			"^(?:" + AbstractValidateErrorUriFromResponseError.ERROR_URI_FIELD_PATTERN_VALID + ")$",
		);
		if (validPattern.test(str)) {
			return true;
		}
		return false;
	}

	private isValidUriSyntax(errorUri: string): boolean {
		// UPSTREAM: Java uses URI.create(errorUri).toURL(), which rejects relative references and URIs whose scheme has
		// no registered URL handler; new URL() is the closest equivalent (rejects relative references too).
		try {
			return URL.canParse(errorUri);
		} catch {
			return false;
		}
	}
}
