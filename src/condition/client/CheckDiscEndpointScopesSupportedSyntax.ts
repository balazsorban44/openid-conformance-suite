import {
	AbstractCondition,
	args,
	isJsonArray,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
} from "../../framework/index.ts";
import { ScopeTokenSyntaxUtil } from "../util/ScopeTokenSyntaxUtil.ts";

/**
 * Validates that each entry in the authorization server metadata's {@code scopes_supported}
 * is a valid RFC 6749 Appendix A.4 scope-token (visible ASCII, no SP / DQUOTE / BACKSLASH).
 * {@code scopes_supported} is OPTIONAL (RFC 8414 §2 / OpenID Connect Discovery §3); its
 * absence is not an error.
 */
export class CheckDiscEndpointScopesSupportedSyntax extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		const scopesSupportedEl = env.getElementFromObject("server", "scopes_supported");
		if (scopesSupportedEl == null) {
			this.logSuccess("authorization server metadata has no scopes_supported (OPTIONAL); nothing to validate");
			return env;
		}
		if (!isJsonArray(scopesSupportedEl)) {
			throw this.error("scopes_supported is not a JSON array", args("scopes_supported", scopesSupportedEl));
		}

		const scopesSupported = scopesSupportedEl;
		const issues: string[] = [];
		for (let i = 0; i < scopesSupported.length; i++) {
			const element = scopesSupported[i];
			if (!OIDFJSON.isString(element)) {
				issues.push(`scopes_supported[${i}]: expected string, got ${JSON.stringify(element)}`);
				continue;
			}
			const scope = OIDFJSON.getString(element);
			const syntaxError = ScopeTokenSyntaxUtil.scopeTokenSyntaxError(scope);
			if (syntaxError != null) {
				issues.push(`scopes_supported[${i}]: '${scope}' ${syntaxError}`);
			}
		}

		if (issues.length > 0) {
			throw this.error("Invalid scope syntax in authorization server scopes_supported", args("issues", issues));
		}

		this.logSuccess("All scopes_supported entries are valid RFC 6749 scope-tokens");
		return env;
	}
}
