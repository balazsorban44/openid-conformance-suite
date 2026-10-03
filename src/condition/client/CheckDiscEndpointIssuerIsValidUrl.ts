import {
	AbstractCondition,
	args,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
} from "../../framework/index.ts";
import { IssuerUrlValidation } from "../util/IssuerUrlValidation.ts";

/**
 * Validates that the authorization server / OpenID Provider metadata {@code issuer} is a
 * well-formed RFC 8414 §2 issuer identifier: an {@code https} URL (scheme case-insensitive) with
 * a host component and no query, fragment, userinfo or out-of-range port.
 *
 * <p>This is structural validation of the identifier itself; {@link CheckDiscEndpointIssuer}
 * separately checks that the value matches the location the metadata was retrieved from.
 */
export class CheckDiscEndpointIssuerIsValidUrl extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		const issuerEl = env.getElementFromObject("server", "issuer");
		if (!OIDFJSON.isString(issuerEl)) {
			throw this.error(
				"issuer is missing or not a string in the authorization server metadata",
				args("issuer", issuerEl),
			);
		}
		const issuer = OIDFJSON.getString(issuerEl);

		const issues: string[] = [];
		IssuerUrlValidation.validate(issuer, "issuer", issues);
		if (issues.length > 0) {
			throw this.error(
				"issuer is not a valid RFC 8414 issuer identifier URL",
				args("issuer", issuer, "issues", issues),
			);
		}

		this.logSuccess("issuer is a valid issuer identifier URL", args("issuer", issuer));
		return env;
	}
}
