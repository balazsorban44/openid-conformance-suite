import {
	args,
	UnexpectedJsonTypeException,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../../framework/index.ts";
import { URISyntaxException } from "../../../util/validation/RedirectURIValidationUtil.ts";
import { AbstractClientValidationCondition, parseJavaURI } from "./AbstractClientValidationCondition.ts";

/**
 * initiate_login_uri
 *  OPTIONAL. URI using the https scheme that a third party can use to initiate a
 *  login by the RP, as specified in Section 4 of OpenID Connect Core 1.0 [OpenID.Core].
 *  The URI MUST accept requests via both GET and POST.
 *  The Client MUST understand the login_hint and iss parameters and SHOULD support the
 *  target_link_uri parameter.
 *
 *  Just checks if it is a valid https uri or not
 *
 */
export class ValidateInitiateLoginUri extends AbstractClientValidationCondition {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		this.client = env.getObject("client") as JsonObject;
		try {
			const initiateLoginUri = this.getInitiateLoginUri();
			if (initiateLoginUri == null) {
				this.logSuccess("initiate_login_uri is not set");
				return env;
			} else {
				try {
					const uri = parseJavaURI(initiateLoginUri);
					if ("https" === uri.scheme?.toLowerCase()) {
						this.logSuccess("initiate_login_uri is valid", args("initiate_login_uri", initiateLoginUri));
						return env;
					}
					throw this.error("initiate_login_uri is not a https URI", args("initiate_login_uri", initiateLoginUri));
				} catch (e) {
					if (!(e instanceof URISyntaxException)) {
						throw e;
					}
					throw this.error("initiate_login_uri is not a valid URI", args("initiate_login_uri", initiateLoginUri));
				}
			}
		} catch (ex) {
			if (!(ex instanceof UnexpectedJsonTypeException)) {
				throw ex;
			}
			throw this.error(
				"initiate_login_uri is not encoded as a string",
				args("initiate_login_uri", this.client["initiate_login_uri"]),
			);
		}
	}
}
