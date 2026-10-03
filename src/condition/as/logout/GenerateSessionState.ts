import { createHash } from "node:crypto";
import {
	AbstractCondition,
	args,
	RandomStringUtils,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../../framework/index.ts";
import { URISyntaxException } from "../../../util/validation/RedirectURIValidationUtil.ts";
import { RFC6749AppendixASyntaxUtils } from "../../util/RFC6749AppendixASyntaxUtils.ts";
import { CreateEffectiveAuthorizationRequestParameters } from "../CreateEffectiveAuthorizationRequestParameters.ts";
import { parseJavaURI } from "../dynregistration/AbstractClientValidationCondition.ts";

/**
 * https://openid.net/specs/openid-connect-session-1_0.html#CreatingUpdatingSessions
 * 		The Session State value is initially calculated on the server. The same Session State value
 * 		is also recalculated by the OP iframe in the browser client. The generation of suitable
 * 		Session State values is specified in Section 4.2, and is based on a salted cryptographic
 * 		hash of Client ID, origin URL, and OP browser state. For the origin URL, the server can
 * 		use the origin URL of the Authentication Response, following the algorithm specified in
 * 		Section 4 of RFC 6454 [RFC6454].
 */
export class GenerateSessionState extends AbstractCondition {
	static override pre: EnvironmentRequirements = {
		required: ["client", CreateEffectiveAuthorizationRequestParameters.ENV_KEY],
	};
	static override post: EnvironmentRequirements = { required: ["session_state_data"] };

	override evaluate(env: Environment): Environment {
		const sessionStateData: JsonObject = {};
		const salt = RandomStringUtils.nextAlphanumeric(50);
		//this is actually a session id but the spec calls it "OP browser state"
		const opBrowserState = RandomStringUtils.nextAlphanumeric(50);

		const clientId = env.getString("client", "client_id");
		const origin = this.getOrigin(
			env.getString(
				CreateEffectiveAuthorizationRequestParameters.ENV_KEY,
				CreateEffectiveAuthorizationRequestParameters.REDIRECT_URI,
			) as string,
		);
		// MessageDigest.getInstance("SHA-256") (NoSuchAlgorithmException -> "Unsupported digest algorithm" can't happen)
		const digester = createHash("sha256");
		const stringToHash = clientId + " " + origin + " " + opBrowserState + " " + salt;
		const digestBytes = digester.update(stringToHash, "utf8").digest();
		const sessionState = digestBytes.toString("base64url") + "." + salt;
		sessionStateData["session_state"] = sessionState;
		sessionStateData["op_browser_state"] = opBrowserState;
		sessionStateData["salt"] = salt;
		sessionStateData["client_id"] = clientId;
		sessionStateData["origin"] = origin;
		sessionStateData["sid"] = RFC6749AppendixASyntaxUtils.generateVSChar(20, 10, 5);

		this.log("Generated session_state", args("session_state_data", sessionStateData));

		env.putObject("session_state_data", sessionStateData);
		return env;
	}

	protected getOrigin(redirectUri: string): string {
		try {
			const uri = parseJavaURI(redirectUri);
			// UPSTREAM: a null scheme/host throws (Java: NullPointerException)
			let origin = (uri.scheme as string).toLowerCase() + "://" + (uri.host as string).toLowerCase();
			if (uri.port === -1) {
				if ("http" === uri.scheme?.toLowerCase()) {
					origin += ":80";
				} else {
					origin += ":443";
				}
			} else {
				origin += ":" + uri.port;
			}
			return origin;
		} catch (e) {
			if (!(e instanceof URISyntaxException)) {
				throw e;
			}
			throw this.error(
				"Unable to extract origin from redirect_uri, invalid redirect_uri",
				args("redirect_uri", redirectUri),
			);
		}
	}
}
