import { createHash } from "node:crypto";
import {
	AbstractCondition,
	args,
	RandomStringUtils,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

/**
 * Creates a URL to retrieve a request object based on the base_url environment value
 *
 * This version includes a fragment into the generated url, as described in OpenID Connect. This behaviour is not
 * present in JAR (RFC9101) so this condition should not be used for those cases.
 */
export class CreateRandomRequestUriWithFragment extends AbstractCondition {
	static override pre: EnvironmentRequirements = { strings: ["base_url"] };
	static override post: EnvironmentRequirements = { required: ["request_uri"], strings: ["request_uri"] };

	private base64UrlEncodedSha256(text: string): string {
		const digest = createHash("sha256").update(Buffer.from(text, "ascii")).digest();

		return digest.toString("base64url");
	}

	override evaluate(env: Environment): Environment {
		let baseUrl = env.getString("base_url") as string;

		if (baseUrl === "") {
			throw this.error("Base URL is empty");
		}

		// see https://gitlab.com/openid/conformance-suite/wikis/Developers/Build-&-Run#ciba-notification-endpoint
		const externalUrlOverride = env.getString("external_url_override");
		if (externalUrlOverride) {
			baseUrl = externalUrlOverride;
		}

		// create a random URL
		//
		// - spec requires full url to be no more than 512 characters
		//
		// - spec does not have any obvious restriction on character set (random alphanumeric used for consistency with
		// python suite)
		//
		// - spec allows a fragment: "If the contents of the referenced resource could ever change, the URI SHOULD
		// include the base64url encoded SHA-256 hash of the referenced resource contents as the fragment component
		// of the URI"; we don't include one for consistency with python
		//
		// spec says "As such, the request_uri MUST have appropriate entropy for its lifetime"; python used 8 characters
		// which is ~48 bits of entropy which is not very much
		//
		// (64 is a relatively arbitrary choice that lies between ~21 characters having a reasonable amount of entropy
		// and the 512 byte upper limit, and appears to match what python does. The spec says clients mustn't use more
		// than 512, but doesn't say servers have to support 512.)
		const path = "requesturi/" + RandomStringUtils.nextAlphanumeric(64);

		// actual content of request object not used as it's not available prior to client registration
		const fragment = this.base64UrlEncodedSha256(RandomStringUtils.nextAlphanumeric(64));
		// FIXME remove fragment at least for VCI; it's only in OIDC, not in JAR
		const o: JsonObject = {};
		o["path"] = path;
		const fullUrl = baseUrl + "/" + path + "#" + fragment;
		o["fullUrl"] = fullUrl;

		env.putObject("request_uri", o);
		env.putString("request_uri", fullUrl);

		this.log("Created random URL for request_uri", args("request_uri", o));

		return env;
	}
}
