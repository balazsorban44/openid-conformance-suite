import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { JWTUtil, ParseException } from "../../util/JWTUtil.ts";

export class ChangeIdTokenToAlgNone extends AbstractCondition {
	private static readonly ALG_NONE_HEADER = Buffer.from('{"alg": "none"}').toString("base64url");

	static override pre: EnvironmentRequirements = { required: ["id_token"] };
	static override post: EnvironmentRequirements = { required: ["id_token"] };

	override evaluate(env: Environment): Environment {
		const idToken = env.getString("id_token", "value");
		if (!idToken) {
			throw this.error("Couldn't find id_token");
		}
		try {
			// SignedJWT.parse(idToken)
			const idTokenParsed = JWTUtil.parseJWT(idToken);
			if (idTokenParsed.type !== "signed") {
				throw new ParseException("Not a JWS header");
			}
			const idTokenParsedParts = idTokenParsed.parts;
			const jwt = ChangeIdTokenToAlgNone.ALG_NONE_HEADER + "." + idTokenParsedParts[1] + ".";
			const idTokenObj = env.getObject("id_token") as JsonObject;
			idTokenObj["value"] = jwt;
			this.logSuccess("Changed id_token to be 'signed' with 'alg: none'", args("id_token", jwt));
			return env;
		} catch (e) {
			if (e instanceof ParseException) {
				throw this.error("Couldn't parse JWT", e, args("id_token", idToken));
			}
			throw e;
		}
	}
}
