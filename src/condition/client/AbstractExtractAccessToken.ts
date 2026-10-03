import { AbstractCondition, type Environment, type JsonObject } from "../../framework/index.ts";

export abstract class AbstractExtractAccessToken extends AbstractCondition {
	protected extractAccessToken(env: Environment, source: string): Environment {
		const accessTokenString = env.getString(source, "access_token");
		if (!accessTokenString) {
			throw this.error("Couldn't find access token in " + source);
		}

		const tokenType = env.getString(source, "token_type");
		if (!tokenType) {
			throw this.error("Couldn't find token type in " + source);
		}

		const o: JsonObject = {};
		o["value"] = accessTokenString;
		o["type"] = tokenType;

		env.putObject("access_token", o);

		this.logSuccess("Extracted the access token", o);

		return env;
	}
}
