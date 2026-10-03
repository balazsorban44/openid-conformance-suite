import {
	AbstractCondition,
	args,
	OIDFJSON,
	RandomStringUtils,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddRandomSuffixToIssuerInServerConfiguration extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["server"], strings: ["issuer"] };
	static override post: EnvironmentRequirements = { required: ["server"], strings: ["issuer", "discoveryUrl"] };

	override evaluate(env: Environment): Environment {
		const server = env.getObject("server") as JsonObject;

		const currentIssuer = OIDFJSON.getString(server["issuer"]);
		const newIssuer = currentIssuer + RandomStringUtils.nextAlphanumeric(10);
		server["issuer"] = newIssuer;
		env.putObject("server", server);
		env.putString("issuer", newIssuer);
		env.putString("discoveryUrl", newIssuer + "/.well-known/openid-configuration");

		this.log("Added random suffix to issuer value in server configuration", args("issuer", newIssuer));

		return env;
	}
}
