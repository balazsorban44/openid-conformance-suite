import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class CreateLogoUri extends AbstractCondition {
	private static readonly LOGO_PATH = "/images/openid.png";

	static override pre: EnvironmentRequirements = { strings: ["base_url"] };
	static override post: EnvironmentRequirements = { strings: ["logo_uri"] };

	override evaluate(env: Environment): Environment {
		let logoUri: string;
		try {
			const baseUri = new URL(env.getString("base_url") as string);
			// new URI(scheme, null, host, port, path, null, null)
			logoUri =
				baseUri.protocol +
				"//" +
				baseUri.hostname +
				(baseUri.port !== "" ? ":" + baseUri.port : "") +
				CreateLogoUri.LOGO_PATH;
		} catch (e) {
			throw this.error("Failed to generate logo URI", e);
		}

		env.putString("logo_uri", logoUri);

		this.log("Generated logo URI", args("logo_uri", logoUri));

		return env;
	}
}
