import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonArray,
	type JsonObject,
} from "../../framework/index.ts";

export class CreateSectorRedirectUris extends AbstractCondition {
	static override pre: EnvironmentRequirements = { strings: ["redirect_uri"] };
	static override post: EnvironmentRequirements = { required: ["sector_redirect_uris"] };

	override evaluate(env: Environment): Environment {
		const sectorRedirectUris: JsonArray = [];
		sectorRedirectUris.push(env.getString("redirect_uri"));

		const obj: JsonObject = {};
		obj["value"] = sectorRedirectUris;

		env.putObject("sector_redirect_uris", obj);

		this.log("Created sector redirect URIs", args("sector_redirect_uris", obj));

		return env;
	}
}
