import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonArray,
	type JsonObject,
} from "../../framework/index.ts";

export class CreateInvalidSectorRedirectUris extends AbstractCondition {
	static override post: EnvironmentRequirements = { required: ["sector_redirect_uris"] };

	override evaluate(env: Environment): Environment {
		const sectorRedirectUris: JsonArray = [];
		sectorRedirectUris.push("https://example.com/op");

		const obj: JsonObject = {};
		obj["value"] = sectorRedirectUris;

		env.putObject("sector_redirect_uris", obj);

		this.log("Created invalid sector redirect URIs", args("sector_redirect_uris", obj));

		return env;
	}
}
