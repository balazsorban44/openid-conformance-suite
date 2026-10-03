import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { CallPAREndpoint } from "./CallPAREndpoint.ts";

export class SetDpopHtmHtuForParEndpoint extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["server", "dpop_proof_claims"] };

	override evaluate(env: Environment): Environment {
		const claims = env.getObject("dpop_proof_claims") as JsonObject;

		const parEndpoint =
			env.getString("pushed_authorization_request_endpoint") != null
				? env.getString("pushed_authorization_request_endpoint")
				: env.getString("server", "pushed_authorization_request_endpoint");

		if (!parEndpoint) {
			throw this.error(
				"pushed_authorization_request_endpoint not found in server configuration",
				args("server_config", env.getObject("server")),
			);
		}

		const resourceMethod =
			env.getString(CallPAREndpoint.HTTP_METHOD_KEY) == null ? "POST" : env.getString(CallPAREndpoint.HTTP_METHOD_KEY);

		claims["htm"] = resourceMethod;
		claims["htu"] = parEndpoint;

		this.logSuccess("Added htm/htu to DPoP proof claims", claims);

		return env;
	}
}
