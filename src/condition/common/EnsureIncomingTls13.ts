import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class EnsureIncomingTls13 extends AbstractCondition {
	private static readonly TLS_13 = "TLSv1.3";

	static override pre: EnvironmentRequirements = { required: ["client_request"] };

	override evaluate(env: Environment): Environment {
		const protocol = env.getString("client_request", "headers.x-ssl-protocol");

		if (!protocol) {
			throw this.error("TLS protocol not found; this header should have been set by the nginx proxy");
		}

		if (protocol === EnsureIncomingTls13.TLS_13) {
			this.logSuccess("TLS 1.3 in use");
			return env;
		}

		throw this.error("Client doesn't support TLS 1.3", args("actual", protocol));
	}
}
