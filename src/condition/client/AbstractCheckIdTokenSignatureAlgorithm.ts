import { AbstractCondition, args, type Environment } from "../../framework/index.ts";

export abstract class AbstractCheckIdTokenSignatureAlgorithm extends AbstractCondition {
	protected checkIdTokenSignatureAlgorithm(env: Environment, expectedAlg: string): Environment {
		const alg = env.getString("id_token", "header.alg");
		if (!alg) {
			throw this.error(
				"alg not present in ID token header",
				args("header", env.getElementFromObject("id_token", "header")),
			);
		}

		if (alg === expectedAlg) {
			this.logSuccess('ID token was signed with "' + expectedAlg + '" as expected');
		} else {
			throw this.error('ID token signature algorithm is not "' + expectedAlg + '"', args("alg", alg));
		}

		return env;
	}
}
