import type { Environment, EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractValidateJWKs } from "./AbstractValidateJWKs.ts";

export class ValidateClientJWKsPrivatePart extends AbstractValidateJWKs {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override async evaluate(env: Environment): Promise<Environment> {
		const jwks = env.getElementFromObject("client", "jwks");

		await this.checkJWKs(jwks, true);

		this.logSuccess(
			"Valid client JWKs: keys are valid JSON, contain the required fields, the private/public exponents match and are correctly encoded using unpadded base64url",
		);

		return env;
	}
}
