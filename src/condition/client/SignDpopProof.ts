import {
	AbstractCondition,
	args,
	ConditionError,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { JWKUtil, ParseException } from "../../util/JWKUtil.ts";
import { isJOSEException } from "../../util/nimbus/errors.ts";
import { JWSSigner } from "../../util/nimbus/jws.ts";
import { parseClaimsSet } from "../../util/nimbus/jwt.ts";

export class SignDpopProof extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["dpop_proof_claims", "client"] };
	static override post: EnvironmentRequirements = { strings: ["dpop_proof"] };

	override async evaluate(env: Environment): Promise<Environment> {
		const claims = env.getObject("dpop_proof_claims") as JsonObject;
		const headerJson = env.getObject("dpop_proof_header") as JsonObject;
		const jwk = env.getElementFromObject("client", "dpop_private_jwk") as JsonObject | undefined;
		if (jwk == null) {
			throw this.error("No dpop_private_jwk found.");
		}

		try {
			// JSONObjectUtils.parse(headerJson.toString())
			const headerClaims: JsonObject = structuredClone(headerJson);
			const alg = OIDFJSON.getString(headerJson["alg"]);
			if (alg == null) {
				throw this.error("No 'alg' field");
			}

			const signingJwk = JWKUtil.parseJWK(JSON.stringify(jwk));
			// new JWSHeader.Builder(alg).customParams(headerClaims).build()
			const header: JsonObject = { ...headerClaims, alg: alg };

			const claimSet = parseClaimsSet(claims);

			// new DefaultJWSSignerFactory().createJWSSigner(signingJwk, alg)
			const signer = JWSSigner.create(signingJwk, alg);

			const jws = await signer.sign(header, JSON.stringify(claimSet));

			// UPSTREAM: toPublicJWK() is null for a symmetric key, Java then throws a NullPointerException
			const publicKeySetString = JSON.stringify(JWKUtil.toPublicJWK(signingJwk));
			const verifiableObj: JsonObject = {};
			verifiableObj["verifiable_jws"] = jws;
			verifiableObj["public_jwk"] = publicKeySetString;

			env.putString("dpop_proof", jws);

			this.logSuccess("Signed the DPoP proof", args("dpop_proof", verifiableObj, "key", signingJwk));

			return env;
		} catch (e) {
			if (e instanceof ConditionError) {
				throw e;
			}
			if (e instanceof ParseException) {
				throw this.error(e);
			}
			if (isJOSEException(e)) {
				throw this.error("Unable to sign dpop proof: " + String(e.cause ?? null), e);
			}
			throw e;
		}
	}
}
