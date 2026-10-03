import { createHash, type Hash } from "node:crypto";
import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { toUsAscii } from "../../util/jdk/strings.ts";
import { InvalidAlgorithmException, JWAUtil } from "../../util/JWAUtil.ts";

export class CalculateAtHash extends AbstractCondition {
	static override pre: EnvironmentRequirements = { strings: ["signing_algorithm", "access_token"] };
	static override post: EnvironmentRequirements = { strings: ["at_hash"] };

	override evaluate(env: Environment): Environment {
		const algorithm = env.getString("signing_algorithm") as string;

		const accessToken = env.getString("access_token") as string;

		let digester: Hash;

		try {
			const digestAlgorithm = JWAUtil.getDigestAlgorithmForSigAlg(algorithm);
			// MessageDigest.getInstance("SHA-256") -> node:crypto createHash("sha256")
			digester = createHash(digestAlgorithm.replace("-", "").toLowerCase());
		} catch (e) {
			if (e instanceof InvalidAlgorithmException) {
				throw this.error("Unsupported algorithm", e, args("alg", algorithm));
			}
			// NoSuchAlgorithmException
			throw this.error("Unsupported digest for algorithm", e, args("alg", algorithm));
		}

		// US_ASCII: non-ASCII characters become '?'
		const digest = digester.update(Buffer.from(toUsAscii(accessToken), "latin1")).digest();

		const halfDigest = digest.subarray(0, Math.floor(digest.length / 2));

		const hashValue = Buffer.from(halfDigest).toString("base64url");

		env.putString("at_hash", hashValue);

		this.logSuccess("Successful at_hash encoding", args("at_hash", hashValue));

		return env;
	}
}
