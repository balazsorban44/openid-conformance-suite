import { createHash, type Hash } from "node:crypto";
import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { InvalidAlgorithmException, JWAUtil } from "../../util/JWAUtil.ts";

/** Java String.getBytes(US_ASCII): every non-ASCII character (code point) becomes '?' */
function toUsAscii(s: string): string {
	return Array.from(s, (c) => ((c.codePointAt(0) as number) > 0x7f ? "?" : c)).join("");
}

export class CalculateCHash extends AbstractCondition {
	static override pre: EnvironmentRequirements = { strings: ["signing_algorithm", "authorization_code"] };
	static override post: EnvironmentRequirements = { strings: ["c_hash"] };

	override evaluate(env: Environment): Environment {
		const algorithm = env.getString("signing_algorithm") as string;

		const code = env.getString("authorization_code") as string;

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
		const digest = digester.update(Buffer.from(toUsAscii(code), "latin1")).digest();

		const halfDigest = digest.subarray(0, Math.floor(digest.length / 2));

		const hashValue = Buffer.from(halfDigest).toString("base64url");

		env.putString("c_hash", hashValue);

		this.logSuccess("Successful c_hash encoding", args("c_hash", hashValue));

		return env;
	}
}
