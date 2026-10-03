import { createHash } from "node:crypto";
import { AbstractCondition, args, isJsonPrimitive, OIDFJSON, type Environment } from "../../framework/index.ts";
import { InvalidAlgorithmException, JWAUtil } from "../../util/JWAUtil.ts";

export abstract class AbstractValidateHash extends AbstractCondition {
	validateHash(env: Environment, hashName: string, envName: string): Environment {
		const hashJson = env.getObject(envName);
		if (hashJson == null) {
			throw this.error("Couldn't find " + hashName);
		}

		const algElement = hashJson["alg"];
		if (algElement == null) {
			throw this.error("Could not find alg field.");
		}

		const hashElement = hashJson[hashName];
		if (hashElement == null) {
			throw this.error("Could not find " + hashName + " field.");
		}

		let alg: string | null = null;
		let hash: string | null = null;

		if (isJsonPrimitive(algElement)) {
			alg = OIDFJSON.getString(algElement);
		}

		if (isJsonPrimitive(hashElement)) {
			hash = OIDFJSON.getString(hashElement);
		}

		if (!alg) {
			throw this.error("Alg is null or empty. Invalid");
		}

		if (!hash) {
			throw this.error(hashName + " element is null or empty. Invalid");
		}

		const baseString = this.getBaseStringBasedOnType(env, hashName);

		let digestAlgorithm: string;

		try {
			digestAlgorithm = JWAUtil.getDigestAlgorithmForSigAlg(alg);
		} catch (e) {
			if (e instanceof InvalidAlgorithmException) {
				throw this.error("Invalid algorithm", args("alg", alg));
			}
			throw e;
		}

		// MessageDigest.getInstance("SHA-256") -> createHash("sha256")
		let digester;
		try {
			digester = createHash(digestAlgorithm.replace("-", "").toLowerCase());
		} catch (e) {
			throw this.error("Unsupported digest for algorithm", e, args("alg", alg));
		}

		// baseString.getBytes(StandardCharsets.US_ASCII): characters outside US-ASCII become '?'
		const asciiBytes = Buffer.from(
			Array.from(baseString, (c) => (c.charCodeAt(0) < 0x80 ? c : "?")).join(""),
			"latin1",
		);
		const stateDigest = digester.update(asciiBytes).digest();

		const halfDigest = stateDigest.subarray(0, stateDigest.length / 2);

		const expectedHash = halfDigest.toString("base64url");
		if (hash !== expectedHash) {
			throw this.error(
				"Invalid " + hashName + " in token",
				args("expected_hash", expectedHash, "id_token_hash", hash, "unhashed_value", baseString),
			);
		}

		this.logSuccess(
			hashName + " validated successfully",
			args("expected_hash", expectedHash, "id_token_hash", hash, "unhashed_value", baseString),
		);

		return env;
	}

	protected getBaseStringBasedOnType(env: Environment, hashName: string): string {
		let baseString: string | null = null;

		switch (hashName) {
			case "s_hash":
				baseString = env.getString("state");
				if (baseString == null) {
					throw this.error("Couldn't find state");
				}
				break;
			case "at_hash": {
				const accessToken = env.getObject("access_token");
				if (accessToken == null) {
					throw this.error("Could not get access_token object...");
				}
				baseString = OIDFJSON.getString(accessToken["value"]);
				break;
			}
			case "c_hash":
				baseString = env.getString("authorization_endpoint_response", "code");
				if (baseString == null) {
					throw this.error("Could not find authorization_endpoint_response.code");
				}
				break;
			default:
				throw this.error("Invalid HashName(" + hashName + ")");
		}

		return baseString;
	}
}
