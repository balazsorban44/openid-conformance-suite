import { randomInt, randomUUID } from "node:crypto";
import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { JOSEException } from "../../util/JWEUtil.ts";
import { JWKUtil, type JWK } from "../../util/JWKUtil.ts";
import { PreGeneratedJwks } from "../../util/PreGeneratedJwks.ts";

/** Nimbus KeyType value ("EC", "RSA", "OKP", ...) */
type KeyType = string;
/** Nimbus KeyUse value ("sig" = KeyUse.SIGNATURE, "enc" = KeyUse.ENCRYPTION) */
type KeyUse = string;
/** Nimbus Curve name ("P-256", "secp256k1", "Ed25519", ...) */
type Curve = string;

export class OIDCCGenerateServerJWKs extends AbstractCondition {
	protected numberOfRSASigningKeysWithNoAlg = 2;
	protected numberOfECCurveP256SigningKeysWithNoAlg = 2;
	protected numberOfECCurveSECP256KSigningKeysWithNoAlg = 1;
	protected numberOfOKPSigningKeysWithNoAlg = 1;

	protected numberOfRSSigningKeys = 0;
	protected numberOfPSSigningKeys = 0;
	protected numberOfES256SigningKeys = 0;
	protected numberOfEdSigningKeys = 0;

	protected numberOfRSAEncKeys = 1;
	protected numberOfECEncKeys = 1;

	protected generateSigKids = true;
	protected generateEncKids = true;

	protected rsaKeySize = 2048;
	protected esCurve: Curve = "P-256";
	protected esKCurve: Curve = "secp256k1";
	protected edCurve: Curve = "Ed25519";

	protected allGeneratedKeys: JWK[] = [];
	protected signingKeyToBeUsed: JWK[] = [];
	protected encryptionKeysToBeUsed: JWK[] = [];

	protected rsSigningAlgorithm = "RS256";
	protected psSigningAlgorithm = "PS256";
	protected esSigningAlgorithm = "ES256";

	protected encryptionAlgorithmForRSAKeys = "RSA-OAEP";
	protected encryptionAlgorithmForECKeys = "ECDH-ES";

	/**
	 * override this and call setters to set number of keys
	 */
	protected setupParameters(): void {}

	static override post: EnvironmentRequirements = {
		required: ["server_public_jwks", "server_jwks", "server_encryption_keys"],
	};

	override evaluate(env: Environment): Environment {
		this.allGeneratedKeys = [];
		this.signingKeyToBeUsed = [];
		this.encryptionKeysToBeUsed = [];
		this.setupParameters();

		try {
			//changing the order of createKeys calls here may affect the signing key selection
			//See JWKUtil.selectAsymmetricJWSKey for full details
			this.createKeys(env, this.numberOfRSASigningKeysWithNoAlg, "RSA", "sig", null, null);
			this.createKeys(env, this.numberOfECCurveP256SigningKeysWithNoAlg, "EC", "sig", null, this.esCurve);
			this.createKeys(env, this.numberOfECCurveSECP256KSigningKeysWithNoAlg, "EC", "sig", null, this.esKCurve);
			this.createKeys(env, this.numberOfOKPSigningKeysWithNoAlg, "OKP", "sig", null, null);

			this.createKeys(env, this.numberOfRSSigningKeys, "RSA", "sig", this.rsSigningAlgorithm, null);
			this.createKeys(env, this.numberOfES256SigningKeys, "EC", "sig", this.esSigningAlgorithm, this.esCurve);
			this.createKeys(env, this.numberOfPSSigningKeys, "RSA", "sig", this.psSigningAlgorithm, null);
			this.createKeys(env, this.numberOfEdSigningKeys, "OKP", "sig", "EdDSA", null);

			this.createKeys(env, this.numberOfRSAEncKeys, "RSA", "enc", this.encryptionAlgorithmForRSAKeys, null);
			this.createKeys(env, this.numberOfECEncKeys, "EC", "enc", this.encryptionAlgorithmForECKeys, this.esCurve);

			const publicJwkSet: JsonObject = { keys: this.allGeneratedKeys };
			const publicJwks = JWKUtil.getPublicJwksAsJsonObject(publicJwkSet);

			const privateJwkSet: JsonObject = { keys: this.signingKeyToBeUsed };
			const jwks = JWKUtil.getPrivateJwksAsJsonObject(privateJwkSet);

			const encJwkSet: JsonObject = { keys: this.encryptionKeysToBeUsed };
			const encJwks = JWKUtil.getPrivateJwksAsJsonObject(encJwkSet);

			env.putObject("server_public_jwks", publicJwks);
			env.putObject("server_jwks", jwks);
			env.putObject("server_encryption_keys", encJwks);

			this.log(
				"Generated server public private JWK sets",
				args("server_public_jwks", publicJwks, "server_jwks", jwks, "server_encryption_keys", encJwks),
			);

			return env;
		} catch (e) {
			if (!(e instanceof JOSEException)) {
				throw e;
			}
			throw this.error("Failed to generate server JWK Set", e);
		}
	}

	/**
	 *
	 * @param keyCount
	 * @param keyType EC, RSA or OKP
	 * @param keyUse if null keys won't have use
	 * @param algorithm if null keys won't have alg
	 * @throws JOSEException
	 */
	protected createKeys(
		env: Environment,
		keyCount: number,
		keyType: KeyType,
		keyUse: KeyUse | null,
		algorithm: string | null,
		curveForECKeys: Curve | null,
	): void {
		if (keyCount < 1) {
			return;
		}
		const whichKeyToUse = this.getIndexOfKeyToUse(keyCount);

		for (let i = 0; i < keyCount; i++) {
			// Pull from a process-wide pool of pre-generated keypairs rather than
			// running fresh RSA/EC primality work per test. The kid (when set) is
			// still fresh per handout so kid-based lookups behave the same as before.
			const kid =
				(this.generateSigKids && (null == keyUse || "sig" === keyUse)) ||
				(this.generateEncKids && (null == keyUse || "enc" === keyUse))
					? randomUUID()
					: null;
			let generatedJWK: JWK;
			if ("EC" === keyType) {
				// PreGeneratedJwks returns a fresh copy, so it can be modified like the Nimbus builder
				const b = PreGeneratedJwks.nextEcKey(env, curveForECKeys as Curve);
				if (keyUse != null) {
					b["use"] = keyUse;
				}
				if (kid != null) {
					b["kid"] = kid;
				}
				if (algorithm != null) {
					b["alg"] = algorithm;
				}
				generatedJWK = b;
			} else if ("RSA" === keyType) {
				const b = PreGeneratedJwks.nextRsaKey(env, this.rsaKeySize);
				if (keyUse != null) {
					b["use"] = keyUse;
				}
				if (kid != null) {
					b["kid"] = kid;
				}
				if (algorithm != null) {
					b["alg"] = algorithm;
				}
				generatedJWK = b;
			} else if ("OKP" === keyType) {
				const b = PreGeneratedJwks.nextOkpKey(env, this.edCurve);
				if (keyUse != null) {
					b["use"] = keyUse;
				}
				if (kid != null) {
					b["kid"] = kid;
				}
				if (algorithm != null) {
					b["alg"] = algorithm;
				}
				generatedJWK = b;
			} else {
				throw new JOSEException("Unsupported key type: " + keyType);
			}
			this.allGeneratedKeys.push(generatedJWK);
			if ((keyUse as KeyUse) === "enc") {
				this.encryptionKeysToBeUsed.push(generatedJWK);
			}

			if (i === whichKeyToUse && (keyUse as KeyUse) === "sig") {
				this.signingKeyToBeUsed.push(generatedJWK);
			}
		}
	}

	/**
	 * Returns a random key index
	 * Override to use a constant index
	 * @return
	 */
	protected getIndexOfKeyToUse(keyCount: number): number {
		if (keyCount < 2) {
			return 0;
		}
		// Bound is exclusive, so it must be keyCount (not keyCount - 1) to allow every key
		// index 0..keyCount-1 to be selectable; the old keyCount-1 never picked the last key
		// (and was deterministically 0 for keyCount == 2).
		const index = randomInt(0, keyCount);
		return index;
	}

	setNumberOfRSAEncKeys(numberOfRSAEncKeys: number): void {
		this.numberOfRSAEncKeys = numberOfRSAEncKeys;
	}

	setNumberOfECEncKeys(numberOfECEncKeys: number): void {
		this.numberOfECEncKeys = numberOfECEncKeys;
	}

	setGenerateSigKids(generateSigKids: boolean): void {
		this.generateSigKids = generateSigKids;
	}

	setGenerateEncKids(generateEncKids: boolean): void {
		this.generateEncKids = generateEncKids;
	}

	setRsaKeySize(rsaKeySize: number): void {
		this.rsaKeySize = rsaKeySize;
	}

	setEncryptionAlgorithmForECKeys(encryptionAlgorithmForECKeys: string): void {
		this.encryptionAlgorithmForECKeys = encryptionAlgorithmForECKeys;
	}

	getNumberOfRSSigningKeys(): number {
		return this.numberOfRSSigningKeys;
	}

	setNumberOfRSSigningKeys(numberOfRSSigningKeys: number): void {
		this.numberOfRSSigningKeys = numberOfRSSigningKeys;
	}

	getNumberOfPSSigningKeys(): number {
		return this.numberOfPSSigningKeys;
	}

	setNumberOfPSSigningKeys(numberOfPSSigningKeys: number): void {
		this.numberOfPSSigningKeys = numberOfPSSigningKeys;
	}

	getNumberOfES256SigningKeys(): number {
		return this.numberOfES256SigningKeys;
	}

	setNumberOfES256SigningKeys(numberOfES256SigningKeys: number): void {
		this.numberOfES256SigningKeys = numberOfES256SigningKeys;
	}

	getNumberOfEdSigningKeys(): number {
		return this.numberOfEdSigningKeys;
	}

	setNumberOfEdSigningKeys(numberOfEdSigningKeys: number): void {
		this.numberOfEdSigningKeys = numberOfEdSigningKeys;
	}

	getNumberOfRSAEncKeys(): number {
		return this.numberOfRSAEncKeys;
	}

	getNumberOfECEncKeys(): number {
		return this.numberOfECEncKeys;
	}

	isGenerateSigKids(): boolean {
		return this.generateSigKids;
	}

	isGenerateEncKids(): boolean {
		return this.generateEncKids;
	}

	getRsaKeySize(): number {
		return this.rsaKeySize;
	}

	getEdCurve(): Curve {
		return this.edCurve;
	}

	setEdCurve(edCurve: Curve): void {
		this.edCurve = edCurve;
	}

	getRsSigningAlgorithm(): string {
		return this.rsSigningAlgorithm;
	}

	setRsSigningAlgorithm(rsSigningAlgorithm: string): void {
		this.rsSigningAlgorithm = rsSigningAlgorithm;
	}

	getPsSigningAlgorithm(): string {
		return this.psSigningAlgorithm;
	}

	setPsSigningAlgorithm(psSigningAlgorithm: string): void {
		this.psSigningAlgorithm = psSigningAlgorithm;
	}

	getEsSigningAlgorithm(): string {
		return this.esSigningAlgorithm;
	}

	setEsSigningAlgorithm(esSigningAlgorithm: string): void {
		this.esSigningAlgorithm = esSigningAlgorithm;
	}

	getEncryptionAlgorithmForRSAKeys(): string {
		return this.encryptionAlgorithmForRSAKeys;
	}

	setEncryptionAlgorithmForRSAKeys(encryptionAlgorithmForRSAKeys: string): void {
		this.encryptionAlgorithmForRSAKeys = encryptionAlgorithmForRSAKeys;
	}

	getEncryptionAlgorithmForECKeys(): string {
		return this.encryptionAlgorithmForECKeys;
	}

	getNumberOfRSASigningKeysWithNoAlg(): number {
		return this.numberOfRSASigningKeysWithNoAlg;
	}

	setNumberOfRSASigningKeysWithNoAlg(numberOfRSASigningKeysWithNoAlg: number): void {
		this.numberOfRSASigningKeysWithNoAlg = numberOfRSASigningKeysWithNoAlg;
	}

	getNumberOfOKPSigningKeysWithNoAlg(): number {
		return this.numberOfOKPSigningKeysWithNoAlg;
	}

	setNumberOfOKPSigningKeysWithNoAlg(numberOfOKPSigningKeysWithNoAlg: number): void {
		this.numberOfOKPSigningKeysWithNoAlg = numberOfOKPSigningKeysWithNoAlg;
	}

	getNumberOfECCurveP256SigningKeysWithNoAlg(): number {
		return this.numberOfECCurveP256SigningKeysWithNoAlg;
	}

	setNumberOfECCurveP256SigningKeysWithNoAlg(numberOfECCurveP256SigningKeysWithNoAlg: number): void {
		this.numberOfECCurveP256SigningKeysWithNoAlg = numberOfECCurveP256SigningKeysWithNoAlg;
	}

	getNumberOfECCurveP256KSigningKeysWithNoAlg(): number {
		return this.numberOfECCurveSECP256KSigningKeysWithNoAlg;
	}

	setNumberOfECCurveSECP256KSigningKeysWithNoAlg(numberOfECCurveSECP256KSigningKeysWithNoAlg: number): void {
		this.numberOfECCurveSECP256KSigningKeysWithNoAlg = numberOfECCurveSECP256KSigningKeysWithNoAlg;
	}

	getEsCurve(): Curve {
		return this.esCurve;
	}

	setEsCurve(esCurve: Curve): void {
		this.esCurve = esCurve;
	}

	getEsKCurve(): Curve {
		return this.esKCurve;
	}

	setEsKCurve(esKCurve: Curve): void {
		this.esKCurve = esKCurve;
	}
}
