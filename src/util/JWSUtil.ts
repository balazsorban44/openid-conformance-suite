import {
	JWS_FAMILY_EC,
	JWS_FAMILY_ED,
	JWS_FAMILY_HMAC_SHA,
	JWS_FAMILY_RSA,
	requireAlgorithmName,
} from "./nimbus/algorithms.ts";

export class JWSUtil {
	/**
	 * Asymmetric JWS algorithms registered in the IANA JOSE Algorithms registry that are
	 * not yet exposed by Nimbus families. The Nimbus EC/ED/RSA families miss these recently
	 * registered post-quantum and revised algorithm names; until the dependency catches up
	 * we treat membership in this set as equivalent to membership in the Nimbus families.
	 *
	 * @see <a href="https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms">IANA JOSE Algorithms registry</a>
	 */
	private static readonly EXTRA_ASYMMETRIC_JWS_ALGORITHMS: readonly string[] = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"];

	/**
	 * Checks if alg is one of the algorithms supported by Nimbusds
	 * @param alg
	 * @return
	 */
	static isValidJWSAlgorithm(alg: string | null | undefined): boolean {
		alg = requireAlgorithmName(alg);
		if (
			JWS_FAMILY_EC.includes(alg) ||
			JWS_FAMILY_ED.includes(alg) ||
			JWS_FAMILY_HMAC_SHA.includes(alg) ||
			JWS_FAMILY_RSA.includes(alg)
		) {
			return true;
		}
		return JWSUtil.EXTRA_ASYMMETRIC_JWS_ALGORITHMS.includes(alg);
	}

	static validJWSAlgorithms(): string[] {
		return JWSUtil.familyNamesWithExtras(JWS_FAMILY_EC, JWS_FAMILY_ED, JWS_FAMILY_HMAC_SHA, JWS_FAMILY_RSA);
	}

	/**
	 * Checks if alg is an asymmetric algorithm
	 * @param alg
	 * @return
	 */
	static isAsymmetricJWSAlgorithm(alg: string | null | undefined): boolean {
		alg = requireAlgorithmName(alg);
		if (JWS_FAMILY_EC.includes(alg) || JWS_FAMILY_ED.includes(alg) || JWS_FAMILY_RSA.includes(alg)) {
			return true;
		}
		return JWSUtil.EXTRA_ASYMMETRIC_JWS_ALGORITHMS.includes(alg);
	}

	static validAsymmetricJWSAlgorithms(): string[] {
		return JWSUtil.familyNamesWithExtras(JWS_FAMILY_EC, JWS_FAMILY_ED, JWS_FAMILY_RSA);
	}

	/**
	 * Collects the algorithm names of the given Nimbus families plus the
	 * {@link JWSUtil.EXTRA_ASYMMETRIC_JWS_ALGORITHMS} not yet exposed by Nimbus.
	 */
	private static familyNamesWithExtras(...families: (readonly string[])[]): string[] {
		return [...families.flat(), ...JWSUtil.EXTRA_ASYMMETRIC_JWS_ALGORITHMS];
	}
}
