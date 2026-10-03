import { AbstractCondition, args, type Environment } from "../framework/index.ts";

export abstract class AbstractEnsureMinimumEntropy extends AbstractCondition {
	protected ensureMinimumEntropy(
		env: Environment,
		s: string,
		requiredEntropy: number,
		successMessage = "Calculated shannon entropy seems sufficient",
		errorMessage = "Calculated shannon entropy does not seem to meet minimum required entropy (i.e. item is too short, or not random enough)",
	): Environment {
		const bitsPerCharacter = this.getShannonEntropy(s);

		const entropy = bitsPerCharacter * s.length;

		if (entropy > requiredEntropy) {
			this.logSuccess(successMessage, args("value", s, "expected", requiredEntropy, "actual", entropy));
			return env;
		} else {
			throw this.error(errorMessage, args("value", s, "expected", requiredEntropy, "actual", entropy));
		}
	}

	// entropy calculation from https://rosettacode.org/wiki/Entropy#Java
	protected getShannonEntropy(s: string): number {
		let n = 0;
		const occ = new Map<string, number>();

		for (let c_ = 0; c_ < s.length; ++c_) {
			const cx = s.charAt(c_);
			if (occ.has(cx)) {
				occ.set(cx, (occ.get(cx) as number) + 1);
			} else {
				occ.set(cx, 1);
			}
			++n;
		}

		let e = 0.0;
		for (const value of javaHashMapCharacterOrder(occ)) {
			const p = value / n;
			e += p * AbstractEnsureMinimumEntropy.log2(p);
		}
		return -e;
	}

	private static log2(a: number): number {
		return Math.log(a) / Math.log(2);
	}
}

/**
 * The values of a Java HashMap<Character, Integer> in its iteration order (bucket index = char code & (capacity - 1),
 * insertion order within a bucket), so the floating point sum above is accumulated in the same order as in Java.
 */
function javaHashMapCharacterOrder(occ: Map<string, number>): number[] {
	let capacity = 16;
	while (occ.size > capacity * 0.75) {
		capacity *= 2;
	}
	return [...occ.entries()]
		.map(([ch, count], insertion) => ({ bucket: ch.charCodeAt(0) & (capacity - 1), insertion, count }))
		.sort((a, b) => a.bucket - b.bucket || a.insertion - b.insertion)
		.map((x) => x.count);
}
