import { AbstractConditionSequence, ConditionResult } from "../framework/index.ts";
import { EnsureJwksHasNoPrivateOrSymmetricKeyMaterial } from "../condition/common/EnsureJwksHasNoPrivateOrSymmetricKeyMaterial.ts";
import { MapJwksToValidationLocation } from "../condition/common/MapJwksToValidationLocation.ts";
import { ParseUsableJwksKeys } from "../condition/common/ParseUsableJwksKeys.ts";
import { ValidateJwksStructure } from "../condition/common/ValidateJwksStructure.ts";
import { WarnOnUnusableJwksKeys } from "../condition/common/WarnOnUnusableJwksKeys.ts";

/**
 * Validates a JWK set wherever one enters the suite, with uniform severities: FAILURE for invalid
 * structure or private/symmetric key material, WARNING for keys using an unknown key type, curve or
 * algorithm. The caller names the source location (a top-level environment object, or a nested path
 * within one) and a human-readable label that is woven into the result messages (e.g. "client_metadata"),
 * so a single set of source-agnostic conditions still produces source-specific messages.
 *
 * @see net.openid.conformance.util.JWKUtil
 */
export class ValidateJwksSequence extends AbstractConditionSequence {
	private readonly sourceKey: string;
	private readonly sourcePath: string;
	private readonly label: string;
	private readonly requirements: string[];
	private allowPrivateKeys = false;

	/**
	 * @param sourceKey the top-level environment object holding (or containing) the JWK set
	 * @param sourcePath dot-separated path to the JWK set within {@code sourceKey}, or null/empty if
	 *                   {@code sourceKey} is itself the JWK set
	 * @param label human-readable name of the source, used in the result messages
	 * @param requirements spec requirement tags to attach to the validation results
	 */
	constructor(sourceKey: string, sourcePath: string | null, label: string, ...requirements: string[]) {
		super();
		this.sourceKey = sourceKey;
		this.sourcePath = sourcePath == null ? "" : sourcePath;
		this.label = label;
		this.requirements = [...requirements];
	}

	/**
	 * Mark the JWK set as a private (signing) key set that legitimately contains private key
	 * material, so the public-only check is skipped. Structure and unusable-key checks still run.
	 * Use for a set that is NOT advertised to a counterparty (e.g. the suite's own signing keys).
	 */
	allowingPrivateKeys(): this {
		this.allowPrivateKeys = true;
		return this;
	}

	override evaluate(): void {
		this.call(this.exec().startBlock("Validate the JWK set in " + this.label));

		this.call(
			this.exec()
				.putString("jwks_validation_source_key", this.sourceKey)
				.putString("jwks_validation_source_path", this.sourcePath)
				.putString("jwks_source_label", this.label),
		);

		if (this.sourcePath === "") {
			this.call(this.condition(MapJwksToValidationLocation).skipIfObjectMissing(this.sourceKey));
		} else {
			this.call(this.condition(MapJwksToValidationLocation).skipIfElementMissing(this.sourceKey, this.sourcePath));
		}

		if (!this.allowPrivateKeys) {
			this.call(
				this.condition(EnsureJwksHasNoPrivateOrSymmetricKeyMaterial)
					.skipIfObjectMissing("jwks_to_validate")
					.onFail(ConditionResult.FAILURE)
					.dontStopOnFailure()
					.requirements(this.requirements),
			);
		}

		this.call(
			this.condition(ValidateJwksStructure)
				.skipIfObjectMissing("jwks_to_validate")
				.onFail(ConditionResult.FAILURE)
				.dontStopOnFailure()
				.requirements(this.requirements),
		);

		this.call(
			this.condition(ParseUsableJwksKeys)
				.skipIfObjectMissing("jwks_to_validate")
				.onFail(ConditionResult.FAILURE)
				.dontStopOnFailure()
				.requirements(this.requirements),
		);

		this.call(
			this.condition(WarnOnUnusableJwksKeys)
				.skipIfObjectMissing("jwks_to_validate")
				.onFail(ConditionResult.WARNING)
				.dontStopOnFailure()
				.requirements(this.requirements),
		);

		this.call(
			this.exec()
				.removeObject("jwks_to_validate")
				.removeNativeValue("jwks_validation_source_key")
				.removeNativeValue("jwks_validation_source_path")
				.removeNativeValue("jwks_source_label")
				.endBlock(),
		);
	}
}
