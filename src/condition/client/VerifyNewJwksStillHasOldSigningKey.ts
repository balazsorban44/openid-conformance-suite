import { args, type JsonObject } from "../../framework/index.ts";
import { AbstractCompareJwks } from "./AbstractCompareJwks.ts";

export class VerifyNewJwksStillHasOldSigningKey extends AbstractCompareJwks {
	protected override compareJwks(originalSigningKeys: JsonObject[], latestSigningKeys: JsonObject[]): void {
		const keysInBoth = originalSigningKeys.filter((k) => AbstractCompareJwks.setContains(latestSigningKeys, k));

		if (keysInBoth.length === 0) {
			throw this.error(
				"None of the previous present keys (with 'use':'sig' or no 'use') are still present. The specification says 'The JWK Set document at the jwks_uri SHOULD retain recently decommissioned signing keys for a reasonable period of time to facilitate a smooth transition.'.",
				args("original_signing_keys", originalSigningKeys, "latest_signing_keys", latestSigningKeys),
			);
		}

		this.logSuccess("Some keys are in both the old and new JWKS", args("signing_keys_in_both", keysInBoth));
	}
}
