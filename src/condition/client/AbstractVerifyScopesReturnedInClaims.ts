import { AbstractCondition, args, isJsonObject, type Environment, type JsonValue } from "../../framework/index.ts";

export abstract class AbstractVerifyScopesReturnedInClaims extends AbstractCondition {
	// https://github.com/OpenIDC/pyoidc/blob/master/src/oic/oic/message.py#L996
	protected readonly SCOPE_STANDARD_CLAIMS = new Map<string, string[]>([
		["openid", ["sub"]],
		[
			"profile",
			[
				"name",
				"given_name",
				"family_name",
				"middle_name",
				"nickname",
				"profile",
				"picture",
				"website",
				"gender",
				"birthdate",
				"zoneinfo",
				"locale",
				"updated_at",
				"preferred_username",
			],
		],
		["email", ["email", "email_verified"]],
		["address", ["address"]],
		["phone", ["phone_number", "phone_number_verified"]],
		["offline_access", []],
	]);

	protected verifyScopesInClaims(env: Environment, claims: JsonValue | undefined, claimsKey: string): Environment {
		if (claims == null || !isJsonObject(claims)) {
			throw this.error("'claims' in " + claimsKey + " is invalid", args("claims", claims ?? null));
		}

		const scopeStr = env.getString("authorization_endpoint_request", "scope");

		if (!scopeStr) {
			throw this.error("'scope' not found in authorization endpoint request");
		}

		const claimsSet = new Set(Object.keys(claims));
		const scopeArr = scopeStr.split(" ");

		// https://github.com/rohe/oidctest/blob/master/src/oidctest/op/check.py#L2464
		const expectedScopeItems: string[] = [];
		for (const scope of scopeArr) {
			const scopeItems = this.SCOPE_STANDARD_CLAIMS.get(scope);
			// UPSTREAM: an unknown scope makes Java throw a NullPointerException (addAll(null)); here a TypeError
			expectedScopeItems.push(...(scopeItems as string[]));
		}

		const missingItems = new Set(expectedScopeItems);
		for (const c of claimsSet) {
			missingItems.delete(c);
		}

		if (!expectedScopeItems.every((item) => claimsSet.has(item))) {
			throw this.error(
				"'claims' in " +
					claimsKey +
					" doesn't contain all scope items of scope in authorization request(corresponds to scope standard claims)",
				args(
					"actual_scope_items",
					claimsSet,
					"expected_scope_items",
					expectedScopeItems,
					"missing_items",
					missingItems,
				),
			);
		}

		this.logSuccess(
			"'claims' in " +
				claimsKey +
				" contains all scope items of scope in authorization request (corresponds to scope standard claims)",
			args("actual_scope_items", claimsSet, "expected_scope_items", expectedScopeItems),
		);

		return env;
	}
}
