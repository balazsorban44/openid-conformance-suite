import { VariantEnum, type VariantParameterInfo } from "../framework/index.ts";

export class OIDCCClientAuthType extends VariantEnum {
	static override readonly parameter: VariantParameterInfo = {
		name: "client_auth_type",
		displayName: "Client Authentication Type",
		description:
			"The type of client authentication your software supports. " +
			"If you support multiple types of client authentication test each one, one at a time.",
	};

	static readonly NONE = new OIDCCClientAuthType("NONE", "none");
	static readonly CLIENT_SECRET_BASIC = new OIDCCClientAuthType("CLIENT_SECRET_BASIC", "client_secret_basic");
	static readonly CLIENT_SECRET_POST = new OIDCCClientAuthType("CLIENT_SECRET_POST", "client_secret_post");
	static readonly CLIENT_SECRET_JWT = new OIDCCClientAuthType("CLIENT_SECRET_JWT", "client_secret_jwt");
	static readonly PRIVATE_KEY_JWT = new OIDCCClientAuthType("PRIVATE_KEY_JWT", "private_key_jwt");
	static readonly TLS_CLIENT_AUTH = new OIDCCClientAuthType("TLS_CLIENT_AUTH", "tls_client_auth");
	static readonly SELF_SIGNED_TLS_CLIENT_AUTH = new OIDCCClientAuthType(
		"SELF_SIGNED_TLS_CLIENT_AUTH",
		"self_signed_tls_client_auth",
	);

	private constructor(name: string, value: string) {
		super(name, value);
	}
}
