import { VariantEnum, type VariantParameterInfo } from "../framework/index.ts";

export class ClientAuthType extends VariantEnum {
	static override readonly parameter: VariantParameterInfo = {
		name: "client_auth_type",
		displayName: "Client Authentication Type",
		description:
			"The type of client authentication your software supports. If you support multiple types of client authentication test each one, one at a time.",
	};

	static readonly NONE = new ClientAuthType("NONE", "none");
	static readonly CLIENT_SECRET_BASIC = new ClientAuthType("CLIENT_SECRET_BASIC", "client_secret_basic");
	static readonly CLIENT_SECRET_POST = new ClientAuthType("CLIENT_SECRET_POST", "client_secret_post");
	static readonly CLIENT_SECRET_JWT = new ClientAuthType("CLIENT_SECRET_JWT", "client_secret_jwt");
	static readonly PRIVATE_KEY_JWT = new ClientAuthType("PRIVATE_KEY_JWT", "private_key_jwt");
	static readonly MTLS = new ClientAuthType("MTLS", "mtls");
	static readonly CLIENT_ATTESTATION = new ClientAuthType("CLIENT_ATTESTATION", "client_attestation");

	private constructor(name: string, value: string) {
		super(name, value);
	}
}
