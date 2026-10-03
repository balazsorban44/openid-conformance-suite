import { VariantEnum, type VariantParameterInfo } from "../framework/index.ts";

export class ClientRegistration extends VariantEnum {
	static override readonly parameter: VariantParameterInfo = {
		name: "client_registration",
		sortOrder: 30,
		displayName: "Client Registration Type",
		description:
			"Whether the tests will use pre-configured (static) clients or will dynamically register the clients they need. If your server supports dynamic registration then it is recommended to use dynamic - it means less manual actions are required to run the tests.",
	};

	static readonly STATIC_CLIENT = new ClientRegistration("STATIC_CLIENT", "static_client");
	static readonly DYNAMIC_CLIENT = new ClientRegistration("DYNAMIC_CLIENT", "dynamic_client");

	private constructor(name: string, value: string) {
		super(name, value);
	}
}
