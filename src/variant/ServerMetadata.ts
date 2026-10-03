import { VariantEnum, type VariantParameterInfo } from "../framework/index.ts";

export class ServerMetadata extends VariantEnum {
	static override readonly parameter: VariantParameterInfo = {
		name: "server_metadata",
		sortOrder: 20,
		displayName: "Auth server metadata location",
		description:
			"Whether the auth server supports discovery (i.e. has a '/.well-known/openid-configuration') or requires the endpoints to be statically configured. If your server supports discovery then it is recommended to use dynamic - it means less manual actions are required to run the tests.",
	};

	static readonly STATIC = new ServerMetadata("STATIC", "static");
	static readonly DISCOVERY = new ServerMetadata("DISCOVERY", "discovery");

	private constructor(name: string, value: string) {
		super(name, value);
	}
}
