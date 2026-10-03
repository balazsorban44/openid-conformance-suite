import { VariantEnum, type VariantParameterInfo } from "../framework/index.ts";

export class ClientRequestType extends VariantEnum {
	static override readonly parameter: VariantParameterInfo = {
		name: "request_type",
		displayName: "Request Type",
		description:
			"Whether to use standard OAuth2 style requests, request objects (by value) or request_uri (i.e. request object by reference)",
	};

	static readonly PLAIN_HTTP_REQUEST = new ClientRequestType("PLAIN_HTTP_REQUEST", "plain_http_request");
	static readonly REQUEST_OBJECT = new ClientRequestType("REQUEST_OBJECT", "request_object");
	static readonly REQUEST_URI = new ClientRequestType("REQUEST_URI", "request_uri");

	private constructor(name: string, value: string) {
		super(name, value);
	}
}
