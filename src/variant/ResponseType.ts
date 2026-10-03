import { VariantEnum, type VariantParameterInfo } from "../framework/index.ts";

export class ResponseType extends VariantEnum {
	static override readonly parameter: VariantParameterInfo = {
		name: "response_type",
		sortOrder: 40,
		displayName: "Response Type",
		description:
			"The Response Type to be used in testing. A separate test plan should be run for each response type that needs to be tested.",
	};

	static readonly CODE = new ResponseType("CODE", ["code"]);
	static readonly ID_TOKEN = new ResponseType("ID_TOKEN", ["id_token"]);
	static readonly ID_TOKEN_TOKEN = new ResponseType("ID_TOKEN_TOKEN", ["id_token", "token"]);
	static readonly CODE_ID_TOKEN = new ResponseType("CODE_ID_TOKEN", ["code", "id_token"]);
	static readonly CODE_TOKEN = new ResponseType("CODE_TOKEN", ["code", "token"]);
	static readonly CODE_ID_TOKEN_TOKEN = new ResponseType("CODE_ID_TOKEN_TOKEN", ["code", "id_token", "token"]);

	private readonly types: readonly string[];

	private constructor(name: string, responseTypes: string[]) {
		super(name, responseTypes.join(" "));
		this.types = Object.freeze([...responseTypes]);
	}

	includesCode(): boolean {
		return this.types.includes("code");
	}

	includesIdToken(): boolean {
		return this.types.includes("id_token");
	}

	includesToken(): boolean {
		return this.types.includes("token");
	}

	isIdToken(): boolean {
		return this.types.length === 1 && this.includesIdToken();
	}
}
