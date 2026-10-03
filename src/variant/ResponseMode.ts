import { VariantEnum, type VariantParameterInfo } from "../framework/index.ts";

export class ResponseMode extends VariantEnum {
	static override readonly parameter: VariantParameterInfo = {
		name: "response_mode",
		displayName: "Response Mode",
		description:
			"The response mode that will be tested. 'default' is required for certification, 'form_post' is optional.",
	};

	/**
	 * default mode for the response type
	 */
	static readonly DEFAULT = new ResponseMode("DEFAULT", "default");
	static readonly FORM_POST = new ResponseMode("FORM_POST", "form_post");

	private readonly modeValue: string;

	private constructor(name: string, responseMode: string) {
		super(name, responseMode);
		this.modeValue = responseMode;
	}

	isFormPost(): boolean {
		return "form_post" === this.modeValue;
	}
}
