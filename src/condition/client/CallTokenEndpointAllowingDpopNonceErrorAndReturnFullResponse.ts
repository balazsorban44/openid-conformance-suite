import {
	args,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type HttpResponse,
	type JsonObject,
} from "../../framework/index.ts";
import { DpopNonceResponseHeader } from "../../util/http/DpopNonceResponseHeader.ts";
import { CallTokenEndpointAndReturnFullResponse } from "./CallTokenEndpointAndReturnFullResponse.ts";

/**
 * Wrapper around {@link CallTokenEndpointAndReturnFullResponse} that recognizes a {@code use_dpop_nonce} 400
 * response and exposes the supplied DPoP-Nonce so the caller can retry.
 */
export class CallTokenEndpointAllowingDpopNonceErrorAndReturnFullResponse extends CallTokenEndpointAndReturnFullResponse {
	/** The nonce the server supplied on this response, or null if it supplied none. */
	private suppliedDpopNonce: string | null = null;

	// WARNING optional token_endpoint_dpop_nonce_error returned with required nonce value
	static override pre: EnvironmentRequirements = {
		required: ["server", "token_endpoint_request_form_parameters"],
	};
	static override post: EnvironmentRequirements = { required: ["token_endpoint_response"] };

	override async evaluate(env: Environment): Promise<Environment> {
		env.removeNativeValue("token_endpoint_dpop_nonce_error");
		return await super.evaluate(env);
	}

	protected override addFullResponse(env: Environment, response: HttpResponse): void {
		super.addFullResponse(env, response);
		const jsonError = env.getElementFromObject("token_endpoint_response_full", "body_json.error");
		const jsonResponseHeaders = env.getObject("token_endpoint_response_headers") as JsonObject;
		const status = env.getInteger("token_endpoint_response_http_status") as number;

		// A DPoP-Nonce that breaks RFC9449 is reported whatever the status code was, so that the violation is
		// attributed to the response that carried it rather than to whatever we do with the value later on.
		const nonceHeader = DpopNonceResponseHeader.from(jsonResponseHeaders);
		if (nonceHeader.violation != null) {
			throw this.error(nonceHeader.violation, args("headers", jsonResponseHeaders));
		}
		const dpopNonce = nonceHeader.nonce;
		this.suppliedDpopNonce = dpopNonce;

		if (status === 400 && jsonError != null && OIDFJSON.getString(jsonError) === "use_dpop_nonce") {
			if (dpopNonce == null) {
				throw this.error(
					"The token endpoint returned a 'use_dpop_nonce' error but supplied no DPoP-Nonce" +
						" header, leaving no nonce to retry the request with.",
					args("headers", jsonResponseHeaders),
				);
			}
			env.putString("authorization_server_dpop_nonce", dpopNonce);
			env.putString("token_endpoint_dpop_nonce_error", dpopNonce);
			env.putObject(
				"token_endpoint_response",
				env.getElementFromObject("token_endpoint_response_full", "body_json") as JsonObject,
			);
		} else if (status >= 200 && status < 300 && dpopNonce != null) {
			// RFC 9449 §8.2: the server may rotate the DPoP nonce on every response and the
			// client MUST use the newly supplied value on subsequent requests. Some ASes treat
			// each nonce as single-use (reusing one returns invalid_dpop_proof with no recovery
			// path), so harvesting the freshly issued nonce from a successful response is
			// required to avoid stale-nonce reuse on the next call.
			env.putString("authorization_server_dpop_nonce", dpopNonce);
		}
	}

	protected override parsedResponseLogSuffix(): string {
		return " - " + DpopNonceResponseHeader.describeSuppliedNonce(this.suppliedDpopNonce);
	}
}
