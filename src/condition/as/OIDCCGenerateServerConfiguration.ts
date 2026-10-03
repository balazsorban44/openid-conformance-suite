import {
	args,
	isJsonArray,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonArray,
	type JsonObject,
} from "../../framework/index.ts";
import {
	ENC_FAMILY_AES_CBC_HMAC_SHA,
	ENC_FAMILY_AES_GCM,
	JWE_FAMILY_ASYMMETRIC,
	JWE_FAMILY_SYMMETRIC,
	JWS_FAMILY_HMAC_SHA,
	JWS_FAMILY_SIGNATURE,
} from "../../util/JWKUtil.ts";
import { OIDCCLoadUserInfo } from "../rs/OIDCCLoadUserInfo.ts";
import { GenerateServerConfiguration } from "./GenerateServerConfiguration.ts";

export class OIDCCGenerateServerConfiguration extends GenerateServerConfiguration {
	static override pre: EnvironmentRequirements = { strings: ["base_url"] };
	static override post: EnvironmentRequirements = { required: ["server"], strings: ["issuer", "discoveryUrl"] };

	override evaluate(env: Environment): Environment {
		let baseUrl = env.getString("base_url") as string;
		if (!baseUrl.endsWith("/")) {
			baseUrl = baseUrl + "/";
		}

		this.createBaseConfiguration(env, baseUrl);
		const server = env.getObject("server") as JsonObject;

		server["userinfo_endpoint"] = baseUrl + "userinfo";
		server["registration_endpoint"] = baseUrl + "register";

		this.addScopesSupported(server);
		this.addResponseTypes(server);
		this.addResponseModes(server);
		this.addTokenEndpointAuthMethodsSupported(server);
		this.addTokenEndpointAuthSigningAlgValuesSupported(server);

		this.addGrantTypes(server);
		this.addClaimsParameterSupported(server);
		this.addAcrValuesSupported(server);
		this.addSubjectTypesSupported(server);
		this.addClaimTypesSupported(server);
		this.addClaimsSupported(server);

		this.addIdTokenSigningAlgValuesSupported(server);
		this.addIdTokenEncryptionAlgValuesSupported(server);
		this.addIdTokenEncryptionEncValuesSupported(server);

		this.addRequestObjectSigningAlgValuesSupported(server);
		this.addRequestObjectEncryptionAlgValuesSupported(server);
		this.addRequestObjectEncryptionEncValuesSupported(server);

		this.addUserinfoSigningAlgValuesSupported(server);
		this.addUserinfoEncryptionAlgValuesSupported(server);
		this.addUserinfoEncryptionEncValuesSupported(server);

		this.addAdditionalConfiguration(server, baseUrl);
		// add this as the server configuration
		env.putObject("server", server);
		this.logSuccess("Generated default server configuration", args("server_configuration", server));
		return env;
	}

	protected addScopesSupported(server: JsonObject): void {
		const scopes: JsonArray = [];
		scopes.push("openid");
		scopes.push("phone");
		scopes.push("profile");
		scopes.push("email");
		scopes.push("address");
		scopes.push("offline_access");
		server["scopes_supported"] = scopes;
	}

	protected addResponseTypes(server: JsonObject): void {
		const responseTypes: JsonArray = [];
		//response types are intentionally in unusual order
		responseTypes.push("code");
		responseTypes.push("id_token code");
		responseTypes.push("token code id_token");
		responseTypes.push("id_token");
		responseTypes.push("token id_token");
		responseTypes.push("token code");
		responseTypes.push("token");
		server["response_types_supported"] = responseTypes;
	}

	protected addResponseModes(server: JsonObject): void {
		const responseModes: JsonArray = [];
		responseModes.push("query");
		responseModes.push("fragment");
		responseModes.push("form_post");
		server["response_modes_supported"] = responseModes;
	}

	protected addTokenEndpointAuthMethodsSupported(server: JsonObject): void {
		const clientAuthTypes: JsonArray = [];
		clientAuthTypes.push("client_secret_basic");
		clientAuthTypes.push("client_secret_post");
		clientAuthTypes.push("client_secret_jwt");
		clientAuthTypes.push("private_key_jwt");
		server["token_endpoint_auth_methods_supported"] = clientAuthTypes;
	}

	protected addTokenEndpointAuthSigningAlgValuesSupported(server: JsonObject): void {
		const clientAuthTypes = server["token_endpoint_auth_methods_supported"];
		if (!isJsonArray(clientAuthTypes)) {
			// Gson getAsJsonArray()
			throw new Error("Not a JSON Array: " + JSON.stringify(clientAuthTypes));
		}
		const algValues: JsonArray = [];

		for (let i = 0; i < clientAuthTypes.length; i++) {
			const authType = OIDFJSON.getString(clientAuthTypes[i]);

			if (authType === "private_key_jwt") {
				for (const alg of JWS_FAMILY_SIGNATURE) {
					algValues.push(alg);
				}
			}

			if (authType === "client_secret_jwt") {
				for (const alg of JWS_FAMILY_HMAC_SHA) {
					algValues.push(alg);
				}
			}
		}

		server["token_endpoint_auth_signing_alg_values_supported"] = algValues;
	}

	//Python suite also always returns urn:ietf:params:oauth:grant-type:jwt-bearer and refresh_token
	//We add refresh_token in OIDCCGenerateServerConfigurationWithRefreshTokenGrantType only for refresh token tests
	protected addGrantTypes(server: JsonObject): void {
		const grantTypes: JsonArray = [];
		grantTypes.push("authorization_code");
		grantTypes.push("implicit");
		server["grant_types_supported"] = grantTypes;
	}

	protected addIdTokenSigningAlgValuesSupported(server: JsonObject): void {
		const algValues: JsonArray = [];
		algValues.push("none");
		for (const alg of JWS_FAMILY_SIGNATURE) {
			algValues.push(alg);
		}
		server["id_token_signing_alg_values_supported"] = algValues;
	}

	protected addIdTokenEncryptionAlgValuesSupported(server: JsonObject): void {
		const algValues: JsonArray = [];
		for (const alg of JWE_FAMILY_ASYMMETRIC) {
			algValues.push(alg);
		}
		for (const alg of JWE_FAMILY_SYMMETRIC) {
			algValues.push(alg);
		}
		server["id_token_encryption_alg_values_supported"] = algValues;
	}

	protected addIdTokenEncryptionEncValuesSupported(server: JsonObject): void {
		const encValues: JsonArray = [];
		for (const alg of ENC_FAMILY_AES_CBC_HMAC_SHA) {
			encValues.push(alg);
		}
		for (const alg of ENC_FAMILY_AES_GCM) {
			encValues.push(alg);
		}
		server["id_token_encryption_enc_values_supported"] = encValues;
	}

	protected addRequestObjectSigningAlgValuesSupported(server: JsonObject): void {
		const algValues: JsonArray = [];
		algValues.push("none");
		for (const alg of JWS_FAMILY_SIGNATURE) {
			algValues.push(alg);
		}
		server["request_object_signing_alg_values_supported"] = algValues;
	}

	protected addRequestObjectEncryptionAlgValuesSupported(server: JsonObject): void {
		const algValues: JsonArray = [];
		for (const alg of JWE_FAMILY_ASYMMETRIC) {
			algValues.push(alg);
		}
		for (const alg of JWE_FAMILY_SYMMETRIC) {
			algValues.push(alg);
		}
		server["request_object_encryption_alg_values_supported"] = algValues;
	}

	protected addRequestObjectEncryptionEncValuesSupported(server: JsonObject): void {
		const encValues: JsonArray = [];
		for (const alg of ENC_FAMILY_AES_CBC_HMAC_SHA) {
			encValues.push(alg);
		}
		for (const alg of ENC_FAMILY_AES_GCM) {
			encValues.push(alg);
		}
		server["request_object_encryption_enc_values_supported"] = encValues;
	}

	protected addClaimsParameterSupported(server: JsonObject): void {
		server["claims_parameter_supported"] = true;
	}

	protected addAcrValuesSupported(server: JsonObject): void {
		const subjectTypes: JsonArray = [];
		subjectTypes.push("PASSWORD");
		server["acr_values_supported"] = subjectTypes;
	}

	protected addSubjectTypesSupported(server: JsonObject): void {
		const subjectTypes: JsonArray = [];
		subjectTypes.push("public");
		subjectTypes.push("pairwise");
		server["subject_types_supported"] = subjectTypes;
	}

	protected addClaimTypesSupported(server: JsonObject): void {
		const claimTypes: JsonArray = [];
		claimTypes.push("normal");
		claimTypes.push("aggregated");
		claimTypes.push("distributed");
		server["claim_types_supported"] = claimTypes;
	}

	protected addClaimsSupported(server: JsonObject): void {
		const claims: JsonArray = [];
		for (const claimName of OIDCCLoadUserInfo.SUPPORTED_CLAIMS) {
			claims.push(claimName);
		}
		server["claims_supported"] = claims;
	}

	protected addUserinfoSigningAlgValuesSupported(server: JsonObject): void {
		const algValues: JsonArray = [];
		for (const alg of JWS_FAMILY_SIGNATURE) {
			algValues.push(alg);
		}
		server["userinfo_signing_alg_values_supported"] = algValues;
	}

	protected addUserinfoEncryptionAlgValuesSupported(server: JsonObject): void {
		const algValues: JsonArray = [];
		for (const alg of JWE_FAMILY_ASYMMETRIC) {
			algValues.push(alg);
		}
		for (const alg of JWE_FAMILY_SYMMETRIC) {
			algValues.push(alg);
		}
		server["userinfo_encryption_alg_values_supported"] = algValues;
	}

	protected addUserinfoEncryptionEncValuesSupported(server: JsonObject): void {
		const encValues: JsonArray = [];
		for (const alg of ENC_FAMILY_AES_CBC_HMAC_SHA) {
			encValues.push(alg);
		}
		for (const alg of ENC_FAMILY_AES_GCM) {
			encValues.push(alg);
		}
		server["userinfo_encryption_enc_values_supported"] = encValues;
	}

	/**
	 * Override in child classes to modify the generated server configuration
	 * This will be called at the end, after the configuration is prepared
	 * @param server
	 */
	protected addAdditionalConfiguration(_server: JsonObject, _baseUrl: string): void {}
}
