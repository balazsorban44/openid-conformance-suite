import {
	args,
	HttpClientException,
	JsonParseException,
	OIDFJSON,
	parseJson,
	type Environment,
	type EnvironmentRequirements,
	type JsonArray,
	type JsonObject,
} from "../../../framework/index.ts";
import {
	AbstractClientValidationCondition,
	getAsJsonArray,
	IllegalStateException,
} from "./AbstractClientValidationCondition.ts";

/**
 * sector_identifier_uri
 * OPTIONAL. URL using the https scheme to be used in calculating Pseudonymous Identifiers by the OP.
 * The URL references a file with a single JSON array of redirect_uri values. Please see Section 5.
 * Providers that use pairwise sub (subject) values SHOULD utilize the sector_identifier_uri value
 * provided in the Subject Identifier calculation for pairwise identifiers.
 *
 * This class should only be used for registration requests:
 * https://openid.net/specs/openid-connect-registration-1_0.html#SectorIdentifierValidation
 * The values registered in redirect_uris MUST be included in the elements of the array,
 * or registration MUST fail. This MUST be validated at registration time;
 * there is no requirement for the OP to retain the contents of this JSON file or
 * to retrieve or revalidate its contents in the future.
 */
export class ValidateClientRegistrationRequestSectorIdentifierUri extends AbstractClientValidationCondition {
	static override pre: EnvironmentRequirements = { required: ["dynamic_registration_request"] };

	override async evaluate(env: Environment): Promise<Environment> {
		this.client = env.getObject("dynamic_registration_request") as JsonObject;

		const sectorIdentifierUri = this.getSectorIdentifierUri();
		if (sectorIdentifierUri == null) {
			this.logSuccess("A sector_identifier_uri was not provided");
			return env;
		}
		if (!sectorIdentifierUri.toLowerCase().startsWith("https://")) {
			throw this.error("sector_identifier_uri MUST be a URL using the https scheme", args("uri", sectorIdentifierUri));
		}
		let responseBody: string | null = "";
		const restTemplate = this.createRestTemplate(env, false);
		try {
			// UPSTREAM: RestTemplate follows redirects for GET, the TS HttpClient does not
			const response = await restTemplate.exchange({ url: sectorIdentifierUri, method: "GET" });
			// RestTemplate.getForObject throws a RestClientException for 4xx/5xx responses
			if (response.status >= 400) {
				throw new HttpClientException(
					response.status +
						" " +
						response.statusText +
						": " +
						(response.body ? '"' + response.body + '"' : "[no body]"),
				);
			}
			responseBody = response.body;
			if (responseBody == null || responseBody.length === 0) {
				throw this.error(
					"Invalid sector_identifier_uri. When fetching sector_identifier_uri " + "the server returned an empty body",
					args("uri", sectorIdentifierUri),
				);
			}
			const jsonArray = getAsJsonArray(parseJson(responseBody));
			let redirectUris: JsonArray | null = null;
			try {
				redirectUris = this.getRedirectUris();
				if (redirectUris == null) {
					throw this.error("redirect_uris is empty");
				}
			} catch (ex) {
				if (!(ex instanceof IllegalStateException)) {
					throw ex;
				}
				throw this.error("redirect_uris is not encoded as a json array");
			}

			const urisFromSectorIdentifierUri = new Set<string>();
			const urisFromRedirectUris = new Set<string>();
			for (const element of jsonArray) {
				urisFromSectorIdentifierUri.add(OIDFJSON.getString(element));
			}
			for (const element of redirectUris) {
				urisFromRedirectUris.add(OIDFJSON.getString(element));
			}
			//The values registered in redirect_uris MUST be included in the elements of the array,
			//or registration MUST fail. This MUST be validated at registration time;
			//there is no requirement for the OP to retain the contents of this JSON file or
			//to retrieve or revalidate its contents in the future.
			for (const redirUri of urisFromRedirectUris) {
				if (!urisFromSectorIdentifierUri.has(redirUri)) {
					throw this.error(
						"A redirect_uri provided in registration request is not found in " + "sector_identifier_uri response",
						args("redirect_uri", redirUri, "sector_identifier_uri_response", jsonArray),
					);
				}
			}
			this.logSuccess(
				"sector_identifier_uri response validated successfully. " +
					"All uris in redirect_uris are included in sector_identifier_uri response",
			);
			return env;
		} catch (ex) {
			if (ex instanceof HttpClientException) {
				throw this.error(
					"Failed to retrieve sector_identifier_uri",
					ex,
					args("uri", sectorIdentifierUri, "error", ex.message),
				);
			}
			if (ex instanceof IllegalStateException) {
				throw this.error(
					"sector_identifier_uri response does not contain a json array",
					ex,
					args("uri", sectorIdentifierUri, "response", responseBody),
				);
			}
			if (ex instanceof JsonParseException) {
				throw this.error(
					"sector_identifier_uri response does not contain a valid json",
					ex,
					args("uri", sectorIdentifierUri, "response", responseBody),
				);
			}
			throw ex;
		} finally {
			await restTemplate.close();
		}
	}
}
