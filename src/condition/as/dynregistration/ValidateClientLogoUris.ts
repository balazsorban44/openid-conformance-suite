import {
	args,
	HttpClientException,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../../framework/index.ts";
import { AbstractClientValidationCondition } from "./AbstractClientValidationCondition.ts";

/**
 * Spring `HttpHeaders.getContentType()`: null when the header is absent or empty, otherwise the parsed media type
 * (type and subtype lowercased, rendered as `type/subtype;param=value` like `MediaType.toString()`).
 */
function getContentType(headers: Headers): { type: string; toString(): string } | null {
	const value = headers.get("content-type");
	if (value == null || value.length === 0) {
		return null;
	}
	const parts = value.split(";");
	const fullType = (parts[0] as string).trim().toLowerCase();
	const slash = fullType.indexOf("/");
	const type = slash === -1 ? fullType : fullType.substring(0, slash);
	const params = parts
		.slice(1)
		.map((p) => p.trim())
		.filter((p) => p.length > 0);
	const rendered = [fullType, ...params].join(";");
	return { type, toString: () => rendered };
}

/**
 * OPTIONAL. URL that references a logo for the Client application. If present, the server SHOULD display this
 * image to the End-User during approval. The value of this field MUST point to a valid image file.
 * If desired, representation of this Claim in different languages and scripts is represented as
 * described in Section 2.1.
 *
 * This class implements "The value of this field MUST point to a valid image file."
 */
export class ValidateClientLogoUris extends AbstractClientValidationCondition {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override async evaluate(env: Environment): Promise<Environment> {
		this.client = env.getObject("client") as JsonObject;
		const logoUris = this.getAllLogoUris();
		if (logoUris == null || logoUris.size === 0) {
			this.logSuccess("Client does not contain any logo_uri");
			return env;
		}
		//Note: I would use a map with uris as keys but it caused errors like the following so I just used strings
		//  org.springframework.data.mapping.MappingException: Map key
		//  https://www.example.com/a.png contains dots but no replacement was configured!
		//  Make sure map keys don't contain dots in the first place or configure an appropriate replacement!
		const uriContentTypesMap: string[] = [];
		const restTemplate = this.createRestTemplate(env, false);

		try {
			for (const lang of logoUris.keys()) {
				const uri = logoUris.get(lang) as string;
				//TODO are data urls also valid logo_uri values? I think they should be
				if (uri.startsWith("data:")) {
					//data:[<mediatype>][;base64],<data>
					//this is a data: url. https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Data_URIs
					if (uri.startsWith("data:image/")) {
						let mimeTypeEndPos = uri.indexOf(";", 11);
						if (mimeTypeEndPos === -1) {
							mimeTypeEndPos = uri.indexOf(",", 11);
						}
						if (mimeTypeEndPos === -1) {
							this.appendError("failure_reason", "Invalid data url format", "details", args("uri", uri));
						} else {
							//success, it's an image
							uriContentTypesMap.push(uri + " : " + uri.substring(5, mimeTypeEndPos));
						}
					}
				} else {
					try {
						const response = await restTemplate.exchange({ url: uri, method: "HEAD" });
						// RestTemplate.headForHeaders throws a RestClientException for 4xx/5xx responses
						if (response.status >= 400) {
							throw new HttpClientException(response.status + " " + response.statusText + ": [no body]");
						}
						const contentType = getContentType(response.headers);
						if (contentType == null) {
							this.appendError(
								"failure_reason",
								"Response does not contain a content-type header",
								"details",
								args("uri", uri),
							);
							continue;
						}

						if ("image" === contentType.type) {
							uriContentTypesMap.push(uri + " : " + contentType.toString());
						} else {
							this.appendError(
								"failure_reason",
								"Invalid content type, " + "content-type is not 'image'",
								"details",
								args("uri", uri, "content_type", contentType.toString()),
							);
						}
					} catch (ex) {
						if (!(ex instanceof HttpClientException)) {
							throw ex;
						}
						this.appendError("failure_reason", "Http error", "details", args("uri", uri, "exception", ex.message));
					}
				}
			}
		} finally {
			await restTemplate.close();
		}
		if (this.validationErrors.length !== 0) {
			throw this.error("logo_uri validation failed", args("errors", this.validationErrors));
		}
		this.logSuccess("Client contains valid logo_uri(s)", args("logo_uri_content_types", uriContentTypesMap));
		return env;
	}
}
