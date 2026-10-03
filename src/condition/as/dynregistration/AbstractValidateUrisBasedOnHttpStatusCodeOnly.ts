import {
	args,
	HttpClientException,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../../framework/index.ts";
import { AbstractClientValidationCondition } from "./AbstractClientValidationCondition.ts";

export abstract class AbstractValidateUrisBasedOnHttpStatusCodeOnly extends AbstractClientValidationCondition {
	protected abstract getUrisToTest(): Map<string, string> | null;
	protected abstract getMetadataName(): string;

	static override pre: EnvironmentRequirements = { required: ["client"] };

	override async evaluate(env: Environment): Promise<Environment> {
		this.client = env.getObject("client") as JsonObject;
		const clientUris = this.getUrisToTest();
		if (clientUris == null || clientUris.size === 0) {
			this.logSuccess("Client does not contain any " + this.getMetadataName());
			return env;
		}
		const clientUriStatusCodes: string[] = [];
		const restTemplate = this.createRestTemplate(env, false);
		try {
			for (const lang of clientUris.keys()) {
				const uri = clientUris.get(lang) as string;
				try {
					//Please note: restTemplate will follow redirects
					// UPSTREAM: the TS HttpClient does not follow redirects, a 3xx response is reported as is
					const response = await restTemplate.exchange({ url: uri, method: "HEAD" });
					//rest template will throw an exception in case of 40x
					if (response.status >= 400) {
						throw new HttpClientException(response.status + " " + response.statusText + ": [no body]");
					}
					clientUriStatusCodes.push(uri + " : " + response.status + " " + response.statusText);
				} catch (ex) {
					if (!(ex instanceof HttpClientException)) {
						throw ex;
					}
					this.appendError(
						"failure_reason",
						"Error checking " + this.getMetadataName(),
						"details",
						args("uri", uri, "error_message", ex.message),
					);
				}
			}
		} finally {
			await restTemplate.close();
		}

		if (this.validationErrors.length !== 0) {
			throw this.error(
				this.getMetadataName() + " validation failed",
				args("errors", this.validationErrors, "uri_status_codes", clientUriStatusCodes),
			);
		}
		this.logSuccess(
			"Client contains valid " + this.getMetadataName() + " value(s)",
			args("uri_status_codes", clientUriStatusCodes),
		);
		return env;
	}
}
