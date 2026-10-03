import { AbstractCondition, args, type Environment } from "../../framework/index.ts";

export abstract class AbstractCheckEndpointContentTypeReturned extends AbstractCondition {
	// this currently copes with the "old" way of using three seperate environment variables, one for each status / headers / body and the new preferred way of the object returned by AbstractCondition.convertResponseForEnvironment
	protected checkContentType(
		env: Environment,
		headersEnvKey: string,
		pathPrefix: string,
		expected: string,
	): Environment {
		const contentType = this.getContentType(env, headersEnvKey, pathPrefix);

		const mimeType = AbstractCheckEndpointContentTypeReturned.getMimeTypeFromContentType(contentType);

		if (expected === mimeType) {
			this.logSuccess(headersEnvKey + " Content-Type: header is " + expected);
			return env;
		}

		throw this.error(
			"Invalid content-type header in " + headersEnvKey,
			args("expected", expected, "actual", contentType),
		);
	}

	static getMimeTypeFromContentType(contentType: string): string | null {
		let mimeType: string | null = null;
		try {
			mimeType = contentType.split(";")[0].trim();
		} catch {
			// ignored
		}
		return mimeType;
	}

	protected getContentType(env: Environment, headersEnvKey: string, pathPrefix: string): string {
		const contentType = env.getString(headersEnvKey, pathPrefix + "content-type");
		if (!contentType) {
			throw this.error("Couldn't find content-type header in " + headersEnvKey);
		}
		return contentType;
	}
}
