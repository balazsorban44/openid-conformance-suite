import {
	AbstractCondition,
	args,
	isJsonObject,
	OIDFJSON,
	type ConditionError,
	type Environment,
	type EnvironmentRequirements,
	type JsonValue,
} from "../../framework/index.ts";

export class CheckDiscEndpointIssuer extends AbstractCondition {
	static override post: EnvironmentRequirements = { required: ["server", "config"] };

	override evaluate(env: Environment): Environment {
		const endpointLabel = this.getEndpointLabel();

		const issuerElement = this.getResponseIssuerElement(env);

		if (issuerElement == null || isJsonObject(issuerElement)) {
			throw this.error("issuer is missing from " + endpointLabel + " endpoint document");
		}

		const issuerUrl = OIDFJSON.getString(issuerElement);

		const discoveryUrl = this.getExpectedIssuerUrl(env);

		//Remove slash character endpoint url before comparing
		if (this.removeSlashEndpointURL(issuerUrl) !== this.removeSlashEndpointURL(discoveryUrl)) {
			throw this.createIssuerMismatchError(env, issuerUrl, discoveryUrl);
		}

		this.logSuccess("issuer is consistent with the " + endpointLabel + " endpoint", args("issuer", issuerUrl));

		return env;
	}

	protected getExpectedIssuerUrl(env: Environment): string {
		let discoveryUrl = this.getConfigurationUrl(env);

		const removingPartInUrl = this.getConfigurationEndpoint();
		if (discoveryUrl.endsWith(removingPartInUrl)) {
			discoveryUrl = discoveryUrl.substring(0, discoveryUrl.length - removingPartInUrl.length);
		}
		return discoveryUrl;
	}

	protected createIssuerMismatchError(_env: Environment, issuerUrl: string, discoveryUrl: string): ConditionError {
		return this.error(
			"issuer listed in the discovery document is not consistent with the location the discovery document was retrieved from. These must match to prevent impersonation attacks.",
			args("discovery_url", discoveryUrl, "issuer", issuerUrl),
		);
	}

	protected getEndpointLabel(): string {
		return "discovery";
	}

	protected getConfigurationUrl(env: Environment): string {
		return env.getString("config", "server.discoveryUrl") as string;
	}

	protected getResponseIssuerElement(env: Environment): JsonValue | undefined {
		return env.getElementFromObject("server", "issuer");
	}

	protected getConfigurationEndpoint(): string {
		return ".well-known/openid-configuration";
	}

	protected removeSlashEndpointURL(url: string): string {
		if (url.endsWith("/")) {
			return url.substring(0, url.length - 1);
		}

		return url;
	}
}
