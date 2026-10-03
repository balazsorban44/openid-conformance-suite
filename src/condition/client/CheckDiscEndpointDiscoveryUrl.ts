import {
	AbstractCondition,
	args,
	isJsonPrimitive,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
} from "../../framework/index.ts";

export class CheckDiscEndpointDiscoveryUrl extends AbstractCondition {
	private readonly requiredProtocol = "https";

	private readonly environmentBaseObject = "config";
	private readonly environmentVariable = "server.discoveryUrl";

	private readonly errorMessageNotJsonPrimitive = "Specified value is not a Json primitive";
	private readonly errorMessageInvalidURL = "Invalid URL. Unable to parse.";
	private readonly errorMessageNotRequiredProtocol =
		"Expected " + this.requiredProtocol + " protocol for " + this.environmentVariable;

	protected getConfigurationEndpoint(): string {
		return "/.well-known/openid-configuration";
	}

	static override pre: EnvironmentRequirements = { required: ["config"] };

	override evaluate(env: Environment): Environment {
		const configUrl = env.getElementFromObject(this.environmentBaseObject, this.environmentVariable);
		if (configUrl == null) {
			throw this.error("Unable to find Discovery URL", args("No discoveryUrl", env.getObject("config")));
		}

		if (!isJsonPrimitive(configUrl)) {
			throw this.error(this.errorMessageNotJsonPrimitive, args("Failure", configUrl));
		} else {
			const discoveryUrl = OIDFJSON.getString(configUrl);

			// Java: URI.create(discoveryUrl).toURL() throws IllegalArgumentException / MalformedURLException
			let extractedUrl: URL;
			try {
				extractedUrl = new URL(discoveryUrl);
			} catch {
				throw this.error(this.errorMessageInvalidURL, args("Failure", configUrl));
			}
			if (!this.isValidDiscoveryUrl(extractedUrl)) {
				throw this.error(
					"discoveryUrl is missing '" + this.getConfigurationEndpoint() + "'",
					args("actual", discoveryUrl),
				);
			}

			// Java's URL.getProtocol() has no trailing colon
			const protocol = extractedUrl.protocol.replace(/:$/, "");
			if (protocol !== this.requiredProtocol) {
				throw this.error(
					this.errorMessageNotRequiredProtocol,
					args("actual", protocol, "expected", this.requiredProtocol),
				);
			}

			this.logSuccess("discoveryUrl", args("actual", configUrl));
		}
		return env;
	}

	protected isValidDiscoveryUrl(url: URL): boolean {
		return url.pathname.endsWith(this.getConfigurationEndpoint());
	}
}
