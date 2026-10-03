import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export abstract class AbstractCheckServerConfiguration extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		const lookFor = this.getExpectedListEndpoint();

		for (const key of lookFor) {
			this.ensureString(env, key);
			this.ensureUrl(env, key);
		}

		this.logSuccess("Found required server configuration keys", args("required", lookFor));
		return env;
	}

	protected ensureString(env: Environment, path: string): void {
		const string = env.getString("server", path);
		if (!string) {
			throw this.error("Couldn't find required component", args("required", path));
		}
	}

	protected ensureUrl(env: Environment, path: string): void {
		const string = env.getString("server", path);
		try {
			// UPSTREAM: URI.create(..).toURL() additionally requires a URL scheme with a registered handler
			// (http, https, ftp, file, jar); new URL() accepts any absolute URL
			new URL(string as string);
		} catch (e) {
			throw this.error("Couldn't parse key as URL", e, args("key", path, "url", string));
		}
	}

	protected abstract getExpectedListEndpoint(): string[];
}
