import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class ExtractImplicitHashToCallbackResponse extends AbstractCondition {
	static override pre: EnvironmentRequirements = { strings: ["implicit_hash"] };
	static override post: EnvironmentRequirements = { required: ["callback_params"] };

	override evaluate(env: Environment): Environment {
		const implicitHash = env.getString("implicit_hash");
		if (implicitHash) {
			const hash = implicitHash.substring(1); // strip off the leading # character

			const parameters = [...new URLSearchParams(hash).entries()];

			this.log(
				"Extracted response from URL fragment",
				args(
					"parameters",
					parameters.map(([name, value]) => ({ name, value })),
				),
			);

			const o: JsonObject = {};
			for (const [name, value] of parameters) {
				o[name] = value;
			}

			env.putObject("callback_params", o);

			this.logSuccess("Extracted the hash values", o);

			return env;
		}

		const o: JsonObject = {};
		env.putObject("callback_params", o);
		this.logSuccess("implicit_hash is empty", o);

		return env;
	}
}
