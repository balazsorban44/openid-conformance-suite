import type { TestExecutionUnit } from "./ConditionCallBuilder.ts";
import type { Environment } from "./Environment.ts";

/**
 * Port of testmodule/Command.java
 *
 * A builder class for test execution controls, such as mapping and unmapping keys in the environment,
 * starting and stopping blocks in the logs, and other controls not directly related to calling a condition.
 * The collected controls are in `spec`.
 */
export class Command implements TestExecutionUnit {
	readonly unitKind = "command";
	readonly spec: {
		envCommands: ((env: Environment) => unknown)[];
		startBlock: string | null;
		endBlock: boolean;
		exposeStrings: string[];
	} = { envCommands: [], startBlock: null, endBlock: false, exposeStrings: [] };

	/** Map a key in the environment. See Environment.mapKey(from, to) */
	mapKey(from: string, to: string): this {
		return this.env((env) => env.mapKey(from, to));
	}

	/** Remove a mapping on the given key. See Environment.unmapKey(key) */
	unmapKey(key: string): this {
		return this.env((env) => env.unmapKey(key));
	}

	/** Remove an object from the environment. See Environment.removeObject(key) */
	removeObject(key: string): this {
		return this.env((env) => env.removeObject(key));
	}

	putInteger(key: string, value: number): this {
		return this.env((env) => env.putInteger(key, value));
	}

	putString(key: string, value: string): this;
	putString(key: string, path: string, value: string): this;
	putString(key: string, pathOrValue: string, value?: string): this {
		return this.env((env) =>
			value === undefined ? env.putString(key, pathOrValue) : env.putString(key, pathOrValue, value),
		);
	}

	removeNativeValue(key: string): this {
		return this.env((env) => env.removeNativeValue(key));
	}

	/** Start a new block in the event log, with the given message. */
	startBlock(msg: string): this {
		this.spec.startBlock = msg;
		return this;
	}

	/** End the current block in the event log. */
	endBlock(): this {
		this.spec.endBlock = true;
		return this;
	}

	/** Expose a string from the environment to the user (i.e. display it in the front end) */
	exposeEnvironmentString(key: string): this {
		this.spec.exposeStrings.push(key);
		return this;
	}

	private env(command: (env: Environment) => unknown): this {
		this.spec.envCommands.push(command);
		return this;
	}
}
