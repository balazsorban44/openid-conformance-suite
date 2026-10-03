import type { TestExecutionUnit } from "./ConditionCallBuilder.ts";
import type { Environment } from "./Environment.ts";

/**
 * Port of testmodule/Command.java
 *
 * A builder class for test execution controls, such as mapping and unmapping keys in the environment,
 * starting and stopping blocks in the logs, and other controls not directly related to calling a condition.
 */
export class Command implements TestExecutionUnit {
	readonly unitKind = "command";
	private readonly envCommands: ((env: Environment) => void)[] = [];
	private _startBlock: string | null = null;
	private _endBlock = false;
	private readonly exposeStrings: string[] = [];

	/** Map a key in the environment. See Environment.mapKey(from, to) */
	mapKey(from: string, to: string): this {
		this.envCommands.push((env) => env.mapKey(from, to));
		return this;
	}

	/** Remove a mapping on the given key. See Environment.unmapKey(key) */
	unmapKey(key: string): this {
		this.envCommands.push((env) => env.unmapKey(key));
		return this;
	}

	/** Remove an object from the environment. See Environment.removeObject(key) */
	removeObject(key: string): this {
		this.envCommands.push((env) => env.removeObject(key));
		return this;
	}

	putInteger(key: string, value: number): this {
		this.envCommands.push((env) => env.putInteger(key, value));
		return this;
	}

	putString(key: string, value: string): this;
	putString(key: string, path: string, value: string): this;
	putString(key: string, pathOrValue: string, value?: string): this {
		if (value === undefined) {
			this.envCommands.push((env) => env.putString(key, pathOrValue));
		} else {
			this.envCommands.push((env) => env.putString(key, pathOrValue, value));
		}
		return this;
	}

	removeNativeValue(key: string): this {
		this.envCommands.push((env) => env.removeNativeValue(key));
		return this;
	}

	/** Start a new block in the event log, with the given message. */
	startBlock(msg: string): this {
		this._startBlock = msg;
		return this;
	}

	/** End the current block in the event log. */
	endBlock(): this {
		this._endBlock = true;
		return this;
	}

	/** Expose a string from the environment to the user (i.e. display it in the front end) */
	exposeEnvironmentString(key: string): this {
		this.exposeStrings.push(key);
		return this;
	}

	// getters

	getEnvCommands(): ((env: Environment) => void)[] {
		return this.envCommands;
	}

	getStartBlock(): string | null {
		return this._startBlock;
	}

	isEndBlock(): boolean {
		return this._endBlock;
	}

	getExposeStrings(): string[] {
		return this.exposeStrings;
	}
}
