import { ConditionError, ConditionResult, type Condition, type EnvironmentRequirements } from "./Condition.ts";
import { args, ex, mapToJsonObject, type LogArgs } from "./DataUtils.ts";
import { Environment, UnexpectedTypeException } from "./Environment.ts";
import type { TestInstanceEventLog } from "./EventLog.ts";
import { HttpClient, type HttpResponse } from "./http.ts";
import {
	OIDFJSON,
	isJsonArray,
	isJsonObject,
	parseJson,
	JsonParseException,
	type JsonArray,
	type JsonObject,
	type JsonValue,
} from "./json.ts";
import { RandomStringUtils } from "./random.ts";
import type { TestLockManager } from "./TestLockManager.ts";

export const SUPPORT_EMAIL = "certification@oidf.org";

// URL for opening a NEW issue, e.g. when suggesting that a spec-defined field be added to the suite.
export const NEW_ISSUE_URL = "https://github.com/balazsorban44/openid-conformance-suite/issues/new";

const UNEXPECTED =
	"Something unexpected happened (this could be caused by something you did wrong, or it may be an issue in the test suite - please review the instructions and your configuration, if you still see a problem please contact " +
	SUPPORT_EMAIL +
	" with the full details)";

/**
 * Port of condition/AbstractCondition.java
 *
 * Subclasses implement evaluate(env) (sync or async) and declare their environment requirements as static
 * fields instead of the Java @PreEnvironment / @PostEnvironment annotations:
 *
 *   static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_response"] };
 *   static override post: EnvironmentRequirements = { strings: ["code"] };
 *
 * Logging and error helpers keep the Java signatures: log(msg), log(msg, map), logSuccess(...), error(...),
 * args("k", v, ...). `throw this.error(...)` where Java has `throw error(...)`.
 */
export abstract class AbstractCondition implements Condition {
	static pre?: EnvironmentRequirements;
	static post?: EnvironmentRequirements;

	private testId = "";
	private _log!: TestInstanceEventLog;
	private requirements = new Set<string>();
	private conditionResultOnFailure: ConditionResult = ConditionResult.FAILURE;
	private lockManager: TestLockManager | null = null;
	private logged = 0;
	private errorsLogged = 0;
	private loggedSoftLimitMsg = false;

	setProperties(
		testId: string,
		log: TestInstanceEventLog,
		conditionResultOnFailure: ConditionResult,
		requirements: string[],
	): void {
		this.testId = testId;
		this._log = log;
		this.conditionResultOnFailure = conditionResultOnFailure;
		this.requirements = new Set(requirements);
	}

	setLockManager(lockManager: TestLockManager | null): void {
		this.lockManager = lockManager;
	}

	protected getLockManager(): TestLockManager | null {
		return this.lockManager;
	}

	getMessage(): string {
		return this.constructor.name;
	}

	/** The event log this condition writes to (Java: private field `log`) */
	protected get eventLog(): TestInstanceEventLog {
		return this._log;
	}

	private requirementsOf(kind: "pre" | "post"): EnvironmentRequirements | undefined {
		return (this.constructor as typeof AbstractCondition)[kind];
	}

	async execute(env: Environment): Promise<void> {
		try {
			const pre = this.requirementsOf("pre");
			if (pre) {
				for (const req of pre.required ?? []) {
					if (!env.containsObject(req)) {
						this._log.log(
							this.getMessage(),
							args(
								"msg",
								UNEXPECTED + " - couldn't find required object in environment before evaluation: " + req,
								"expected",
								req,
								"result",
								ConditionResult.FAILURE,
								"mapped",
								env.isKeyShadowed(req) ? env.getEffectiveKey(req) : null,
								"requirements",
								this.getRequirements(),
							),
						);
						throw this.alreadyLoggedPrePostError(
							"[pre] " + UNEXPECTED + " - couldn't find object in environment: " + req,
						);
					}
				}
				for (const s of pre.strings ?? []) {
					if (env.getString(s) == null) {
						this._log.log(
							this.getMessage(),
							args(
								"msg",
								UNEXPECTED + " - couldn't find required string in environment before evaluation: " + s,
								"expected",
								s,
								"result",
								ConditionResult.FAILURE,
								"requirements",
								this.getRequirements(),
							),
						);
						throw this.alreadyLoggedPrePostError(
							"[pre] " + UNEXPECTED + " - couldn't find string in environment: " + s,
						);
					}
				}
				for (const i of pre.integers ?? []) {
					if (env.getInteger(i) == null) {
						this._log.log(
							this.getMessage(),
							args(
								"msg",
								UNEXPECTED + " - couldn't find required integer in environment before evaluation: " + i,
								"expected",
								i,
								"result",
								ConditionResult.FAILURE,
								"requirements",
								this.getRequirements(),
							),
						);
						throw this.alreadyLoggedPrePostError(
							"[pre] " + UNEXPECTED + " - couldn't find integer in environment: " + i,
						);
					}
				}
			}

			// evaluate the condition and assign its results back to our environment
			env = await this.evaluate(env);
			if (this.logged === 0) {
				this._log.log(this.getMessage(), args("msg", "Condition ran but did not log anything"));
			}
			if (this.errorsLogged > 0) {
				// the condition has logged a warning/failure so must throw an error, otherwise the test result will
				// not be updated
				throw new Error("Test condition needs to throw error() if it logs failures/warnings");
			}

			// check the environment to make sure the condition did what it claimed to
			const post = this.requirementsOf("post");
			if (post) {
				for (const req of post.required ?? []) {
					if (!env.containsObject(req)) {
						this._log.log(
							this.getMessage(),
							args(
								"msg",
								UNEXPECTED + " - couldn't find required object in environment after evaluation: " + req,
								"expected",
								req,
								"result",
								ConditionResult.FAILURE,
								"mapped",
								env.isKeyShadowed(req) ? env.getEffectiveKey(req) : null,
								"requirements",
								this.getRequirements(),
							),
						);
						throw this.alreadyLoggedPrePostError(
							"[post] " + UNEXPECTED + " - couldn't find object in environment: " + req,
						);
					}
				}
				for (const s of post.strings ?? []) {
					if (env.getString(s) == null) {
						this._log.log(
							this.getMessage(),
							args(
								"msg",
								UNEXPECTED + " - couldn't find required string in environment after evaluation: " + s,
								"expected",
								s,
								"result",
								ConditionResult.FAILURE,
								"requirements",
								this.getRequirements(),
							),
						);
						throw this.alreadyLoggedPrePostError(
							"[post] " + UNEXPECTED + " - couldn't find string in environment: " + s,
						);
					}
				}
				for (const i of post.integers ?? []) {
					if (env.getInteger(i) == null) {
						this._log.log(
							this.getMessage(),
							args(
								"msg",
								UNEXPECTED + " - couldn't find required integer in environment after evaluation: " + i,
								"expected",
								i,
								"result",
								ConditionResult.FAILURE,
								"requirements",
								this.getRequirements(),
							),
						);
						throw this.alreadyLoggedPrePostError(
							"[post] " + UNEXPECTED + " - couldn't find integer in environment: " + i,
						);
					}
				}
			}
		} catch (e) {
			if (e instanceof UnexpectedTypeException) {
				throw this.error(e.message, e);
			}
			throw e;
		}
	}

	/**
	 * Tests if the condition holds true. Reads from the given environment and returns a potentially modified
	 * environment. Throws ConditionError (via `throw this.error(...)`) when condition isn't met.
	 */
	abstract evaluate(env: Environment): Environment | Promise<Environment>;

	protected getTestId(): string {
		return this.testId;
	}

	/** Get a string from the environment, throwing a condition error if missing/not a string */
	protected getStringFromEnvironment(env: Environment, key: string, path: string, friendlyName: string): string {
		const value = env.getElementFromObject(key, path);
		if (value == null) {
			throw this.error(friendlyName + " is missing", args(key, env.getObject(key)));
		}
		if (typeof value !== "string") {
			throw this.error(friendlyName + " is not a string", args("value", value));
		}
		return value;
	}

	/** Get an object from the environment, throwing a condition error if missing/not an object */
	protected getJsonObjectFromEnvironment(
		env: Environment,
		key: string,
		path: string,
		friendlyName: string,
	): JsonObject {
		const value = env.getElementFromObject(key, path);
		if (value == null) {
			throw this.error(friendlyName + " is missing", args(key, env.getObject(key)));
		}
		if (!isJsonObject(value)) {
			throw this.error(friendlyName + " is not a JSON object", args("value", value));
		}
		return value;
	}

	protected getJsonArrayFromEnvironment(
		env: Environment,
		key: string,
		path: string,
		friendlyName: string,
		failIfEmpty = false,
	): JsonArray {
		const value = env.getElementFromObject(key, path);
		if (value == null) {
			throw this.error(friendlyName + " is missing", args(key, env.getObject(key)));
		}
		if (!isJsonArray(value)) {
			throw this.error(friendlyName + " is not a JSON array", args("value", value));
		}
		if (failIfEmpty && value.length === 0) {
			throw this.error(friendlyName + " is empty", args("value", value));
		}
		return value;
	}

	/*
	 * Logging utilities
	 */

	/**
	 * Do some common processing/checks on log messages
	 * @returns true if this message should not be logged
	 */
	private reachedLoggingLimits(result: string | null): boolean {
		const errorLimit = 50;
		const logSoftLimit = 1000; // we stop logging here
		const logHardLimit = 10000; // we abort execution here

		this.logged++;

		if (
			result != null &&
			result !== ConditionResult.SUCCESS &&
			result !== ConditionResult.INFO &&
			result !== ConditionResult.REVIEW
		) {
			this.errorsLogged++;
			if (this.errorsLogged > errorLimit) {
				const msg = "This condition has logged over " + errorLimit + " errors and has been aborted.";
				this._log.log(this.getMessage(), args("msg", msg, "result", this.conditionResultOnFailure));
				throw new ConditionError(this.testId, this.getMessage() + ": " + msg);
			}
			return false;
		}
		if (this.logged >= logSoftLimit) {
			if (!this.loggedSoftLimitMsg) {
				this._log.log(
					this.getMessage(),
					"This condition has logged over " + logSoftLimit + " log entries. Further entries will be suppressed.",
				);
				this.loggedSoftLimitMsg = true;
			}
			if (this.logged >= logHardLimit) {
				const msg = "This condition attempted to log over " + logHardLimit + " log entries and has been aborted.";
				this._log.log(this.getMessage(), args("msg", msg, "result", this.conditionResultOnFailure));
				throw new ConditionError(this.testId, this.getMessage() + ": " + msg);
			}
			return true;
		}
		return false;
	}

	private withRequirements(input: LogArgs): LogArgs {
		const out: LogArgs = { ...input };
		if (this.requirements.size > 0 && !("requirements" in out)) {
			out["requirements"] = [...this.requirements];
		}
		return out;
	}

	/**
	 * log(msg) / log(map) / log(msg, map)
	 */
	protected log(msgOrMap: string | LogArgs, map?: LogArgs): void {
		let out: LogArgs;
		if (typeof msgOrMap === "string") {
			out = this.withRequirements({ ...(map ?? {}), msg: msgOrMap });
		} else {
			out = this.withRequirements(msgOrMap);
		}
		const result = "result" in out && out["result"] != null ? String(out["result"]) : null;
		if (this.reachedLoggingLimits(result)) {
			return;
		}
		this._log.log(this.getMessage(), out);
	}

	/**
	 * logSuccess(msg) / logSuccess(map) / logSuccess(msg, map)
	 */
	protected logSuccess(msgOrMap: string | LogArgs, map?: LogArgs): void {
		if (typeof msgOrMap === "string") {
			this.log({ ...(map ?? {}), msg: msgOrMap, result: ConditionResult.SUCCESS });
		} else {
			this.log({ ...msgOrMap, result: ConditionResult.SUCCESS });
		}
	}

	/**
	 * Automatically log failures or warnings, depending on if this is an optional test.
	 *
	 * Note that this does NOT cause the test result to move to warning/failure - it is better for a test condition
	 * to throw error(). If there is a need to call logFailure directly (for example, making multiple checks in
	 * a single condition) then the condition author must ensure it throws an error at the end if any checks have
	 * failed.
	 */
	protected logFailure(msgOrMap: string | LogArgs, map?: LogArgs): void {
		if (typeof msgOrMap === "string") {
			this.log({ ...(map ?? {}), msg: msgOrMap, result: this.conditionResultOnFailure });
		} else {
			this.log({ ...msgOrMap, result: this.conditionResultOnFailure });
		}
	}

	/*
	 * Error utilities
	 */

	/** Return a ConditionError for failures in the Pre/Post Environment checks (already logged) */
	private alreadyLoggedPrePostError(message: string, cause?: unknown): ConditionError {
		return new ConditionError(this.testId, this.getMessage() + ": " + message, { cause, isPreOrPostError: true });
	}

	/**
	 * Log a failure then return a ConditionError. Java overloads supported:
	 *   error(message)
	 *   error(message, map)
	 *   error(message, cause)
	 *   error(message, cause, map)
	 *   error(cause)
	 *   error(cause, map)
	 */
	protected error(message: string): ConditionError;
	protected error(message: string, map: LogArgs): ConditionError;
	protected error(message: string, cause: unknown): ConditionError;
	protected error(message: string, cause: unknown, map: LogArgs): ConditionError;
	protected error(cause: Error): ConditionError;
	protected error(cause: Error, map: LogArgs): ConditionError;
	protected error(a: string | Error, b?: unknown, c?: LogArgs): ConditionError {
		if (typeof a === "string") {
			if (b === undefined) {
				this.logFailure(a);
				return new ConditionError(this.testId, this.getMessage() + ": " + a);
			}
			if (isPlainArgs(b) && c === undefined) {
				this.logFailure(a, b as LogArgs);
				return new ConditionError(this.testId, this.getMessage() + ": " + a);
			}
			// b is a cause
			this.logFailure(a, ex(b, c ?? {}));
			return new ConditionError(this.testId, this.getMessage() + ": " + a, { cause: b });
		}
		// a is a cause
		this.logFailure(a.message, ex(a, (b as LogArgs | undefined) ?? {}));
		return new ConditionError(this.testId, this.getMessage(), { cause: a });
	}

	/** Get the list of requirements that this test would fulfill if it passed */
	protected getRequirements(): Set<string> {
		return this.requirements;
	}

	protected createBrowserInteractionPlaceholder(msg?: string): string {
		const placeholder = RandomStringUtils.nextAlphanumeric(10);
		if (msg !== undefined) {
			this.log(msg, args("upload", placeholder, "result", ConditionResult.REVIEW));
		} else {
			this.log(args("upload", placeholder, "result", ConditionResult.REVIEW));
		}
		return placeholder;
	}

	/**
	 * Timeout in seconds applied to outbound HTTP requests made by conditions.
	 */
	protected getHttpClientTimeoutSeconds(): number {
		return 60;
	}

	/**
	 * Whether outbound requests use the configured mTLS client certificate.
	 * Negative tests that must connect without a client certificate override this method.
	 */
	protected useMtlsForHttpRequests(): boolean {
		return true;
	}

	/**
	 * Create an HTTP client for use in calling outbound to other services (Java: createRestTemplate(env)).
	 * All requests/responses made through it are logged; redirects are not followed; no status is an error.
	 */
	protected createHttpClient(env: Environment, restrictAllowedTLSVersions = true): HttpClient {
		return new HttpClient({
			source: this.getMessage(),
			log: this._log,
			lockManager: this.lockManager,
			mutualTls: this.useMtlsForHttpRequests() ? env.getObject("mutual_tls_authentication") : null,
			restrictAllowedTLSVersions,
			timeoutSeconds: this.getHttpClientTimeoutSeconds(),
		});
	}

	/** Alias to keep ported code close to the Java (createRestTemplate(env)) */
	protected createRestTemplate(env: Environment, restrictAllowedTLSVersions = true): HttpClient {
		return this.createHttpClient(env, restrictAllowedTLSVersions);
	}

	protected convertResponseForEnvironment(endpointName: string, response: HttpResponse): JsonObject {
		const responseInfo: JsonObject = {};
		responseInfo["status"] = response.status;
		responseInfo["endpoint_name"] = endpointName; // for use in further logging
		responseInfo["headers"] = mapToJsonObject(response.headers, true);
		responseInfo["body"] = response.body;
		return responseInfo;
	}

	protected convertJsonResponseForEnvironment(
		endpointName: string,
		response: HttpResponse,
		allowParseFailure = false,
	): JsonObject {
		const responseInfo = this.convertResponseForEnvironment(endpointName, response);
		const jsonString = response.body;
		if (jsonString == null || jsonString === "") {
			if (allowParseFailure) {
				return responseInfo;
			}
			throw this.error("Empty response from the " + endpointName + " endpoint");
		}
		let jsonRoot: JsonValue;
		try {
			jsonRoot = parseJson(jsonString);
		} catch (e) {
			if (e instanceof JsonParseException) {
				if (allowParseFailure) {
					return responseInfo;
				}
				throw this.error(
					"Response from " + endpointName + " endpoint does not appear to be JSON.",
					e,
					args("response", jsonString),
				);
			}
			throw e;
		}
		if (jsonRoot == null || !(isJsonObject(jsonRoot) || isJsonArray(jsonRoot))) {
			if (allowParseFailure) {
				return responseInfo;
			}
			throw this.error(endpointName + " endpoint did not return a JSON object.", args("response", jsonString));
		}
		responseInfo["body_json"] = jsonRoot;
		return responseInfo;
	}

	/** Shorthand used by ported code: OIDFJSON.getString(obj.get(key)) etc. */
	protected static readonly json = OIDFJSON;
}

function isPlainArgs(v: unknown): v is LogArgs {
	return typeof v === "object" && v !== null && !(v instanceof Error) && Object.getPrototypeOf(v) === Object.prototype;
}
