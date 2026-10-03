import { ConditionError, ConditionResult, type Condition, type EnvironmentRequirements } from "./Condition.ts";
import { ex, mapToJsonObject, type LogArgs } from "./DataUtils.ts";
import { Environment, UnexpectedTypeException } from "./Environment.ts";
import type { TestInstanceEventLog } from "./EventLog.ts";
import { HttpClient, type HttpInterceptor, type HttpResponse } from "./http.ts";
import {
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
 * The @PreEnvironment / @PostEnvironment checks, in the order Java runs them: each kind of requirement, how it
 * is satisfied, and the noun used in the log message.
 */
const ENVIRONMENT_CHECKS: {
	type: keyof EnvironmentRequirements;
	noun: string;
	isPresent: (env: Environment, key: string) => boolean;
}[] = [
	{ type: "required", noun: "object", isPresent: (env, key) => env.containsObject(key) },
	{ type: "strings", noun: "string", isPresent: (env, key) => env.getString(key) != null },
	{ type: "integers", noun: "integer", isPresent: (env, key) => env.getInteger(key) != null },
];

const ERROR_LIMIT = 50;
const LOG_SOFT_LIMIT = 1000; // we stop logging here
const LOG_HARD_LIMIT = 10000; // we abort execution here

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
	private eventLog!: TestInstanceEventLog;
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
		this.eventLog = log;
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

	async execute(env: Environment): Promise<void> {
		try {
			this.checkEnvironment("pre", env);

			// evaluate the condition and assign its results back to our environment
			env = await this.evaluate(env);
			if (this.logged === 0) {
				this.eventLog.log(this.getMessage(), { msg: "Condition ran but did not log anything" });
			}
			if (this.errorsLogged > 0) {
				// the condition has logged a warning/failure so must throw an error, otherwise the test result will
				// not be updated
				throw new Error("Test condition needs to throw error() if it logs failures/warnings");
			}

			// check the environment to make sure the condition did what it claimed to
			this.checkEnvironment("post", env);
		} catch (e) {
			if (e instanceof UnexpectedTypeException) {
				throw this.error(e.message, e);
			}
			throw e;
		}
	}

	/** The @PreEnvironment / @PostEnvironment checks: log and throw for the first missing value */
	private checkEnvironment(kind: "pre" | "post", env: Environment): void {
		const declared = (this.constructor as typeof AbstractCondition)[kind];
		if (!declared) {
			return;
		}
		const when = kind === "pre" ? "before" : "after";
		for (const { type, noun, isPresent } of ENVIRONMENT_CHECKS) {
			for (const key of declared[type] ?? []) {
				if (isPresent(env, key)) {
					continue;
				}
				const entry: LogArgs = {
					msg: `${UNEXPECTED} - couldn't find required ${noun} in environment ${when} evaluation: ${key}`,
					expected: key,
					result: ConditionResult.FAILURE,
				};
				if (type === "required") {
					entry["mapped"] = env.isKeyShadowed(key) ? env.getEffectiveKey(key) : null;
				}
				entry["requirements"] = this.getRequirements();
				this.eventLog.log(this.getMessage(), entry);
				throw this.alreadyLoggedPrePostError(`[${kind}] ${UNEXPECTED} - couldn't find ${noun} in environment: ${key}`);
			}
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
		const value = this.getElementFromEnvironment(env, key, path, friendlyName);
		if (typeof value !== "string") {
			throw this.error(friendlyName + " is not a string", { value });
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
		const value = this.getElementFromEnvironment(env, key, path, friendlyName);
		if (!isJsonObject(value)) {
			throw this.error(friendlyName + " is not a JSON object", { value });
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
		const value = this.getElementFromEnvironment(env, key, path, friendlyName);
		if (!isJsonArray(value)) {
			throw this.error(friendlyName + " is not a JSON array", { value });
		}
		if (failIfEmpty && value.length === 0) {
			throw this.error(friendlyName + " is empty", { value });
		}
		return value;
	}

	private getElementFromEnvironment(env: Environment, key: string, path: string, friendlyName: string): JsonValue {
		const value = env.getElementFromObject(key, path);
		if (value == null) {
			throw this.error(friendlyName + " is missing", { [key]: env.getObject(key) });
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
		this.logged++;

		if (
			result != null &&
			result !== ConditionResult.SUCCESS &&
			result !== ConditionResult.INFO &&
			result !== ConditionResult.REVIEW
		) {
			this.errorsLogged++;
			if (this.errorsLogged > ERROR_LIMIT) {
				this.abortForLoggingLimit("This condition has logged over " + ERROR_LIMIT + " errors and has been aborted.");
			}
			return false;
		}
		if (this.logged >= LOG_SOFT_LIMIT) {
			if (!this.loggedSoftLimitMsg) {
				this.eventLog.log(
					this.getMessage(),
					"This condition has logged over " + LOG_SOFT_LIMIT + " log entries. Further entries will be suppressed.",
				);
				this.loggedSoftLimitMsg = true;
			}
			if (this.logged >= LOG_HARD_LIMIT) {
				this.abortForLoggingLimit(
					"This condition attempted to log over " + LOG_HARD_LIMIT + " log entries and has been aborted.",
				);
			}
			return true;
		}
		return false;
	}

	private abortForLoggingLimit(msg: string): never {
		this.eventLog.log(this.getMessage(), { msg, result: this.conditionResultOnFailure });
		throw new ConditionError(this.testId, this.getMessage() + ": " + msg);
	}

	/**
	 * log(msg) / log(map) / log(msg, map)
	 */
	protected log(msgOrMap: string | LogArgs, map?: LogArgs): void {
		const out: LogArgs = toLogArgs(msgOrMap, map);
		if (this.requirements.size > 0 && !("requirements" in out)) {
			out["requirements"] = [...this.requirements];
		}
		if (this.reachedLoggingLimits(out["result"] == null ? null : String(out["result"]))) {
			return;
		}
		this.eventLog.log(this.getMessage(), out);
	}

	/**
	 * logSuccess(msg) / logSuccess(map) / logSuccess(msg, map)
	 */
	protected logSuccess(msgOrMap: string | LogArgs, map?: LogArgs): void {
		this.log({ ...toLogArgs(msgOrMap, map), result: ConditionResult.SUCCESS });
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
		this.log({ ...toLogArgs(msgOrMap, map), result: this.conditionResultOnFailure });
	}

	/*
	 * Error utilities
	 */

	/** Return a ConditionError for failures in the Pre/Post Environment checks (already logged) */
	private alreadyLoggedPrePostError(message: string): ConditionError {
		return new ConditionError(this.testId, this.getMessage() + ": " + message, { isPreOrPostError: true });
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
		if (typeof a !== "string") {
			// a is a cause
			this.logFailure(a.message, ex(a, (b as LogArgs | undefined) ?? {}));
			return new ConditionError(this.testId, this.getMessage(), { cause: a });
		}
		const message = this.getMessage() + ": " + a;
		if (b === undefined || (isPlainArgs(b) && c === undefined)) {
			this.logFailure(a, b);
			return new ConditionError(this.testId, message);
		}
		// b is a cause
		this.logFailure(a, ex(b, c ?? {}));
		return new ConditionError(this.testId, message, { cause: b });
	}

	/** Get the list of requirements that this test would fulfill if it passed */
	protected getRequirements(): Set<string> {
		return this.requirements;
	}

	protected createBrowserInteractionPlaceholder(msg?: string): string {
		const placeholder = RandomStringUtils.nextAlphanumeric(10);
		const entry = { upload: placeholder, result: ConditionResult.REVIEW };
		if (msg !== undefined) {
			this.log(msg, entry);
		} else {
			this.log(entry);
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
	 * `interceptor` wraps the network call (Java: an extra ClientHttpRequestInterceptor after the logging one).
	 */
	protected createHttpClient(
		env: Environment,
		restrictAllowedTLSVersions = true,
		interceptor?: HttpInterceptor,
	): HttpClient {
		return new HttpClient({
			source: this.getMessage(),
			log: this.eventLog,
			lockManager: this.lockManager,
			mutualTls: this.useMtlsForHttpRequests() ? env.getObject("mutual_tls_authentication") : null,
			restrictAllowedTLSVersions,
			timeoutSeconds: this.getHttpClientTimeoutSeconds(),
			interceptor,
		});
	}

	/**
	 * Same as createHttpClient but additionally installs the opt-in external endpoint cache
	 * (condition/client/CachingHttpInterceptor), consulted before issuing the real HTTP request.
	 */
	protected async createRestTemplateWithCache(env: Environment): Promise<HttpClient> {
		const { CachingHttpInterceptor } = await import("../condition/client/CachingHttpInterceptor.ts");
		const cache = new CachingHttpInterceptor(env);
		return this.createHttpClient(env, true, (req, exec) => cache.intercept(req, exec));
	}

	/** Alias to keep ported code close to the Java (createRestTemplate(env)) */
	protected createRestTemplate(env: Environment, restrictAllowedTLSVersions = true): HttpClient {
		return this.createHttpClient(env, restrictAllowedTLSVersions);
	}

	protected convertResponseForEnvironment(endpointName: string, response: HttpResponse): JsonObject {
		return {
			status: response.status,
			endpoint_name: endpointName, // for use in further logging
			headers: mapToJsonObject(response.headers, true),
			body: response.body,
		};
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
			if (!(e instanceof JsonParseException)) {
				throw e;
			}
			if (allowParseFailure) {
				return responseInfo;
			}
			throw this.error("Response from " + endpointName + " endpoint does not appear to be JSON.", e, {
				response: jsonString,
			});
		}
		if (!isJsonObject(jsonRoot) && !isJsonArray(jsonRoot)) {
			if (allowParseFailure) {
				return responseInfo;
			}
			throw this.error(endpointName + " endpoint did not return a JSON object.", { response: jsonString });
		}
		responseInfo["body_json"] = jsonRoot;
		return responseInfo;
	}
}

/** log(msg, map) / log(map) arguments as one map (msg after the map's own keys, as Java's put order) */
function toLogArgs(msgOrMap: string | LogArgs, map?: LogArgs): LogArgs {
	return typeof msgOrMap === "string" ? { ...map, msg: msgOrMap } : { ...msgOrMap };
}

function isPlainArgs(v: unknown): v is LogArgs {
	return typeof v === "object" && v !== null && !(v instanceof Error) && Object.getPrototypeOf(v) === Object.prototype;
}
