import { ConditionError, ConditionResult, type Condition, type ConditionClass } from "./Condition.ts";
import { ConditionCallBuilder, type Skip, type TestExecutionUnit } from "./ConditionCallBuilder.ts";
import { Command } from "./Command.ts";
import {
	ConditionSequenceCallBuilder,
	type ConditionSequence,
	type ConditionSequenceClass,
	type ConditionSequenceSupplier,
	type SkippedCondition,
} from "./ConditionSequence.ts";
import { implicitOnFail, sequenceOf, splitOnFail } from "./AbstractConditionSequence.ts";
import { ex, type LogArgs } from "./DataUtils.ts";
import { Environment } from "./Environment.ts";
import type { TestInstanceEventLog } from "./EventLog.ts";
import { TestExecutionManager, sleep } from "./execution.ts";
import { TestFailureException, TestInterruptedException, TestSkippedException } from "./exceptions.ts";
import type { ImageService } from "./ImageService.ts";
import type { JsonObject } from "./json.ts";
import type { BrowserControl } from "./BrowserControl.ts";
import { Result, Status, type HttpSession, type IncomingHttpRequest, type PublishTestModule } from "./TestModule.ts";
import type { TestLockManager } from "./TestLockManager.ts";
import { jsonResponse } from "./views.ts";
import type { ModuleVariantMetadata, VariantEnum, VariantEnumClass, VariantMap } from "./variants.ts";

/**
 * A simple async mutex standing in for the Java ReentrantLock that protects a running test. Only one logical
 * flow (the test body or an incoming HTTP request handler) runs conditions at a time; HTTP I/O releases it.
 */
class AsyncMutex {
	locked = false;
	private readonly waiters = new Set<() => void>();

	async acquire(timeoutMs: number, onTimeout: () => Error): Promise<void> {
		if (this.locked) {
			const { promise, resolve, reject } = Promise.withResolvers<void>();
			const wake = () => {
				clearTimeout(timer);
				resolve();
			};
			const timer = setTimeout(() => {
				this.waiters.delete(wake);
				reject(onTimeout());
			}, timeoutMs);
			this.waiters.add(wake);
			await promise;
		}
		this.locked = true;
	}

	release(): void {
		if (this.locked) {
			this.locked = false;
			const [next] = this.waiters;
			if (next) {
				this.waiters.delete(next);
				next();
			}
		}
	}
}

export interface TestModuleHooks {
	onStatusChange?: (status: Status) => void;
	onResultChange?: (result: Result) => void;
}

/** What the runner hands a module before configure() (Java: TestRunner calling setProperties) */
export interface TestModuleAttachment {
	id: string;
	owner: Record<string, string> | null;
	eventLog: TestInstanceEventLog;
	browser: BrowserControl;
	executionManager: TestExecutionManager;
	imageService: ImageService;
	hooks?: TestModuleHooks;
}

/**
 * Test status state machine:
 *
 *          /----------->--------------------------------\
 *         /           /                                  \
 *        /----------------->----------------\             \
 *       /           /     /                  v             v
 *   CREATED -> CONFIGURED -> RUNNING --> FINISHED      INTERRUPTED
 *                         \     ^--v      ^              ^
 *                          \-> WAITING --/--------------/
 *
 * Not in upstream: FINISHED -> RUNNING/WAITING is allowed with keepServingAfterFinish (see setStatusInternal).
 */
const TRANSITIONS: Record<Status, readonly Status[]> = {
	NOT_YET_CREATED: [Status.CREATED],
	CREATED: [Status.CONFIGURED, Status.WAITING, Status.INTERRUPTED, Status.FINISHED],
	CONFIGURED: [Status.RUNNING, Status.INTERRUPTED, Status.FINISHED, Status.WAITING],
	RUNNING: [Status.INTERRUPTED, Status.FINISHED, Status.WAITING],
	WAITING: [Status.RUNNING, Status.INTERRUPTED, Status.FINISHED],
	FINISHED: [],
	INTERRUPTED: [],
};

const mapped = (env: Environment, key: string) => (env.isKeyShadowed(key) ? env.getEffectiveKey(key) : null);

/**
 * The skip checks of a condition call, in the order they are evaluated (every skip of the first kind, then of the
 * second kind, ...). Each returns the log entry (keys in upstream order) when the call has to be skipped, else null.
 */
const SKIP_CHECKS: {
	[K in Skip["kind"]]: (
		env: Environment,
		skip: Extract<Skip, { kind: K }>,
		result: ConditionResult,
		requirements: string[],
	) => LogArgs | null;
} = {
	objectMissing: (env, { key }, result, requirements) =>
		env.containsObject(key)
			? null
			: {
					msg: "Skipped evaluation due to missing required object: " + key,
					expected: key,
					result,
					mapped: mapped(env, key),
					requirements,
				},
	stringMissing: (env, { key }, result, requirements) =>
		env.getString(key) != null
			? null
			: { msg: "Skipped evaluation due to missing required string: " + key, expected: key, result, requirements },
	stringPresent: (env, { key }, result, requirements) =>
		env.getString(key) == null
			? null
			: { msg: "Skipped evaluation because string is present: " + key, expected: key, result, requirements },
	longMissing: (env, { key }, result, requirements) =>
		env.getLong(key) != null
			? null
			: {
					msg: "Skipped evaluation due to missing required long integer: " + key,
					expected: key,
					result,
					requirements,
				},
	elementMissing: (env, { key, path }, result, requirements) =>
		env.getElementFromObject(key, path) != null
			? null
			: {
					msg: "Skipped evaluation due to missing required element: " + key + " " + path,
					object: key,
					path,
					mapped: mapped(env, key),
					result,
					requirements,
				},
	elementPresent: (env, { key, path }, result, requirements) =>
		env.getElementFromObject(key, path) == null
			? null
			: {
					msg: "Skipped evaluation because element is present: " + key + " " + path,
					object: key,
					path,
					mapped: mapped(env, key),
					result,
					requirements,
				},
};
const SKIP_KINDS = Object.keys(SKIP_CHECKS) as Skip["kind"][];

/**
 * Port of testmodule/AbstractTestModule.java
 *
 * Differences from Java:
 *  - everything that calls conditions is async (await this.callAndStopOnFailure(...))
 *  - the ReentrantLock is an async mutex owned by this class; setStatus(RUNNING) acquires it, WAITING/FINISHED
 *    release it, and HTTP I/O inside conditions releases/reacquires it via the TestLockManager
 *  - @PublishTestModule becomes `static readonly meta`, variant annotations become `static variants`
 *  - handleHttp() returns a web `Response`
 *  - setProperties(...) is attach({...}); whenStatus()/whenFinished() let the runner wait for a status
 */
export abstract class AbstractTestModule {
	static readonly meta: PublishTestModule;
	static variants?: ModuleVariantMetadata;

	static readonly LOG_FINAL_ENV = process.env["CONFORMANCE_LOG_FINAL_ENV"] !== "false";

	private id = ""; // unique identifier for the test, set from the outside
	private status: Status = Status.NOT_YET_CREATED;
	private result: Result = Result.UNKNOWN;
	private variant: VariantMap = new Map();
	private owner: Record<string, string> | null = null;
	protected eventLog!: TestInstanceEventLog;
	protected browser!: BrowserControl;
	protected executionManager!: TestExecutionManager;
	protected exposed: Record<string, string | null> = {}; // exposes runtime values to outside modules
	protected env = new Environment(); // keeps track of values at runtime
	private cleanupCalled = false;
	private cleanupInProgress = false;
	protected imageService!: ImageService;
	private hooks: TestModuleHooks = {};
	private readonly mutex = new AsyncMutex();
	private readonly finished = Promise.withResolvers<void>();
	private statusWaiters: { statuses: Status[]; resolve: (status: Status) => void }[] = [];
	/**
	 * Not in upstream. When set, incoming HTTP requests are still handled after the module has finished (status
	 * FINISHED -> RUNNING is allowed). The runner sets it on the RP test module that acts as the emulated OP in
	 * suite-vs-suite runs, where OP test modules call e.g. the userinfo endpoint more than once.
	 */
	private keepServingAfterFinish = false;
	private lockManagerEnabled = true;
	/** Handed to conditions: releases the lock around HTTP I/O (RUNNING -> WAITING -> RUNNING) */
	private readonly testLockManager: TestLockManager = {
		releaseLock: async () => {
			if (this.lockManagerEnabled && this.status === Status.RUNNING) {
				await this.setStatusInternal(Status.WAITING);
			}
		},
		reacquireLock: async () => {
			if (this.lockManagerEnabled && this.status === Status.WAITING) {
				await this.setStatusInternal(Status.RUNNING);
			}
		},
		disable: () => {
			this.lockManagerEnabled = false;
		},
	};

	getEventLog(): TestInstanceEventLog {
		return this.eventLog;
	}

	/** automatically start all tests by default */
	autoStart(): boolean {
		return true;
	}

	/** Java: setProperties(id, owner, eventLog, browser, info, executionManager, imageService) */
	attach(a: TestModuleAttachment): void {
		this.id = a.id;
		this.owner = a.owner;
		this.eventLog = a.eventLog;
		this.browser = a.browser;
		this.executionManager = a.executionManager;
		this.imageService = a.imageService;
		this.hooks = a.hooks ?? {};

		this.exposeOwnerIdToEnvironment();

		void this.setStatusInternal(Status.CREATED);
	}

	setVariant(variant: VariantMap): void {
		this.variant = variant;
	}

	getVariant<T extends VariantEnum>(parameter: VariantEnumClass<T>): T {
		const value = this.variant.get(parameter);
		if (value == null) {
			throw new Error("Invalid variant parameter: " + parameter.name);
		}
		if (!(value instanceof (parameter as unknown as new (...a: unknown[]) => T))) {
			throw new Error(`BUG: invalid value for variant ${parameter.name}: ${value}`);
		}
		return value as T;
	}

	protected exposeOwnerIdToEnvironment(): void {
		const currentOwner = this.owner;
		if (currentOwner != null) {
			const sub = currentOwner["sub"];
			const iss = currentOwner["iss"];
			if (sub != null && iss != null) {
				this.env.putString("owner_id", sub + " " + iss);
				this.env.putString("owner_sub", sub);
				this.env.putString("owner_iss", iss);
			}
		}
	}

	/**
	 * Create and evaluate a Condition in the current environment. Throw a TestFailureException if the Condition fails.
	 *   callAndStopOnFailure(condition, ...requirements)
	 *   callAndStopOnFailure(condition, ConditionResult.FAILURE, ...requirements)
	 */
	protected async callAndStopOnFailure(
		condition: Condition | ConditionClass,
		...rest: (string | ConditionResult)[]
	): Promise<void> {
		const { onFail, requirements } = splitOnFail(rest, ConditionResult.FAILURE);
		if (onFail !== ConditionResult.FAILURE) {
			throw new TestFailureException(
				this.getId(),
				"callAndStopOnFailure called with onFail != ConditionResult.FAILURE",
			);
		}
		await this.call(this.condition(condition).requirements(requirements).onFail(onFail));
	}

	private logException(e: unknown): void {
		const event = ex(e);
		event["msg"] = "Caught exception from test framework: " + (e instanceof Error ? e.message : String(e));
		this.eventLog.log(this.getName(), event);
	}

	/**
	 * Create and evaluate a Condition in the current environment. Log but ignore if the Condition fails.
	 *   callAndContinueOnFailure(condition, onFail, ...requirements)
	 */
	protected async callAndContinueOnFailure(
		condition: Condition | ConditionClass,
		onFail: ConditionResult,
		...requirements: string[]
	): Promise<void> {
		await this.call(this.condition(condition).requirements(requirements).onFail(onFail).dontStopOnFailure());
	}

	/**
	 * Create and evaluate a Condition in the current environment, but only if the environment contains the given
	 * objects and strings (both can be null).
	 *   skipIfMissing(required, strings, onSkip, condition)                         -> onFail INFO
	 *   skipIfMissing(required, strings, onSkip, condition, ...requirements)        -> onFail WARNING
	 *   skipIfMissing(required, strings, onSkip, condition, onFail, ...requirements)
	 */
	protected async skipIfMissing(
		required: string[] | null,
		strings: string[] | null,
		onSkip: ConditionResult,
		condition: Condition | ConditionClass,
		...rest: (string | ConditionResult)[]
	): Promise<void> {
		const { onFail, requirements } = splitOnFail(rest, implicitOnFail(rest));
		await this.call(
			this.condition(condition)
				.skipIfObjectsMissing(required)
				.skipIfStringsMissing(strings)
				.onSkip(onSkip)
				.requirements(requirements)
				.onFail(onFail)
				.dontStopOnFailure(),
		);
	}

	/**
	 * Create and evaluate a Condition in the current environment, but only if the environment contains the given element.
	 */
	protected async skipIfElementMissing(
		objId: string,
		path: string,
		onSkip: ConditionResult,
		condition: Condition | ConditionClass,
		onFail: ConditionResult,
		...requirements: string[]
	): Promise<void> {
		await this.call(
			this.condition(condition)
				.skipIfElementMissing(objId, path)
				.onSkip(onSkip)
				.requirements(requirements)
				.onFail(onFail)
				.dontStopOnFailure(),
		);
	}

	/**
	 * Call the condition as specified in the builder: create it, check the skips, evaluate it, and map a failure
	 * to the test result (or a TestFailureException when the call stops on failure).
	 */
	protected async callCondition(builder: ConditionCallBuilder): Promise<void> {
		// We don't run this check for 'CREATED' as the lock is currently not held during 'configure'; cleanup()
		// runs inside the FINISHED/INTERRUPTED transition with the lock held (Java: isHeldByCurrentThread)
		if (this.status !== Status.CREATED && !this.cleanupInProgress && this.status !== Status.RUNNING) {
			throw new TestFailureException(
				this.getId(),
				"Condition '" +
					builder.conditionClass.name +
					"' called when test status is '" +
					this.getStatus() +
					"'. This is a bug in the test module and probably means that a call to " +
					"setStatus(Status.RUNNING) is missing.",
			);
		}

		const { spec } = builder;
		try {
			const condition = builder.condition ?? new builder.conditionClass();
			condition.setProperties(this.id, this.eventLog, spec.onFail, spec.requirements);
			condition.setLockManager(this.testLockManager);

			// check the environment to see if we need to skip this call
			for (const kind of SKIP_KINDS) {
				const check = SKIP_CHECKS[kind] as (
					env: Environment,
					skip: Skip,
					result: ConditionResult,
					requirements: string[],
				) => LogArgs | null;
				for (const skip of spec.skips) {
					const skipped = skip.kind === kind ? check(this.env, skip, spec.onSkip, spec.requirements) : null;
					if (skipped) {
						this.eventLog.log(condition.getMessage(), skipped);
						this.updateResultFromConditionFailure(spec.onSkip);
						return;
					}
				}
			}

			await condition.execute(this.env);
		} catch (error) {
			if (error instanceof ConditionError) {
				if (error.isPreOrPostError || spec.stopOnFailure) {
					throw new TestFailureException(error);
				}
				this.updateResultFromConditionFailure(spec.onFail);
			} else if (error instanceof TestFailureException) {
				throw error;
			} else {
				// log errors (e.g. stack overflows) into the test results so they're easily visible
				this.logException(error);
				throw new TestFailureException(this.getId(), error);
			}
		}
	}

	/** Create a new condition call builder, which can be passed to call() */
	protected condition(condition: Condition | ConditionClass): ConditionCallBuilder {
		return new ConditionCallBuilder(condition);
	}

	/** Create a new test execution builder, which can be passed to call() */
	protected exec(): Command {
		return new Command();
	}

	/**
	 * Execute a set of test execution commands: expose strings, start block, env commands, end block.
	 */
	protected async callCommand(builder: Command): Promise<void> {
		const { exposeStrings, startBlock, envCommands, endBlock } = builder.spec;
		for (const e of exposeStrings) {
			this.exposeEnvString(e);
		}
		if (startBlock) {
			this.eventLog.startBlock(startBlock);
		}
		for (const cmd of envCommands) {
			cmd(this.env);
		}
		if (endBlock) {
			this.eventLog.endBlock();
		}
	}

	/**
	 * Dispatch function to call a more specific subclass as needed.
	 */
	protected async call(
		unit: TestExecutionUnit | ConditionSequence | ConditionSequenceCallBuilder | null | undefined,
	): Promise<void> {
		if (unit == null) {
			return;
		}
		switch (unit.unitKind) {
			case "condition":
				await this.callCondition(unit as ConditionCallBuilder);
				break;
			case "command":
				await this.callCommand(unit as Command);
				break;
			case "sequence-call":
				await this.callSequence((unit as ConditionSequenceCallBuilder).create());
				break;
			case "sequence":
				await this.callSequence(unit as ConditionSequence);
				break;
			case "skipped":
				this.eventLog.log((unit as SkippedCondition).source, { msg: (unit as SkippedCondition).message });
				break;
			default:
				throw new TestFailureException(this.getId(), "Unknown class passed to call() function");
		}
	}

	/** Create a caller for the given sequence */
	protected sequence(s: ConditionSequenceClass | ConditionSequenceSupplier): ConditionSequenceCallBuilder {
		return new ConditionSequenceCallBuilder(s);
	}

	protected sequenceOf(...units: TestExecutionUnit[]): ConditionSequence {
		return sequenceOf(...units);
	}

	/**
	 * Map generic client authentication keys to endpoint-specific keys.
	 */
	protected mapClientAuthKeys(formParamsKey: string, headersKey: string): void {
		if (this.env.getObject(headersKey) == null) {
			this.env.putObject(headersKey, {});
		}
		if (this.env.getObject(formParamsKey) == null) {
			this.env.putObject(formParamsKey, {});
		}
		this.env.mapKey("request_form_parameters", formParamsKey);
		this.env.mapKey("request_headers", headersKey);
	}

	protected unmapClientAuthKeys(): void {
		this.env.unmapKey("request_form_parameters");
		this.env.unmapKey("request_headers");
	}

	protected async callSequence(sequence: ConditionSequence | null): Promise<void> {
		if (sequence == null) {
			return;
		}
		// execute the sequence
		sequence.evaluate();
		// pass all of the resulting units to the call functions
		for (const unit of sequence.getTestExecutionUnits()) {
			await this.call(unit);
		}
	}

	getId(): string {
		return this.id;
	}

	getStatus(): Status {
		return this.status;
	}

	protected logFinalEnv(): void {
		if (AbstractTestModule.LOG_FINAL_ENV) {
			this.eventLog.log(this.getName(), { msg: "Final environment", env: this.env.toJSON(), final_env: true });
		}
	}

	fireSetupDone(): void {
		this.eventLog.log(this.getName(), "Setup Done");
	}

	/**
	 * Mark the test as finished, setting it to PASSED or REVIEW if appropriate.
	 * This should always be called with the test status set to 'RUNNING'.
	 */
	async fireTestFinished(): Promise<void> {
		// first we set our test to WAITING to release the lock and prepare for finalization
		await this.setStatusInternal(Status.WAITING);
		this.fireTestFinishedInternal();
	}

	// internal version of above used to skip the 'setStatus(WAITING)' when called from non-test jobs
	private fireTestFinishedInternal(): void {
		// this happens in the background so that we can check the state of the browser controller
		this.getTestExecutionManager().runFinalisationTaskInBackground(async () => {
			// wait for web runners to wrap up first
			const timeout = Date.now() + 60_000; // wait at most 60 seconds
			while (this.browser.runnersActive() && Date.now() < timeout) {
				await sleep(100);
			}

			this.getTestExecutionManager().cancelAllBackgroundTasksExceptFinalisation();

			const resultSoFar = this.getResult();
			if (resultSoFar === Result.UNKNOWN || resultSoFar === Result.WARNING) {
				if (this.imageService.getFilledPlaceholders(this.getId(), true).length > 0) {
					this.fireTestReviewNeeded();
				} else if (resultSoFar === Result.UNKNOWN) {
					this.fireTestSuccess();
				}
			}

			// clean up any remaining placeholders here
			for (const placeholder of this.imageService.getRemainingPlaceholders(this.getId(), true)) {
				this.imageService.fillPlaceholder(this.getId(), placeholder, { image_no_longer_required: true }, true);
			}

			this.eventLog.log(this.getName(), {
				msg: "Test has run to completion",
				result: Status.FINISHED,
				testmodule_result: this.getResult(),
			});

			// if we weren't interrupted already, then we're finished
			if (this.getStatus() !== Status.INTERRUPTED) {
				this.logFinalEnv();
				await this.setStatusInternal(Status.FINISHED);
			}

			await this.stop("Test has run to completion.");
			return "done";
		});
	}

	fireTestReviewNeeded(): void {
		if (this.result !== Result.FAILED) {
			this.setResult(Result.REVIEW);
		}
	}

	private fireTestSuccess(): void {
		this.setResult(Result.PASSED);
	}

	private fireTestFailure(): void {
		this.setResult(Result.FAILED);
	}

	/**
	 * Mark the test as skipped (untestable). This method throws a TestSkippedException to skip any further
	 * conditions from running. The test status must be RUNNING when this is called.
	 */
	fireTestSkipped(msg: string): never {
		if (this.getResult() !== Result.FAILED) {
			this.setResult(Result.SKIPPED);
		}
		throw new TestSkippedException(this.getId(), msg);
	}

	getResult(): Result {
		return this.result;
	}

	private setResult(result: Result): void {
		this.result = result;
		this.hooks.onResultChange?.(result);
	}

	private updateResultFromConditionFailure(onFail: ConditionResult): void {
		if (onFail === ConditionResult.FAILURE) {
			this.setResult(Result.FAILED);
		} else if (
			onFail === ConditionResult.WARNING &&
			this.getResult() !== Result.FAILED &&
			this.getResult() !== Result.REVIEW
		) {
			this.setResult(Result.WARNING);
		}
	}

	protected async setStatus(newStatus: Status): Promise<void> {
		if (newStatus !== Status.CONFIGURED && newStatus !== Status.WAITING && newStatus !== Status.RUNNING) {
			throw new TestFailureException(
				this.getId(),
				"Test module called setStatus() with a value other than CONFIGURED/WAITING/RUNNING. This is a bug in the test module; it should use a different method to change to the desired state - e.g. fireTestFinished() or throwing a TestFailureException.",
			);
		}
		await this.setStatusInternal(newStatus);
	}

	/** Changes the status along the state machine (see TRANSITIONS), taking and releasing the lock */
	private async setStatusInternal(newStatus: Status): Promise<void> {
		// RUNNING always takes the lock; FINISHED/INTERRUPTED take it unless the current flow already holds it
		// (status RUNNING means the holder is the flow that is now finishing/stopping itself)
		const needsLock =
			newStatus === Status.RUNNING ||
			((newStatus === Status.FINISHED || newStatus === Status.INTERRUPTED) &&
				!(this.mutex.locked && this.status === Status.RUNNING));
		if (needsLock) {
			const timeoutSeconds = this.getLockAcquireTimeoutSeconds();
			await this.mutex.acquire(
				timeoutSeconds * 1000,
				() =>
					new TestFailureException(
						this.getId(),
						"Timed out after " +
							timeoutSeconds +
							" seconds waiting to acquire the test lock; another thread is holding it and is probably stuck. This may be a bug in the test suite. Aborting.",
					),
			);
		}
		try {
			const oldStatus = this.getStatus();

			if (newStatus !== Status.RUNNING && newStatus === oldStatus) {
				throw new TestFailureException(
					this.getId(),
					"setStatus() called but status is the same: " + oldStatus + " -> " + newStatus,
				);
			}

			const allowed =
				TRANSITIONS[oldStatus].includes(newStatus) ||
				// not in upstream: an emulated OP (suite-vs-suite) keeps answering requests after its own flow finished
				(oldStatus === Status.FINISHED &&
					this.keepServingAfterFinish &&
					(newStatus === Status.RUNNING || newStatus === Status.WAITING));
			if (!allowed) {
				throw new TestFailureException(this.getId(), "Illegal test state change: " + oldStatus + " -> " + newStatus);
			}

			if (newStatus === Status.FINISHED || newStatus === Status.INTERRUPTED) {
				// Disable the lock manager before cleanup
				this.testLockManager.disable();
				// make the cleanup steps complete before we move the test to 'FINISHED' or 'INTERRUPTED'
				await this.performFinalCleanup();
			}

			if (
				newStatus === Status.INTERRUPTED &&
				(this.getResult() === Result.WARNING || this.getResult() === Result.REVIEW)
			) {
				// WARNING and REVIEW only become a verdict once the test runs to completion
				this.setResult(Result.UNKNOWN);
			}

			if (newStatus === Status.FINISHED && this.getResult() === Result.UNKNOWN) {
				throw new TestFailureException(
					this.getId(),
					"Illegal test state; tried to move from " + oldStatus + " -> " + newStatus + " but 'result' is UNKNOWN",
				);
			}

			this.updateStatus(newStatus);

			if (newStatus !== Status.RUNNING) {
				// release the lock as the very final step (RUNNING exits with the lock held, as we should always have
				// the lock when TestConditions are being run)
				this.mutex.release();
			}
		} catch (e) {
			// It's really best if we don't exit with the lock held
			this.mutex.release();
			throw e;
		}
	}

	/** The one place the status changes: notifies the hooks, whenStatus() and whenFinished() */
	private updateStatus(newStatus: Status): void {
		this.status = newStatus;
		this.hooks.onStatusChange?.(newStatus);
		const waiting = this.statusWaiters;
		this.statusWaiters = waiting.filter((w) => !w.statuses.includes(newStatus));
		for (const w of waiting) {
			if (w.statuses.includes(newStatus)) {
				w.resolve(newStatus);
			}
		}
		if (newStatus === Status.FINISHED || newStatus === Status.INTERRUPTED) {
			this.finished.resolve();
		}
	}

	/** Resolves with the status once the test is in one of the given statuses (immediately if it already is) */
	whenStatus(...statuses: Status[]): Promise<Status> {
		if (statuses.includes(this.status)) {
			return Promise.resolve(this.status);
		}
		const { promise, resolve } = Promise.withResolvers<Status>();
		this.statusWaiters.push({ statuses, resolve });
		return promise;
	}

	/** Resolves when the test reaches FINISHED or INTERRUPTED */
	whenFinished(): Promise<void> {
		return this.finished.promise;
	}

	/** Add a key/value pair to the exposed values that the user will see in the frontend */
	protected expose(key: string, val: string | null): void {
		this.exposed[key] = val;
	}

	protected unexpose(key: string): void {
		delete this.exposed[key];
	}

	/**
	 * Expose a value from the environment so the user sees it in the frontend.
	 */
	protected exposeEnvString(key: string, sourceKey: string | null = null, sourcePath: string | null = null): void {
		let val: string | null;
		if (sourceKey == null) {
			val = this.env.getString(key);
		} else if (sourcePath == null) {
			val = this.env.getString(sourceKey);
		} else {
			val = this.env.getString(sourceKey, sourcePath);
		}
		this.expose(key, val);
	}

	getExposedValues(): Record<string, string | null> {
		return this.exposed;
	}

	/** The test module name (Java: @PublishTestModule.testName) */
	getName(): string {
		return (this.constructor as typeof AbstractTestModule).meta.testName;
	}

	/**
	 * Called by the test runner to stop the test. This will add an entry to the log, if the test is not already
	 * FINISHED/INTERRUPTED.
	 */
	async stop(reason: string): Promise<void> {
		if (!(this.getStatus() === Status.FINISHED || this.getStatus() === Status.INTERRUPTED)) {
			await this.setStatusInternal(Status.INTERRUPTED);
			this.eventLog.log(this.getName(), {
				msg: "Test was interrupted before it could complete. " + reason,
				result: Status.INTERRUPTED,
			});
			this.logFinalEnv();
		}
		this.getTestExecutionManager().cancelAllBackgroundTasks();
	}

	protected async performFinalCleanup(): Promise<void> {
		if (!this.cleanupCalled) {
			this.cleanupInProgress = true;
			try {
				await this.cleanup();
			} catch (e) {
				if (e instanceof TestFailureException) {
					this.eventLog.log(this.getName(), ex(e, { msg: "A test failure was raised while cleaning up" }));
				} else {
					throw e;
				}
			} finally {
				this.cleanupCalled = true;
				this.cleanupInProgress = false;
			}
		}
	}

	/** Handle a fatal exception */
	async handleException(error: TestInterruptedException, source: string): Promise<void> {
		if (error instanceof TestSkippedException) {
			this.eventLog.log(this.getName(), { result: Result.SKIPPED, msg: "The test was skipped: " + error.message });
			await this.fireTestFinished();
		} else {
			/* must be a TestFailureException */
			let failure: string;
			if (error.cause instanceof ConditionError) {
				// ConditionError will already have been logged when created in AbstractCondition
				failure = error.cause.message;
			} else {
				failure = error.message;
				const event: Record<string, unknown> = { caught_at: source };
				if (error.cause == null) {
					// a message a TestModule has explicitly thrown
					event["msg"] = failure;
				}
				this.eventLog.log(this.getName(), ex(error, event));
			}
			// Any exception except 'skipped' from a test counts as a failure
			this.fireTestFailure();
			await this.stop("The failure '" + failure + "' means the test cannot continue.");
		}
	}

	/**
	 * Called after the test has been stopped (for any reason) to allow cleanup of resources, such as dynamic
	 * client registrations.
	 */
	async cleanup(): Promise<void> {
		// Nothing to do in general
	}

	protected getLockAcquireTimeoutSeconds(): number {
		return 90;
	}

	/**
	 * Method is called to pass configuration parameters
	 */
	abstract configure(
		config: JsonObject,
		baseUrl: string,
		externalUrlOverride: string,
		baseMtlsUrl: string,
	): Promise<void>;

	/** Called by the TestRunner to start the test */
	abstract start(): Promise<void>;

	/**
	 * Called when an external party calls a URL under the test's base URL.
	 * @param path the path relative to the test's base URL (e.g. "callback")
	 * @param requestParts elements from the request parsed out into a json object for use in condition classes
	 */
	async handleHttp(
		path: string,
		_req: IncomingHttpRequest,
		_res: unknown,
		_session: HttpSession,
		requestParts: JsonObject,
	): Promise<Response> {
		return this.unexpectedHttpRequest(path, requestParts);
	}

	async handleHttpMtls(
		path: string,
		_req: IncomingHttpRequest,
		_res: unknown,
		_session: HttpSession,
		requestParts: JsonObject,
	): Promise<Response> {
		return this.unexpectedHttpRequest(path, requestParts);
	}

	async handleWellKnown(
		path: string,
		_req: IncomingHttpRequest,
		_res: unknown,
		_session: HttpSession,
		requestParts: JsonObject,
	): Promise<Response> {
		if (path.startsWith("/.well-known/oauth-authorization-server")) {
			return jsonResponse({ error: "this test doesn't support the path '" + path + "'" }, 404);
		}
		return this.unexpectedHttpRequest(path, requestParts);
	}

	/**
	 * Called when an HTTP request arrives for a path neither the test module nor any of its parent classes serve.
	 */
	protected async unexpectedHttpRequest(path: string, requestParts: JsonObject | null): Promise<Response> {
		await this.setStatus(Status.RUNNING);
		const response = await this.reportUnexpectedHttpRequest(path, requestParts);
		await this.setStatus(Status.WAITING);
		return response;
	}

	protected async reportUnexpectedHttpRequest(path: string, requestParts: JsonObject | null): Promise<Response> {
		const unexpected: JsonObject = { path };
		if (requestParts != null && "method" in requestParts) {
			unexpected["method"] = requestParts["method"];
		}
		// dynamic import to avoid a module cycle (the condition extends AbstractCondition via the framework barrel)
		const { UnexpectedHttpRequestReceived } = await import("../condition/common/UnexpectedHttpRequestReceived.ts");
		this.env.putObject(UnexpectedHttpRequestReceived.ENV_KEY, unexpected);
		await this.callAndContinueOnFailure(UnexpectedHttpRequestReceived, ConditionResult.FAILURE);
		this.env.removeObject(UnexpectedHttpRequestReceived.ENV_KEY);
		return jsonResponse({ error: "The test does not serve the path '" + path + "'" }, 404);
	}

	getTestExecutionManager(): TestExecutionManager {
		return this.executionManager;
	}

	protected waitForPlaceholders(): void {
		// set up a listener to wait for either an error callback or an image upload
		this.executionManager.runInBackground(async () => {
			let delayMillis = 1000;
			await sleep(delayMillis, this.executionManager.signal);
			while (true) {
				const remainingPlaceholders = this.imageService.getRemainingPlaceholders(this.getId(), true);
				if (this.getStatus() === Status.FINISHED || this.getStatus() === Status.INTERRUPTED) {
					break;
				}
				if (remainingPlaceholders.length === 0 && this.getStatus() === Status.WAITING) {
					this.fireTestFinishedInternal();
					break;
				}
				if (delayMillis < 30 * 1000) {
					delayMillis *= 2;
				}
				await sleep(delayMillis, this.executionManager.signal);
			}
			return "done";
		}, "placeholder watcher");
	}

	/** Not in upstream: see keepServingAfterFinish */
	setKeepServingAfterFinish(keep: boolean): void {
		this.keepServingAfterFinish = keep;
	}

	/** Force the lock to be released, if held. Used in failure paths to cleanup. */
	forceReleaseLock(): void {
		this.mutex.release();
	}
}
