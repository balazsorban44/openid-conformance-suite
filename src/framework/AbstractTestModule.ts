import {
	ConditionError,
	ConditionResult,
	isConditionResult,
	type Condition,
	type ConditionClass,
} from "./Condition.ts";
import { ConditionCallBuilder, type TestExecutionUnit } from "./ConditionCallBuilder.ts";
import { Command } from "./Command.ts";
import {
	ConditionSequenceCallBuilder,
	SkippedCondition,
	type ConditionSequence,
	type ConditionSequenceClass,
	type ConditionSequenceSupplier,
} from "./ConditionSequence.ts";
import { AbstractConditionSequence, splitOnFail } from "./AbstractConditionSequence.ts";
import { args, ex } from "./DataUtils.ts";
import { Environment } from "./Environment.ts";
import type { TestInstanceEventLog } from "./EventLog.ts";
import { TestExecutionManager, sleep } from "./execution.ts";
import { TestFailureException, TestInterruptedException, TestSkippedException } from "./exceptions.ts";
import type { ImageService } from "./ImageService.ts";
import { IterateEnvironmentArray } from "./IterateEnvironmentArray.ts";
import { isJsonArray, type JsonObject } from "./json.ts";
import type { BrowserControl } from "./BrowserControl.ts";
import { Result, Status, type HttpSession, type IncomingHttpRequest, type PublishTestModule } from "./TestModule.ts";
import type { TestLockManager } from "./TestLockManager.ts";
import { jsonResponse } from "./views.ts";
import {
	collectVariantMetadata,
	type ModuleVariantMetadata,
	type VariantEnum,
	type VariantEnumClass,
	type VariantMap,
} from "./variants.ts";

/**
 * A simple async mutex standing in for the Java ReentrantLock that protects a running test. Only one logical
 * flow (the test body or an incoming HTTP request handler) runs conditions at a time; HTTP I/O releases it.
 */
class AsyncMutex {
	private locked = false;
	private waiters: (() => void)[] = [];

	isLocked(): boolean {
		return this.locked;
	}

	async acquire(timeoutMs: number, onTimeout: () => Error): Promise<void> {
		if (!this.locked) {
			this.locked = true;
			return;
		}
		await new Promise<void>((resolve, reject) => {
			const timer = setTimeout(() => {
				this.waiters = this.waiters.filter((w) => w !== wake);
				reject(onTimeout());
			}, timeoutMs);
			const wake = () => {
				clearTimeout(timer);
				resolve();
			};
			this.waiters.push(wake);
		});
		this.locked = true;
	}

	release(): void {
		if (!this.locked) {
			return;
		}
		this.locked = false;
		const next = this.waiters.shift();
		if (next) {
			next();
		}
	}
}

export interface TestModuleHooks {
	onStatusChange?: (status: Status) => void;
	onResultChange?: (result: Result) => void;
}

/**
 * Port of testmodule/AbstractTestModule.java
 *
 * Differences from Java:
 *  - everything that calls conditions is async (await this.callAndStopOnFailure(...))
 *  - the ReentrantLock is an async mutex owned by this class; setStatus(RUNNING) acquires it, WAITING/FINISHED
 *    release it, and HTTP I/O inside conditions releases/reacquires it via the TestLockManager
 *  - @PublishTestModule becomes `static readonly meta`, variant annotations become `static variants`
 *  - handleHttp() returns a web `Response`
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
	private created = new Date();
	private statusUpdated = new Date();
	private finalError: TestInterruptedException | null = null;
	private cleanupCalled = false;
	private cleanupInProgress = false;
	protected imageService!: ImageService;
	private testLockManager!: TestLockManager;
	private hooks: TestModuleHooks = {};
	private readonly mutex = new AsyncMutex();
	private finishedPromise: Promise<void>;
	private resolveFinished!: () => void;

	constructor() {
		this.finishedPromise = new Promise<void>((resolve) => {
			this.resolveFinished = resolve;
		});
	}

	getEventLog(): TestInstanceEventLog {
		return this.eventLog;
	}

	/** automatically start all tests by default */
	autoStart(): boolean {
		return true;
	}

	setProperties(
		id: string,
		owner: Record<string, string> | null,
		eventLog: TestInstanceEventLog,
		browser: BrowserControl,
		executionManager: TestExecutionManager,
		imageService: ImageService,
		hooks: TestModuleHooks = {},
	): void {
		this.id = id;
		this.owner = owner;
		this.eventLog = eventLog;
		this.browser = browser;
		this.executionManager = executionManager;
		this.imageService = imageService;
		this.hooks = hooks;

		this.exposeOwnerIdToEnvironment();

		this.created = new Date();
		this.statusUpdated = this.created;

		let enabled = true;
		this.testLockManager = {
			releaseLock: async () => {
				if (enabled && this.status === Status.RUNNING) {
					await this.setStatusInternal(Status.WAITING);
				}
			},
			reacquireLock: async () => {
				if (enabled && this.status === Status.WAITING) {
					await this.setStatusInternal(Status.RUNNING);
				}
			},
			disable: () => {
				enabled = false;
			},
		};

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

	/** Like getVariant(), but returns defaultValue instead of throwing when no value is set for parameter. */
	getVariantOrDefault<T extends VariantEnum>(parameter: VariantEnumClass<T>, defaultValue: T): T {
		if (!this.variant.has(parameter)) {
			return defaultValue;
		}
		return this.getVariant(parameter);
	}

	getVariantMap(): VariantMap {
		return this.variant;
	}

	getOwner(): Record<string, string> | null {
		return this.owner;
	}

	protected exposeOwnerIdToEnvironment(): void {
		const currentOwner = this.getOwner();
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
		let onFail: ConditionResult;
		let requirements: string[];
		if (rest.length > 0 && isConditionResult(rest[0])) {
			onFail = rest[0];
			requirements = rest.slice(1) as string[];
		} else if (rest.length === 0) {
			onFail = ConditionResult.INFO;
			requirements = [];
		} else {
			onFail = ConditionResult.WARNING;
			requirements = rest as string[];
		}
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
	 * Call the condition as specified in the builder (see Java doc for the order of checks).
	 */
	protected async callCondition(builder: ConditionCallBuilder): Promise<void> {
		if (this.getStatus() !== Status.CREATED && !this.cleanupInProgress) {
			// We don't run this check for 'CREATED' as the lock is currently not held during 'configure'; cleanup()
			// runs inside the FINISHED/INTERRUPTED transition with the lock held (Java: isHeldByCurrentThread)
			if (this.getStatus() !== Status.RUNNING) {
				throw new TestFailureException(
					this.getId(),
					"Condition '" +
						builder.getConditionClass().name +
						"' called when test status is '" +
						this.getStatus() +
						"'. This is a bug in the test module and probably means that a call to " +
						"setStatus(Status.RUNNING) is missing.",
				);
			}
		}

		try {
			let condition = builder.getCondition();
			if (condition == null) {
				condition = new (builder.getConditionClass())();
			}
			condition.setProperties(this.id, this.eventLog, builder.getOnFail(), builder.getRequirements());
			condition.setLockManager(this.testLockManager);

			// check the environment to see if we need to skip this call
			for (const req of builder.getSkipIfObjectsMissing()) {
				if (!this.env.containsObject(req)) {
					this.eventLog.log(
						condition.getMessage(),
						args(
							"msg",
							"Skipped evaluation due to missing required object: " + req,
							"expected",
							req,
							"result",
							builder.getOnSkip(),
							"mapped",
							this.env.isKeyShadowed(req) ? this.env.getEffectiveKey(req) : null,
							"requirements",
							builder.getRequirements(),
						),
					);
					this.updateResultFromConditionFailure(builder.getOnSkip());
					return;
				}
			}
			for (const s of builder.getSkipIfStringsMissing()) {
				if (this.env.getString(s) == null) {
					this.eventLog.log(
						condition.getMessage(),
						args(
							"msg",
							"Skipped evaluation due to missing required string: " + s,
							"expected",
							s,
							"result",
							builder.getOnSkip(),
							"requirements",
							builder.getRequirements(),
						),
					);
					this.updateResultFromConditionFailure(builder.getOnSkip());
					return;
				}
			}
			for (const s of builder.getSkipIfStringsPresent()) {
				if (this.env.getString(s) != null) {
					this.eventLog.log(
						condition.getMessage(),
						args(
							"msg",
							"Skipped evaluation because string is present: " + s,
							"expected",
							s,
							"result",
							builder.getOnSkip(),
							"requirements",
							builder.getRequirements(),
						),
					);
					this.updateResultFromConditionFailure(builder.getOnSkip());
					return;
				}
			}
			for (const s of builder.getSkipIfLongsMissing()) {
				if (this.env.getLong(s) == null) {
					this.eventLog.log(
						condition.getMessage(),
						args(
							"msg",
							"Skipped evaluation due to missing required long integer: " + s,
							"expected",
							s,
							"result",
							builder.getOnSkip(),
							"requirements",
							builder.getRequirements(),
						),
					);
					this.updateResultFromConditionFailure(builder.getOnSkip());
					return;
				}
			}
			for (const [key, path] of builder.getSkipIfElementsMissing()) {
				const el = this.env.getElementFromObject(key, path);
				if (el == null) {
					this.eventLog.log(
						condition.getMessage(),
						args(
							"msg",
							"Skipped evaluation due to missing required element: " + key + " " + path,
							"object",
							key,
							"path",
							path,
							"mapped",
							this.env.isKeyShadowed(key) ? this.env.getEffectiveKey(key) : null,
							"result",
							builder.getOnSkip(),
							"requirements",
							builder.getRequirements(),
						),
					);
					this.updateResultFromConditionFailure(builder.getOnSkip());
					return;
				}
			}
			for (const [key, path] of builder.getSkipIfElementsPresent()) {
				const el = this.env.getElementFromObject(key, path);
				if (el != null) {
					this.eventLog.log(
						condition.getMessage(),
						args(
							"msg",
							"Skipped evaluation because element is present: " + key + " " + path,
							"object",
							key,
							"path",
							path,
							"mapped",
							this.env.isKeyShadowed(key) ? this.env.getEffectiveKey(key) : null,
							"result",
							builder.getOnSkip(),
							"requirements",
							builder.getRequirements(),
						),
					);
					this.updateResultFromConditionFailure(builder.getOnSkip());
					return;
				}
			}

			await condition.execute(this.env);
		} catch (error) {
			if (error instanceof ConditionError) {
				if (error.isPreOrPostError) {
					throw new TestFailureException(error);
				} else if (builder.isStopOnFailure()) {
					throw new TestFailureException(error);
				} else {
					this.updateResultFromConditionFailure(builder.getOnFail());
				}
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
		for (const e of builder.getExposeStrings()) {
			this.exposeEnvString(e);
		}
		const start = builder.getStartBlock();
		if (start) {
			this.eventLog.startBlock(start);
		}
		for (const cmd of builder.getEnvCommands()) {
			cmd(this.env);
		}
		if (builder.isEndBlock()) {
			this.eventLog.endBlock();
		}
	}

	protected async callIterate(builder: IterateEnvironmentArray): Promise<void> {
		const sourceElement = this.env.getElementFromObject(builder.getSourceObject(), builder.getSourcePath());
		if (sourceElement == null) {
			throw new TestFailureException(
				this.getId(),
				"Missing environment array for iteration at " + builder.getSourceObject() + "." + builder.getSourcePath(),
			);
		}
		if (!isJsonArray(sourceElement)) {
			throw new TestFailureException(
				this.getId(),
				"Expected environment array for iteration at " + builder.getSourceObject() + "." + builder.getSourcePath(),
			);
		}
		try {
			for (let i = 0; i < sourceElement.length; i++) {
				const element = sourceElement[i];
				builder.prepareIteration(this.env, element, i, sourceElement.length);
				const blockLabel = builder.getLogBlockLabel(element, i, sourceElement.length);
				if (blockLabel) {
					this.eventLog.startBlock(blockLabel);
				}
				try {
					await this.call(builder.getSequenceCallBuilder());
				} finally {
					if (blockLabel) {
						this.eventLog.endBlock();
					}
				}
			}
		} finally {
			builder.cleanupAfterIteration(this.env, sourceElement.length);
		}
	}

	/**
	 * Dispatch function to call a more specific subclass as needed.
	 */
	protected async call(
		builder: TestExecutionUnit | ConditionSequence | ConditionSequenceCallBuilder | null | undefined,
	): Promise<void> {
		if (builder == null) {
			return;
		}
		if (builder instanceof ConditionCallBuilder) {
			await this.callCondition(builder);
		} else if (builder instanceof Command) {
			await this.callCommand(builder);
		} else if (builder instanceof IterateEnvironmentArray) {
			await this.callIterate(builder);
		} else if (builder instanceof ConditionSequenceCallBuilder) {
			await this.callSequence(builder.create());
		} else if (builder instanceof SkippedCondition) {
			this.eventLog.log(builder.getSource(), args("msg", builder.getMessage()));
		} else if (isSequence(builder)) {
			await this.callSequence(builder);
		} else {
			throw new TestFailureException(this.getId(), "Unknown class passed to call() function");
		}
	}

	/** Create a caller for the given sequence */
	protected sequence(s: ConditionSequenceClass | ConditionSequenceSupplier): ConditionSequenceCallBuilder {
		return new ConditionSequenceCallBuilder(s);
	}

	protected sequenceOf(...units: TestExecutionUnit[]): ConditionSequence {
		return new (class extends AbstractConditionSequence {
			evaluate(): void {
				this.call(units);
			}
		})();
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
			this.eventLog.log(this.getName(), args("msg", "Final environment", "env", this.env.toJSON(), "final_env", true));
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

			this.eventLog.log(
				this.getName(),
				args("msg", "Test has run to completion", "result", Status.FINISHED, "testmodule_result", this.getResult()),
			);

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

	/**
	 * Records the FAILED result of a stop-on-failure condition whose exception the module catches, to answer the
	 * client with an error response and keep the test running. Returns the condition failure.
	 */
	protected recordConditionFailure(e: TestFailureException): ConditionError {
		const cause = e.cause;
		if (!(cause instanceof ConditionError) || cause.isPreOrPostError) {
			throw e;
		}
		this.updateResultFromConditionFailure(ConditionResult.FAILURE);
		return cause;
	}

	private updateResultFromConditionFailure(onFail: ConditionResult): void {
		switch (onFail) {
			case ConditionResult.FAILURE:
				this.setResult(Result.FAILED);
				break;
			case ConditionResult.WARNING:
				if (this.getResult() !== Result.FAILED && this.getResult() !== Result.REVIEW) {
					this.setResult(Result.WARNING);
				}
				break;
			default:
				break;
		}
	}

	protected async setStatus(newStatus: Status): Promise<void> {
		switch (newStatus) {
			case Status.CONFIGURED:
			case Status.WAITING:
			case Status.RUNNING:
				await this.setStatusInternal(newStatus);
				break;
			default:
				throw new TestFailureException(
					this.getId(),
					"Test module called setStatus() with a value other than CONFIGURED/WAITING/RUNNING. This is a bug in the test module; it should use a different method to change to the desired state - e.g. fireTestFinished() or throwing a TestFailureException.",
				);
		}
	}

	/**
	 * Atomically changes the test status from WAITING to RUNNING. Returns false when the status was not
	 * WAITING by the time the lock was acquired.
	 */
	protected async setStatusRunningIfWaiting(): Promise<boolean> {
		return this.setStatusInternal(Status.RUNNING, Status.WAITING);
	}

	/*
	 * Test status state machine:
	 *
	 *          /----------->--------------------------------\
	 *         /           /                                  \
	 *        /----------------->----------------\             \
	 *       /           /     /                  v             v
	 *   CREATED -> CONFIGURED -> RUNNING --> FINISHED      INTERRUPTED
	 *                         \     ^--v      ^              ^
	 *                          \-> WAITING --/--------------/
	 */
	private async setStatusInternal(newStatus: Status, expectedOldStatus: Status | null = null): Promise<boolean> {
		// RUNNING always takes the lock; FINISHED/INTERRUPTED take it unless the current flow already holds it
		// (status RUNNING means the holder is the flow that is now finishing/stopping itself)
		const needsLock =
			newStatus === Status.RUNNING ||
			((newStatus === Status.FINISHED || newStatus === Status.INTERRUPTED) &&
				!(this.mutex.isLocked() && this.status === Status.RUNNING));
		let acquired = false;
		if (needsLock) {
			{
				await this.mutex.acquire(this.getLockAcquireTimeoutSeconds() * 1000, () => {
					return new TestFailureException(
						this.getId(),
						"Timed out after " +
							this.getLockAcquireTimeoutSeconds() +
							" seconds waiting to acquire the test lock; another thread is holding it and is probably stuck. This may be a bug in the test suite. Aborting.",
					);
				});
				acquired = true;
			}
		}
		try {
			const oldStatus = this.getStatus();
			if (expectedOldStatus != null && oldStatus !== expectedOldStatus) {
				if (acquired) {
					this.mutex.release();
				}
				return false;
			}

			if (newStatus !== Status.RUNNING && newStatus === oldStatus) {
				throw new TestFailureException(
					this.getId(),
					"setStatus() called but status is the same: " + oldStatus + " -> " + newStatus,
				);
			}

			const illegal = () =>
				new TestFailureException(this.getId(), "Illegal test state change: " + oldStatus + " -> " + newStatus);
			const allowed = (...s: Status[]) => s.includes(newStatus);
			switch (oldStatus) {
				case Status.NOT_YET_CREATED:
					if (newStatus !== Status.CREATED) {
						throw illegal();
					}
					break;
				case Status.CREATED:
					if (!allowed(Status.CONFIGURED, Status.WAITING, Status.INTERRUPTED, Status.FINISHED)) {
						throw illegal();
					}
					break;
				case Status.CONFIGURED:
					if (!allowed(Status.RUNNING, Status.INTERRUPTED, Status.FINISHED, Status.WAITING)) {
						throw illegal();
					}
					break;
				case Status.RUNNING:
					if (!allowed(Status.INTERRUPTED, Status.FINISHED, Status.WAITING)) {
						throw illegal();
					}
					break;
				case Status.WAITING:
					if (!allowed(Status.RUNNING, Status.INTERRUPTED, Status.FINISHED)) {
						throw illegal();
					}
					break;
				default:
					throw illegal();
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

			this.status = newStatus;
			this.statusUpdated = new Date();
			this.hooks.onStatusChange?.(newStatus);

			if (newStatus === Status.FINISHED || newStatus === Status.INTERRUPTED) {
				this.resolveFinished();
			}

			if (newStatus === Status.RUNNING) {
				// exit with the lock still held, as we should always have the lock when TestConditions are being run
			} else {
				// release the lock as the very final step
				this.mutex.release();
			}
			return true;
		} catch (e) {
			// It's really best if we don't exit with the lock held
			this.mutex.release();
			throw e;
		}
	}

	/** Helper to check if we have the lock, and if we do, unlock it. */
	protected clearLockIfHeld(): void {
		this.mutex.release();
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

	getBrowser(): BrowserControl {
		return this.browser;
	}

	/** The test module name (Java: @PublishTestModule.testName) */
	getName(): string {
		return (this.constructor as typeof AbstractTestModule).meta.testName;
	}

	/** Resolves when the test reaches FINISHED or INTERRUPTED */
	whenFinished(): Promise<void> {
		return this.finishedPromise;
	}

	/**
	 * Called by the test runner to stop the test. This will add an entry to the log, if the test is not already
	 * FINISHED/INTERRUPTED.
	 */
	async stop(reason: string): Promise<void> {
		if (!(this.getStatus() === Status.FINISHED || this.getStatus() === Status.INTERRUPTED)) {
			await this.setStatusInternal(Status.INTERRUPTED);
			this.eventLog.log(
				this.getName(),
				args("msg", "Test was interrupted before it could complete. " + reason, "result", Status.INTERRUPTED),
			);
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
					this.eventLog.log(this.getName(), ex(e, args("msg", "A test failure was raised while cleaning up")));
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
			this.eventLog.log(
				this.getName(),
				args("result", Result.SKIPPED, "msg", "The test was skipped: " + error.message),
			);
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
				} else {
					this.setFinalError(error);
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

	getCreated(): Date {
		return this.created;
	}

	getStatusUpdated(): Date {
		return this.statusUpdated;
	}

	getFinalError(): TestInterruptedException | null {
		return this.finalError;
	}

	setFinalError(finalError: TestInterruptedException): void {
		this.finalError = finalError;
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

	/** Force the lock to be released, if held. Used in failure paths to cleanup. */
	forceReleaseLock(): void {
		this.mutex.release();
	}

	/** The merged variant metadata of this module's class hierarchy */
	static variantMetadata(this: Function): Required<ModuleVariantMetadata> {
		return collectVariantMetadata(this);
	}
}

function isSequence(u: unknown): u is ConditionSequence {
	return (
		typeof u === "object" &&
		u !== null &&
		typeof (u as ConditionSequence).evaluate === "function" &&
		typeof (u as ConditionSequence).getTestExecutionUnits === "function"
	);
}
