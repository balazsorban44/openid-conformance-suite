import { setTimeout as delay } from "node:timers/promises";
import { ConditionError } from "./Condition.ts";
import { TestFailureException, TestInterruptedException } from "./exceptions.ts";

export type BackgroundTask = () => Promise<unknown> | unknown;

/**
 * Port of runner/TestExecutionManager.java (+ its BackgroundTask wrapper).
 *
 * Background "threads" are promises. Cancellation is cooperative: tasks get an AbortSignal through
 * `signal` and `sleep()` rejects when cancelled. A cancelled task's error is swallowed (like a cancelled Future);
 * the finalisation task is never cancelled.
 */
export class TestExecutionManager {
	private readonly testId: string;
	private readonly tasks = new Set<Promise<unknown>>();
	private readonly controller = new AbortController();
	private finalisationStarted = false;
	private finalisation: Promise<unknown> | null = null;
	private readonly onError: (error: TestInterruptedException, source: string) => Promise<void>;
	private readonly afterTask: () => void;

	constructor(
		testId: string,
		hooks: {
			/** Called with any TestInterruptedException thrown by a task (Java: TestRunner -> test.handleException) */
			onError: (error: TestInterruptedException, source: string) => Promise<void>;
			/** Called when a task completes (Java: BackgroundTask's finally -> forceReleaseLock) */
			afterTask: () => void;
		},
	) {
		this.testId = testId;
		this.onError = hooks.onError;
		this.afterTask = hooks.afterTask;
	}

	get signal(): AbortSignal {
		return this.controller.signal;
	}

	/** Cancel all background tasks (cooperatively); drain() no longer waits for them */
	cancelAllBackgroundTasks(): void {
		this.controller.abort();
		this.tasks.clear();
	}

	/** The finalisation task does not check `signal`, so this is the same as cancelAllBackgroundTasks() */
	cancelAllBackgroundTasksExceptFinalisation(): void {
		this.cancelAllBackgroundTasks();
	}

	/** Run a callable in the background, routing any error to the module's exception handler */
	runInBackground(callable: BackgroundTask, source = "background task"): void {
		if (this.finalisationStarted) {
			throw new Error("runInBackground called after runFinalisationTaskInBackground()");
		}
		const task = this.run(callable, source, false);
		this.tasks.add(task);
		task.finally(() => this.tasks.delete(task)).catch(() => {});
	}

	scheduleInBackground(callable: BackgroundTask, delayMillis: number, source = "scheduled task"): void {
		this.runInBackground(async () => {
			await sleep(delayMillis, this.signal);
			return callable();
		}, source);
	}

	runFinalisationTaskInBackground(callable: BackgroundTask): void {
		if (!this.finalisationStarted) {
			this.finalisationStarted = true;
			this.finalisation = this.run(callable, "finalisation", true);
		}
	}

	/** Resolves when every started task (and the finalisation task) has settled */
	async drain(): Promise<void> {
		await Promise.allSettled(this.tasks);
		await this.finalisation?.catch(() => {});
	}

	/** Errors go to onError (Java: the Future's exception reaches TestRunner) */
	private async run(callable: BackgroundTask, source: string, isFinalisation: boolean): Promise<unknown> {
		try {
			return await callable();
		} catch (e) {
			if (!isFinalisation && this.signal.aborted) {
				// cancelled; swallow like a cancelled Future
				return undefined;
			}
			// Java: BackgroundTask's finally releases the lock before TestRunner handles the exception
			this.afterTask();
			await this.onError(this.toTestInterruptedException(e), source);
			return undefined;
		} finally {
			this.afterTask();
		}
	}

	/** Java: BackgroundTask.call()'s catch blocks */
	private toTestInterruptedException(e: unknown): TestInterruptedException {
		if (e instanceof TestInterruptedException) {
			if (e.getTestId() != null && e.getTestId() !== this.testId) {
				return new TestFailureException(
					this.testId,
					"A TestInterruptedException has been caught that does not contain the test id for the current test, this is a bug in the test module",
					e,
				);
			}
			return e;
		}
		if (e instanceof ConditionError) {
			return new TestFailureException(
				this.testId,
				"A ConditionError has been incorrectly thrown by a TestModule, this is a bug in the test module: " + e.message,
			);
		}
		return new TestFailureException(this.testId, e);
	}
}

/** Sleep that rejects (with an AbortError) if the signal is aborted */
export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
	return delay(ms, undefined, { signal });
}
