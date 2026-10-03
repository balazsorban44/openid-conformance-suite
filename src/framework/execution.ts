import { ConditionError } from "./Condition.ts";
import { TestFailureException, TestInterruptedException } from "./exceptions.ts";

export type BackgroundTask = () => Promise<unknown> | unknown;

/**
 * Port of runner/TestExecutionManager.java (+ its BackgroundTask wrapper).
 *
 * Background "threads" are promises. Cancellation is cooperative: tasks get an AbortSignal through
 * `signal` and `sleep()` rejects when cancelled.
 */
export class TestExecutionManager {
	private readonly testId: string;
	private tasks = new Set<Promise<unknown>>();
	private controller = new AbortController();
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

	getTestId(): string {
		return this.testId;
	}

	/** Cancel all background tasks (cooperatively) */
	cancelAllBackgroundTasks(): void {
		this.controller.abort();
		this.tasks.clear();
	}

	cancelAllBackgroundTasksExceptFinalisation(): void {
		// a cancelled task notices via `signal`; the finalisation task does not check it
		this.controller.abort();
		this.tasks.clear();
	}

	private wrap(callable: BackgroundTask, source: string, isFinalisation: boolean): Promise<unknown> {
		const myController = this.controller;
		const p = (async () => {
			try {
				return await callable();
			} catch (e) {
				if (!isFinalisation && myController.signal.aborted) {
					// cancelled; swallow like a cancelled Future
					return undefined;
				}
				this.afterTask();
				let err: TestInterruptedException;
				if (e instanceof TestInterruptedException) {
					if (e.getTestId() != null && e.getTestId() !== this.testId) {
						err = new TestFailureException(
							this.testId,
							"A TestInterruptedException has been caught that does not contain the test id for the current test, this is a bug in the test module",
							e,
						);
					} else {
						err = e;
					}
				} else if (e instanceof ConditionError) {
					err = new TestFailureException(
						this.testId,
						"A ConditionError has been incorrectly thrown by a TestModule, this is a bug in the test module: " +
							e.message,
					);
				} else {
					err = new TestFailureException(this.testId, e);
				}
				await this.onError(err, source);
				return undefined;
			} finally {
				this.afterTask();
			}
		})();
		return p;
	}

	/** Run a callable in the background, routing any error to the module's exception handler */
	runInBackground(callable: BackgroundTask, source = "background task"): void {
		if (this.finalisationStarted) {
			throw new Error("runInBackground called after runFinalisationTaskInBackground()");
		}
		const p = this.wrap(callable, source, false);
		this.tasks.add(p);
		p.finally(() => this.tasks.delete(p)).catch(() => {});
	}

	/** Like runInBackground but returns false (and does nothing) once finalisation has started */
	tryRunInBackground(callable: BackgroundTask, source = "background task"): boolean {
		if (this.finalisationStarted) {
			return false;
		}
		this.runInBackground(callable, source);
		return true;
	}

	scheduleInBackground(callable: BackgroundTask, delayMillis: number, source = "scheduled task"): void {
		this.runInBackground(async () => {
			await sleep(delayMillis, this.signal);
			return callable();
		}, source);
	}

	runFinalisationTaskInBackground(callable: BackgroundTask): void {
		if (this.finalisationStarted) {
			return;
		}
		this.finalisationStarted = true;
		this.finalisation = this.wrap(callable, "finalisation", true);
	}

	/** Resolves when every started task (and the finalisation task) has settled */
	async drain(): Promise<void> {
		await Promise.allSettled(this.tasks);
		if (this.finalisation) {
			await this.finalisation.catch(() => {});
		}
	}
}

/** Sleep that rejects with CancelledError if the signal is aborted */
export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
	return new Promise((resolve, reject) => {
		if (signal?.aborted) {
			reject(new CancelledError());
			return;
		}
		const t = setTimeout(() => {
			signal?.removeEventListener("abort", onAbort);
			resolve();
		}, ms);
		const onAbort = () => {
			clearTimeout(t);
			reject(new CancelledError());
		};
		signal?.addEventListener("abort", onAbort, { once: true });
	});
}

export class CancelledError extends Error {
	constructor() {
		super("cancelled");
		this.name = "CancelledError";
	}
}
