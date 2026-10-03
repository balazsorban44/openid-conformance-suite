/**
 * Port of testmodule/TestLockManager.java
 *
 * In Java, the test module holds a lock while RUNNING and releases it around network I/O so that incoming
 * HTTP requests (which take the lock) can be handled meanwhile. In this port the "lock" is an async mutex
 * owned by AbstractTestModule; conditions release/reacquire it around HTTP calls the same way.
 */
export interface TestLockManager {
	releaseLock(): Promise<void>;
	reacquireLock(): Promise<void>;
	disable(): void;
}
