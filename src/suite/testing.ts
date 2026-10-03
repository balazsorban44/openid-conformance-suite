/**
 * Unit-test helpers (Vitest): a fresh event log installed as the current test's log for every test, and an MSW
 * server for helpers that make HTTP calls (requests are intercepted at the network level; unhandled requests fail).
 *
 *   const t = useTestLog();
 *   const server = useMswServer();
 *   test("...", async () => { server.use(http.get(...)); await helper(); expect(t.entries()).toEqual([...]); });
 */
import { setupServer } from "msw/node";
import { afterAll, afterEach, beforeAll, beforeEach } from "vitest";
import { createLog, useLog, type EventLog, type LogEntry } from "./log.ts";

export function useTestLog(testName = "unit-test"): {
	readonly log: EventLog;
	entries(): Omit<LogEntry, "_id" | "testId" | "time" | "seq">[];
} {
	let log = createLog("t1");
	let uninstall = () => {};
	beforeEach(() => {
		log = createLog("t1");
		uninstall = useLog(log, { testName });
	});
	afterEach(() => uninstall());
	return {
		get log() {
			return log;
		},
		entries: () => log.entries.map(({ _id: _, testId: _t, time: _time, seq: _seq, ...rest }) => rest),
	};
}

export function useMswServer(): ReturnType<typeof setupServer> {
	const server = setupServer();
	beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
	afterEach(() => server.resetHandlers());
	afterAll(() => server.close());
	return server;
}
