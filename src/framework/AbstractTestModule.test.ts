import assert from "node:assert/strict";
import { test } from "node:test";
import { AbstractCondition } from "./AbstractCondition.ts";
import { AbstractConditionSequence } from "./AbstractConditionSequence.ts";
import { AbstractTestModule } from "./AbstractTestModule.ts";
import { BrowserControl } from "./BrowserControl.ts";
import { ConditionResult, type EnvironmentRequirements } from "./Condition.ts";
import { args } from "./DataUtils.ts";
import type { Environment } from "./Environment.ts";
import { TestInstanceEventLog } from "./EventLog.ts";
import { TestExecutionManager } from "./execution.ts";
import { ImageService } from "./ImageService.ts";
import type { JsonObject } from "./json.ts";
import { Result, Status, type PublishTestModule } from "./TestModule.ts";

class PutsValue extends AbstractCondition {
	static override post: EnvironmentRequirements = { strings: ["value"] };
	override evaluate(env: Environment): Environment {
		env.putString("value", "v");
		this.logSuccess("put value", args("value", "v"));
		return env;
	}
}

class AlwaysFails extends AbstractCondition {
	override evaluate(_env: Environment): Environment {
		throw this.error("this always fails", args("x", 1));
	}
}

class NeedsMissing extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["does_not_exist"] };
	override evaluate(env: Environment): Environment {
		return env;
	}
}

class Seq extends AbstractConditionSequence {
	override evaluate(): void {
		this.callAndStopOnFailure(PutsValue, "REQ-1");
		this.callAndContinueOnFailure(AlwaysFails, ConditionResult.WARNING, "REQ-2");
	}
}

class Module extends AbstractTestModule {
	static override readonly meta: PublishTestModule = { testName: "unit-test-module", displayName: "x", profile: "x" };
	stopAtFailure = false;

	override async configure(config: JsonObject, baseUrl: string): Promise<void> {
		this.env.putObject("config", config);
		this.env.putString("base_url", baseUrl);
		await this.setStatus(Status.CONFIGURED);
		this.fireSetupDone();
	}

	override async start(): Promise<void> {
		await this.setStatus(Status.RUNNING);
		await this.call(this.sequence(Seq));
		await this.skipIfMissing(["nope"], null, ConditionResult.INFO, PutsValue);
		if (this.stopAtFailure) {
			await this.callAndStopOnFailure(NeedsMissing);
		}
		await this.fireTestFinished();
	}
}

async function runModule(stopAtFailure: boolean): Promise<{ m: Module; log: TestInstanceEventLog }> {
	const log = new TestInstanceEventLog("t1");
	const m = new Module();
	m.stopAtFailure = stopAtFailure;
	const exec = new TestExecutionManager("t1", {
		onError: (e, src) => m.handleException(e, src),
		afterTask: () => m.forceReleaseLock(),
	});
	const images = new ImageService(log);
	const browser = new BrowserControl({}, "t1", log, exec, images, () => Promise.reject(new Error("no browser")));
	m.setProperties("t1", null, log, browser, exec, images);
	exec.runInBackground(async () => {
		await m.configure({}, "http://localhost/test/t1", "", "");
		await m.start();
	});
	await m.whenFinished();
	await exec.drain();
	return { m, log };
}

test("module runs sequence, records warning and finishes", async () => {
	const { m, log } = await runModule(false);
	assert.equal(m.getStatus(), Status.FINISHED);
	assert.equal(m.getResult(), Result.WARNING);
	const srcs = log.entries.map((e) => e.src);
	assert.ok(srcs.includes("PutsValue"));
	assert.ok(srcs.includes("AlwaysFails"));
	const fail = log.entries.find((e) => e.src === "AlwaysFails");
	assert.equal(fail?.["result"], "WARNING");
	assert.deepEqual(fail?.["requirements"], ["REQ-2"]);
	const skip = log.entries.find((e) => e.src === "PutsValue" && String(e["msg"]).startsWith("Skipped"));
	assert.ok(skip);
	assert.ok(log.entries.some((e) => e["msg"] === "Test has run to completion"));
});

test("stop-on-failure pre-environment error fails and interrupts the module", async () => {
	const { m, log } = await runModule(true);
	assert.equal(m.getStatus(), Status.INTERRUPTED);
	assert.equal(m.getResult(), Result.FAILED);
	assert.ok(log.entries.some((e) => e.src === "NeedsMissing" && e["result"] === "FAILURE"));
});
