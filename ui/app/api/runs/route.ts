import { rejectCrossSite } from "@/lib/http.ts";
import { activeRunId, listRuns, RunError, startRun } from "@/lib/runs.ts";
import type { RunRequest } from "@/lib/types.ts";

/** The active run's id and every run, newest first */
export async function GET(): Promise<Response> {
	return Response.json({ active: activeRunId(), runs: await listRuns() });
}

/** Starts a run: a `RunRequest` (a CI project, or a plan + config + variant); 409 while another run is going */
export async function POST(request: Request): Promise<Response> {
	const rejected = rejectCrossSite(request, { json: true });
	if (rejected) {
		return rejected;
	}
	let body: RunRequest;
	try {
		body = (await request.json()) as RunRequest;
	} catch {
		return Response.json({ error: "the body must be a JSON run request" }, { status: 400 });
	}
	if (body?.kind !== "project" && body?.kind !== "plan") {
		return Response.json({ error: "kind must be 'project' or 'plan'" }, { status: 400 });
	}
	try {
		const run = await startRun(body);
		return Response.json({ run }, { status: 201 });
	} catch (e) {
		if (e instanceof RunError) {
			return Response.json({ error: e.message, runId: e.runId }, { status: e.status });
		}
		throw e;
	}
}
