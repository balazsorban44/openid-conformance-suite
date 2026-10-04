import { rejectCrossSite } from "@/lib/http.ts";
import { refuseWhenHosted } from "@/lib/mode.ts";
import { cancelRun, findRun, RunError } from "@/lib/runs.ts";

interface Context {
	params: Promise<{ id: string }>;
}

/** The run and the tail of its console output */
export async function GET(_request: Request, { params }: Context): Promise<Response> {
	const run = await findRun((await params).id);
	return run ? Response.json(run) : Response.json({ error: "unknown run" }, { status: 404 });
}

/** Cancels the run (stops its process group) */
export async function DELETE(request: Request, { params }: Context): Promise<Response> {
	const rejected = refuseWhenHosted() ?? rejectCrossSite(request, { json: false });
	if (rejected) {
		return rejected;
	}
	try {
		return Response.json({ run: cancelRun((await params).id) });
	} catch (e) {
		if (e instanceof RunError) {
			return Response.json({ error: e.message }, { status: e.status });
		}
		throw e;
	}
}
