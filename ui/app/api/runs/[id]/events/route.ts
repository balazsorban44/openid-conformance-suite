import { findRun, subscribe } from "@/lib/runs.ts";
import type { RunEvent } from "@/lib/types.ts";

function noop(): void {}

interface Context {
	params: Promise<{ id: string }>;
}

/**
 * The run's progress as Server-Sent Events (`RunEvent`s, one JSON object per `data:` line): a snapshot first,
 * then console output, module updates and status changes. A run that is no longer in memory (the server restarted)
 * gets its stored snapshot and the stream ends.
 */
export async function GET(request: Request, { params }: Context): Promise<Response> {
	const { id } = await params;
	const encoder = new TextEncoder();
	let cleanup: () => void = noop;
	const stream = new ReadableStream<Uint8Array>({
		async start(controller) {
			let closed = false;
			const send = (e: RunEvent) => {
				if (!closed) {
					controller.enqueue(encoder.encode(`data: ${JSON.stringify(e)}\n\n`));
				}
			};
			const close = () => {
				if (!closed) {
					closed = true;
					cleanup();
					controller.close();
				}
			};
			const unsubscribe = subscribe(id, (e) => {
				send(e);
				if (e.type === "status" && e.run.endedAt) {
					// let the client read the last events, then end the stream
					setTimeout(close, 250);
				}
			});
			if (!unsubscribe) {
				const stored = await findRun(id);
				if (stored) {
					send({ type: "snapshot", run: stored.info, output: stored.output });
				} else {
					controller.enqueue(encoder.encode(`event: error\ndata: ${JSON.stringify({ error: "unknown run" })}\n\n`));
				}
				close();
				return;
			}
			const ping = setInterval(() => !closed && controller.enqueue(encoder.encode(": ping\n\n")), 15_000);
			cleanup = () => {
				clearInterval(ping);
				unsubscribe();
			};
			request.signal.addEventListener("abort", close);
		},
		cancel() {
			cleanup();
		},
	});
	return new Response(stream, {
		headers: {
			"content-type": "text/event-stream; charset=utf-8",
			"cache-control": "no-cache, no-transform",
			connection: "keep-alive",
			"x-accel-buffering": "no",
		},
	});
}
