/**
 * The UI runs in one of two modes:
 *
 *   local   (default)  reads a report directory and starts runs with the suite's CLI (`pnpm ui`)
 *   hosted             read-only: serves the results bundled under ui/sample-data/ (scripts/sample-data.ts); no runs.
 *                      Chosen by CONFORMANCE_UI_MODE=static, or automatically on Vercel (VERCEL is set there, at build
 *                      and at run time); CONFORMANCE_UI_MODE=local turns it off again.
 *
 * Server side only: the client components get `hosted` as a prop from the root layout.
 */
import { HOSTED_RUN_MESSAGE } from "./format.ts";

const mode = process.env["CONFORMANCE_UI_MODE"];

export const hosted: boolean = mode ? mode === "static" : Boolean(process.env["VERCEL"]);

/** The suite's repository, linked from the hosted banner */
export const REPOSITORY_URL = "https://github.com/balazsorban44/openid-conformance-suite";

/** The 405 of every route that starts or stops a run when the UI is hosted; null when it is not */
export function refuseWhenHosted(): Response | null {
	return hosted
		? Response.json({ error: HOSTED_RUN_MESSAGE }, { status: 405, headers: { allow: "GET, HEAD, OPTIONS" } })
		: null;
}
