import { readFile, stat } from "node:fs/promises";
import { extname } from "node:path";
import { hosted } from "@/lib/mode.ts";
import { inside, reportDir, resultsDir } from "@/lib/paths.ts";

async function isFile(path: string): Promise<boolean> {
	return stat(path).then(
		(s) => s.isFile(),
		() => false,
	);
}

const TYPES: Record<string, string> = {
	".json": "application/json; charset=utf-8",
	".html": "text/html; charset=utf-8",
	".md": "text/markdown; charset=utf-8",
	".txt": "text/plain; charset=utf-8",
	".png": "image/png",
	".jpg": "image/jpeg",
	".webm": "video/webm",
	".zip": "application/zip",
};

const ROOTS: Record<string, string> = { results: resultsDir, report: reportDir };

interface Context {
	params: Promise<{ root: string; path: string[] }>;
}

/**
 * A file of a run: `/api/files/results/<test dir>/log.json` (the results directory: logs, screenshots, videos,
 * traces) or `/api/files/report/results.json` (the report directory). Paths cannot leave their root.
 */
export async function GET(_request: Request, { params }: Context): Promise<Response> {
	const { root, path } = await params;
	const base = ROOTS[root];
	const file = base ? inside(base, path.join("/")) : null;
	const type = file ? TYPES[extname(file).toLowerCase()] : undefined;
	if (!file || !type) {
		return new Response("not found", { status: 404 });
	}
	try {
		// the bundled results keep large text files gzipped next to their name (log.html.gz): served as they are
		const gzipped = hosted && !(await isFile(file)) && (await isFile(`${file}.gz`));
		if (!gzipped && !(await isFile(file))) {
			return new Response("not found", { status: 404 });
		}
		const body = await readFile(gzipped ? `${file}.gz` : file);
		const headers: Record<string, string> = {
			"content-type": type,
			"cache-control": hosted ? "public, max-age=300" : "no-cache",
		};
		if (gzipped) {
			headers["content-encoding"] = "gzip";
		}
		if (type === "application/zip") {
			headers["content-disposition"] = `attachment; filename="${path.at(-1)}"`;
		}
		if (type.startsWith("text/html")) {
			// log.html is the suite's own page; keep it from running anything
			headers["content-security-policy"] = "default-src 'none'; img-src data:; style-src 'unsafe-inline'";
		}
		return new Response(new Uint8Array(body), { headers });
	} catch {
		return new Response("not found", { status: 404 });
	}
}
