import { Info } from "lucide-react";
import { REPOSITORY_URL } from "@/lib/mode.ts";

/** Above every page of the hosted (read-only) UI */
export function HostedBanner() {
	return (
		<div
			role="note"
			className="bg-info-soft text-info flex items-start gap-2 border-b px-4 py-2 text-xs leading-relaxed sm:items-center"
		>
			<Info className="mt-0.5 size-3.5 shrink-0 sm:mt-0" aria-hidden />
			<p>
				<strong className="font-semibold">Read-only demo.</strong> This is the suite&apos;s web UI showing results
				bundled with it (<span className="font-mono">rp-basic</span>, <span className="font-mono">op-config</span>,{" "}
				<span className="font-mono">op-dynamic</span>). To run the tests and follow them live, use a checkout:{" "}
				<code className="font-mono">pnpm ui</code> (
				<a href={REPOSITORY_URL} className="underline underline-offset-2" target="_blank" rel="noreferrer">
					source
				</a>
				).
			</p>
		</div>
	);
}
