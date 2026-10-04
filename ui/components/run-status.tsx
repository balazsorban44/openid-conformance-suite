import { Ban, Check, CircleAlert, Loader2, X } from "lucide-react";
import type { RunStatus } from "@/lib/types.ts";
import { cn } from "@/lib/utils.ts";

const STYLE: Record<RunStatus, { label: string; className: string; icon: typeof Check }> = {
	starting: { label: "Starting", className: "bg-info-soft text-info border-info/25", icon: Loader2 },
	running: { label: "Running", className: "bg-info-soft text-info border-info/25", icon: Loader2 },
	passed: { label: "Passed", className: "bg-success-soft text-success border-success/25", icon: Check },
	failed: { label: "Failed", className: "bg-failure-soft text-failure border-failure/30", icon: X },
	cancelled: { label: "Cancelled", className: "bg-muted text-muted-foreground border-border", icon: Ban },
	error: { label: "Error", className: "bg-failure-soft text-failure border-failure/30", icon: CircleAlert },
};

/** A run's status: starting, running, passed (exit code 0), failed, cancelled, error (did not start) */
export function RunStatusBadge({ status, className }: { status: RunStatus; className?: string }) {
	const s = STYLE[status];
	return (
		<span
			className={cn(
				"inline-flex h-6 items-center gap-1.5 rounded-md border px-2 text-xs font-medium whitespace-nowrap",
				s.className,
				className,
			)}
		>
			<s.icon
				className={cn("size-3.5", (status === "running" || status === "starting") && "animate-spin")}
				aria-hidden
			/>
			{s.label}
		</span>
	);
}
