import {
	Ban,
	Check,
	CircleAlert,
	CircleDashed,
	CircleSlash,
	Eye,
	Info,
	Loader2,
	ShieldCheck,
	TriangleAlert,
	X,
} from "lucide-react";
import { OUTCOME_LABEL } from "@/lib/format.ts";
import type { Outcome } from "@/lib/types.ts";
import { cn } from "@/lib/utils.ts";

const TONE = {
	success: "bg-success-soft text-success border-success/25",
	failure: "bg-failure-soft text-failure border-failure/30",
	warning: "bg-warning-soft text-warning border-warning/30",
	info: "bg-info-soft text-info border-info/25",
	review: "bg-review-soft text-review border-review/25",
	muted: "bg-muted text-muted-foreground border-border",
} as const;

type Tone = keyof typeof TONE;

const OUTCOME_TONE: Record<Outcome, Tone> = {
	passed: "success",
	"expected-failure": "success",
	warning: "warning",
	review: "review",
	skipped: "muted",
	failed: "failure",
	interrupted: "failure",
	"not-run": "muted",
	pending: "muted",
	running: "info",
	cancelled: "muted",
};

const OUTCOME_ICON: Record<Outcome, typeof Check> = {
	passed: Check,
	"expected-failure": ShieldCheck,
	warning: TriangleAlert,
	review: Eye,
	skipped: CircleSlash,
	failed: X,
	interrupted: CircleAlert,
	"not-run": CircleDashed,
	pending: CircleDashed,
	running: Loader2,
	cancelled: Ban,
};

/** Background colour class of an outcome, for dots and strips */
export const OUTCOME_DOT: Record<Outcome, string> = {
	passed: "bg-success",
	"expected-failure": "bg-success/60",
	warning: "bg-warning",
	review: "bg-review",
	skipped: "bg-muted-foreground/30",
	failed: "bg-failure",
	interrupted: "bg-failure",
	"not-run": "bg-muted-foreground/15",
	pending: "bg-muted-foreground/15",
	running: "bg-info animate-pulse",
	cancelled: "bg-muted-foreground/30",
};

function Pill({ tone, className, children }: { tone: Tone; className?: string; children: React.ReactNode }) {
	return (
		<span
			className={cn(
				"inline-flex h-5 shrink-0 items-center gap-1 rounded-md border px-1.5 text-[11px] font-medium whitespace-nowrap [&>svg]:size-3",
				TONE[tone],
				className,
			)}
		>
			{children}
		</span>
	);
}

/** A module's outcome: passed, failed, expected failure, ... */
export function OutcomeBadge({ outcome, className }: { outcome: Outcome; className?: string }) {
	const Icon = OUTCOME_ICON[outcome];
	return (
		<Pill tone={OUTCOME_TONE[outcome]} className={className}>
			<Icon className={cn(outcome === "running" && "animate-spin")} aria-hidden />
			{OUTCOME_LABEL[outcome]}
		</Pill>
	);
}

const LOG_TONE: Record<string, Tone> = {
	SUCCESS: "success",
	FAILURE: "failure",
	WARNING: "warning",
	INFO: "info",
	REVIEW: "review",
};

const LOG_ICON: Record<string, typeof Check> = {
	SUCCESS: Check,
	FAILURE: X,
	WARNING: TriangleAlert,
	INFO: Info,
	REVIEW: Eye,
};

/** A log entry's result: SUCCESS, FAILURE, WARNING, INFO, REVIEW (upstream's condition results) */
export function LogResultBadge({ result, className }: { result: string; className?: string }) {
	const Icon = LOG_ICON[result] ?? Info;
	return (
		<Pill tone={LOG_TONE[result] ?? "muted"} className={cn("font-mono tracking-tight", className)}>
			<Icon aria-hidden />
			{result}
		</Pill>
	);
}

/** The module's own result as upstream names it (PASSED, FAILED, WARNING, REVIEW, SKIPPED) */
export function ResultText({ result }: { result: string }) {
	const tone: Tone =
		result === "PASSED"
			? "success"
			: result === "FAILED"
				? "failure"
				: result === "WARNING"
					? "warning"
					: result === "REVIEW"
						? "review"
						: "muted";
	return (
		<Pill tone={tone} className="font-mono tracking-tight">
			{result}
		</Pill>
	);
}
