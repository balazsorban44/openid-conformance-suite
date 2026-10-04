"use client";

import { ArrowDownToLine, ChevronRight, RotateCcw, Square, TerminalSquare } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { PageHeader } from "@/components/page-header.tsx";
import { OUTCOME_DOT, OutcomeBadge } from "@/components/result-badge.tsx";
import { useRunDialog } from "@/components/run-dialog.tsx";
import { RunStatusBadge } from "@/components/run-status.tsx";
import { Button } from "@/components/ui/button.tsx";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card.tsx";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip.tsx";
import { formatDuration, isOk, OUTCOME_LABEL } from "@/lib/format.ts";
import type { RunEvent, RunInfo } from "@/lib/types.ts";
import { cn } from "@/lib/utils.ts";

const MAX_LINES = 4000;

/** A run's live view: per-module progress and the console, streamed from /api/runs/<id>/events */
export function LiveRun({ initial, initialOutput }: { initial: RunInfo; initialOutput: string[] }) {
	const router = useRouter();
	const { open } = useRunDialog();
	const [run, setRun] = useState(initial);
	const [output, setOutput] = useState(initialOutput);
	const [cancelling, setCancelling] = useState(false);
	const ended = run.endedAt != null;

	useEffect(() => {
		if (initial.endedAt) {
			return;
		}
		const source = new EventSource(`/api/runs/${initial.id}/events`);
		source.addEventListener("message", (message) => {
			const event = JSON.parse(message.data as string) as RunEvent;
			switch (event.type) {
				case "snapshot":
					setRun(event.run);
					setOutput(event.output);
					break;
				case "output":
					setOutput((o) => {
						const next = o.concat(event.lines);
						return next.length > MAX_LINES ? next.slice(-MAX_LINES) : next;
					});
					break;
				case "module":
					setRun((r) => ({ ...r, modules: r.modules.map((m, i) => (i === event.index ? event.module : m)) }));
					break;
				case "modules":
					setRun((r) => ({ ...r, modules: event.modules }));
					break;
				case "status":
					setRun(event.run);
					if (event.run.endedAt) {
						source.close();
						announce(event.run);
						router.refresh();
					}
					break;
			}
		});
		return () => source.close();
	}, [initial.id, initial.endedAt, router]);

	async function cancel() {
		setCancelling(true);
		const res = await fetch(`/api/runs/${run.id}`, { method: "DELETE" });
		if (!res.ok) {
			toast.error("Could not cancel the run", { description: ((await res.json()) as { error?: string }).error });
			setCancelling(false);
		}
	}

	const done = run.modules.filter((m) => m.state === "done").length;
	const failing = run.modules.filter((m) => m.state === "done" && m.outcome !== "not-run" && !isOk(m.outcome)).length;

	return (
		<>
			<PageHeader
				crumbs={[{ label: "Runs", href: "/runs" }, { label: run.label }]}
				actions={
					ended ? (
						<Button size="sm" variant="outline" onClick={() => open(rerun(run))}>
							<RotateCcw /> Run again
						</Button>
					) : (
						<Button size="sm" variant="destructive" onClick={cancel} disabled={cancelling}>
							<Square className="fill-current" /> {cancelling ? "Cancelling..." : "Cancel run"}
						</Button>
					)
				}
			/>
			<main className="flex min-h-0 flex-col gap-6 p-4 md:p-6">
				<div className="flex flex-col gap-3">
					<div className="flex flex-wrap items-center gap-3">
						<h1 className="font-mono text-2xl font-semibold tracking-tight">{run.label}</h1>
						<RunStatusBadge status={run.status} />
						<Elapsed from={run.startedAt} to={run.endedAt} />
					</div>
					<p className="text-muted-foreground font-mono text-xs break-all">$ {run.command}</p>
					{run.error && <p className="text-failure text-sm">{run.error}</p>}
				</div>

				<Card className="gap-3 py-4">
					<CardContent className="flex flex-col gap-3 px-4">
						<div className="flex items-baseline justify-between text-sm">
							<span>
								<span className="font-semibold tabular-nums">{done}</span>
								<span className="text-muted-foreground"> of {run.modules.length} modules finished</span>
								{failing > 0 && <span className="text-failure ml-3 font-medium">{failing} failing</span>}
							</span>
							<span className="text-muted-foreground text-xs tabular-nums">
								{run.modules.length ? Math.round((done / run.modules.length) * 100) : 0}%
							</span>
						</div>
						<div
							className="flex h-2.5 gap-0.5 overflow-hidden rounded-full"
							role="progressbar"
							aria-valuemin={0}
							aria-valuemax={run.modules.length}
							aria-valuenow={done}
						>
							{run.modules.length === 0 ? (
								<div className="bg-muted h-full flex-1 animate-pulse" />
							) : (
								run.modules.map((m) => (
									<Tooltip key={m.title}>
										<TooltipTrigger asChild>
											<div className={cn("h-full flex-1 transition-colors", OUTCOME_DOT[m.outcome])} />
										</TooltipTrigger>
										<TooltipContent>
											<span className="font-mono">{m.name}</span> · {OUTCOME_LABEL[m.outcome]}
										</TooltipContent>
									</Tooltip>
								))
							)}
						</div>
					</CardContent>
				</Card>

				<div className="grid min-h-0 gap-6 xl:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
					<Card className="gap-0 py-0">
						<CardHeader className="border-b py-3 [.border-b]:pb-3">
							<CardTitle className="text-sm">Modules</CardTitle>
						</CardHeader>
						<CardContent className="max-h-[36rem] divide-y overflow-auto px-0">
							{run.modules.length === 0 && (
								<p className="text-muted-foreground px-4 py-6 text-sm">
									{ended ? "No module ran." : "Listing the modules..."}
								</p>
							)}
							{run.modules.map((m) => {
								const row = (
									<>
										<OutcomeBadge outcome={m.outcome} className="w-32 justify-center" />
										<span className="min-w-0 flex-1 truncate font-mono text-xs">{m.name}</span>
										<span className="text-muted-foreground text-xs tabular-nums">{formatDuration(m.durationMs)}</span>
										{m.testId && <ChevronRight className="text-muted-foreground size-4" />}
									</>
								);
								return m.testId ? (
									<Link
										key={m.title}
										href={`/modules/${m.testId}`}
										className={cn(
											"hover:bg-muted/50 flex items-center gap-3 px-4 py-2 transition-colors",
											m.state === "running" && "bg-info-soft/40",
										)}
									>
										{row}
									</Link>
								) : (
									<div
										key={m.title}
										className={cn("flex items-center gap-3 px-4 py-2", m.state === "running" && "bg-info-soft/40")}
									>
										{row}
									</div>
								);
							})}
						</CardContent>
					</Card>
					<Console lines={output} live={!ended} />
				</div>
			</main>
		</>
	);
}

function rerun(run: RunInfo) {
	const r = run.request;
	return r.kind === "project"
		? { kind: "project" as const, project: r.project, module: r.module }
		: { kind: "plan" as const, plan: r.plan, config: r.config, module: r.module };
}

function announce(run: RunInfo): void {
	const failing = run.modules.filter((m) => m.state === "done" && m.outcome !== "not-run" && !isOk(m.outcome)).length;
	if (run.status === "passed") {
		toast.success(`${run.label} passed`, { description: `${run.modules.length} modules, nothing unexpected` });
	} else if (run.status === "cancelled") {
		toast(`${run.label} cancelled`);
	} else {
		toast.error(`${run.label} ${run.status}`, {
			description: failing ? `${failing} modules with unexpected results` : run.error,
		});
	}
}

function Elapsed({ from, to }: { from: number; to?: number }) {
	const [now, setNow] = useState(() => Date.now());
	useEffect(() => {
		if (to) {
			return;
		}
		const t = setInterval(() => setNow(Date.now()), 1000);
		return () => clearInterval(t);
	}, [to]);
	return (
		<span className="text-muted-foreground text-sm tabular-nums" suppressHydrationWarning>
			{formatDuration((to ?? now) - from)}
		</span>
	);
}

const LINE_TONE: [RegExp, string][] = [
	[/^\s*✓\s+\d+/, "text-emerald-400"],
	[/^\s*✘\s+\d+/, "text-red-400 font-semibold"],
	[/^\s*-\s+\d+\s/, "text-zinc-500"],
	[/\[FAILURE\]/, "text-red-400"],
	[/\[WARNING\]/, "text-amber-300"],
	[/\[REVIEW\]/, "text-violet-300"],
	[/\[SUCCESS\]/, "text-zinc-300"],
	[/^\$ /, "text-sky-300"],
	[/^\s*\d+ (passed|failed|skipped|flaky)/, "text-zinc-100 font-semibold"],
];

/** The run's console output; follows the end unless scrolled up */
function Console({ lines, live }: { lines: string[]; live: boolean }) {
	const ref = useRef<HTMLDivElement>(null);
	const [follow, setFollow] = useState(true);
	useEffect(() => {
		if (follow && ref.current) {
			ref.current.scrollTop = ref.current.scrollHeight;
		}
	}, [lines, follow]);
	return (
		<Card className="gap-0 overflow-hidden border-zinc-800 bg-zinc-950 py-0 text-zinc-300 dark:bg-black/60">
			<div className="flex items-center gap-2 border-b border-zinc-800 px-4 py-2.5">
				<TerminalSquare className="size-4 text-zinc-500" aria-hidden />
				<span className="text-sm font-medium text-zinc-200">Console</span>
				{live && <span className="size-1.5 animate-pulse rounded-full bg-emerald-400" aria-label="live" />}
				<span className="ml-auto font-mono text-[11px] text-zinc-500 tabular-nums">{lines.length} lines</span>
				{!follow && (
					<Button
						size="sm"
						variant="ghost"
						className="h-6 px-2 text-xs text-zinc-300 hover:bg-zinc-800 hover:text-zinc-100"
						onClick={() => setFollow(true)}
					>
						<ArrowDownToLine className="size-3" /> Follow
					</Button>
				)}
			</div>
			<div
				ref={ref}
				onScroll={(e) => {
					const el = e.currentTarget;
					setFollow(el.scrollHeight - el.scrollTop - el.clientHeight < 24);
				}}
				className="h-[36rem] overflow-auto px-4 py-3 font-mono text-[11.5px] leading-5"
				tabIndex={0}
				aria-label="Console output"
			>
				{lines.map((line, i) => (
					<div key={i} className={cn("whitespace-pre-wrap break-all", LINE_TONE.find(([re]) => re.test(line))?.[1])}>
						{line || " "}
					</div>
				))}
			</div>
		</Card>
	);
}
