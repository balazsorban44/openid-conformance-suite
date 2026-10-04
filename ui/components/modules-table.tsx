import { ChevronRight, Play } from "lucide-react";
import Link from "next/link";
import { OutcomeBadge } from "@/components/result-badge.tsx";
import { NewRunButton, type RunPrefill } from "@/components/run-dialog.tsx";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table.tsx";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip.tsx";
import { formatDuration, formatRelative, moduleIntent, outcomeOf } from "@/lib/format.ts";
import type { ModuleStatus } from "@/lib/types.ts";

/** The modules of a plan or project with their latest result; each row links to the module's log */
export function ModulesTable({
	modules,
	runPrefill,
	showVariant = false,
}: {
	modules: ModuleStatus[];
	/** "run this module" button: the run to start, with `module` set to the row's */
	runPrefill?: RunPrefill;
	showVariant?: boolean;
}) {
	return (
		<Table>
			<TableHeader>
				<TableRow>
					<TableHead className="w-36 pl-6">Result</TableHead>
					<TableHead>Module</TableHead>
					{showVariant && <TableHead className="hidden xl:table-cell">Variant</TableHead>}
					<TableHead className="hidden text-right md:table-cell">
						<Tooltip>
							<TooltipTrigger className="cursor-help underline decoration-dotted underline-offset-4">
								Conditions
							</TooltipTrigger>
							<TooltipContent>success / warning / failure log entries</TooltipContent>
						</Tooltip>
					</TableHead>
					<TableHead className="hidden text-right sm:table-cell">Duration</TableHead>
					<TableHead className="hidden lg:table-cell">Finished</TableHead>
					<TableHead className="w-0 pr-6" />
				</TableRow>
			</TableHeader>
			<TableBody>
				{modules.map((m) => {
					const r = m.record?.report;
					const outcome = r ? outcomeOf(r) : m.skipReason ? "skipped" : "not-run";
					const href = r?.testId ? `/modules/${r.testId}` : null;
					return (
						<TableRow key={m.moduleList ? `${m.name} (${m.moduleList})` : m.name} className="group">
							<TableCell className="pl-6">
								<OutcomeBadge outcome={outcome} />
							</TableCell>
							<TableCell className="max-w-0 min-w-56">
								{href ? (
									<Link href={href} className="font-mono text-sm font-medium hover:underline">
										{m.name}
									</Link>
								) : (
									<span className="font-mono text-sm">{m.name}</span>
								)}
								{m.moduleList && (
									<span className="text-muted-foreground ml-2 font-mono text-[11px]">{m.moduleList}</span>
								)}
								<p className="text-muted-foreground truncate text-xs">
									{r
										? moduleIntent(r.title)
										: m.skipReason
											? `Not run by this project: ${m.skipReason}`
											: "No result yet"}
								</p>
							</TableCell>
							{showVariant && (
								<TableCell className="text-muted-foreground hidden max-w-72 truncate font-mono text-[11px] xl:table-cell">
									{r?.variantString}
								</TableCell>
							)}
							<TableCell className="hidden text-right font-mono text-xs tabular-nums md:table-cell">
								{r ? (
									<>
										<span className="text-success">{r.analysis.counts.SUCCESS}</span>
										<span className="text-muted-foreground"> / </span>
										<span className={r.analysis.counts.WARNING ? "text-warning" : "text-muted-foreground"}>
											{r.analysis.counts.WARNING}
										</span>
										<span className="text-muted-foreground"> / </span>
										<span className={r.analysis.counts.FAILURE ? "text-failure" : "text-muted-foreground"}>
											{r.analysis.counts.FAILURE}
										</span>
									</>
								) : null}
							</TableCell>
							<TableCell className="text-muted-foreground hidden text-right text-sm tabular-nums sm:table-cell">
								{formatDuration(r?.durationMs)}
							</TableCell>
							<TableCell className="text-muted-foreground hidden text-sm lg:table-cell">
								{m.record ? formatRelative(m.record.finishedAt) : ""}
							</TableCell>
							<TableCell className="pr-6">
								<div className="flex justify-end gap-1">
									{runPrefill && (
										<NewRunButton
											size="icon"
											variant="ghost"
											className="size-8 opacity-60 group-hover:opacity-100 focus-visible:opacity-100"
											aria-label={`Run ${m.name}`}
											prefill={{ ...runPrefill, module: m.name }}
										>
											<Play />
										</NewRunButton>
									)}
									{href && (
										<Link
											href={href}
											aria-label={`Open the log of ${m.name}`}
											className="hover:bg-accent text-muted-foreground inline-flex size-8 items-center justify-center rounded-md"
										>
											<ChevronRight className="size-4" />
										</Link>
									)}
								</div>
							</TableCell>
						</TableRow>
					);
				})}
			</TableBody>
		</Table>
	);
}
