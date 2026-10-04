import { ChevronRight, History } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { connection } from "next/server";
import { PageHeader, PageTitle } from "@/components/page-header.tsx";
import { NewRunButton } from "@/components/run-dialog.tsx";
import { RunStatusBadge } from "@/components/run-status.tsx";
import { Card, CardContent } from "@/components/ui/card.tsx";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table.tsx";
import { formatDateTime, formatDuration, isOk } from "@/lib/format.ts";
import { listRuns } from "@/lib/runs.ts";

export const metadata: Metadata = { title: "Runs" };

export default async function RunsPage() {
	await connection();
	const runs = await listRuns();
	return (
		<>
			<PageHeader crumbs={[{ label: "Runs" }]} actions={<NewRunButton size="sm" />} />
			<main className="flex flex-col gap-6 p-4 md:p-6">
				<PageTitle
					title="Runs"
					description="Runs started from this UI, newest first. One run at a time per report directory."
				/>
				{runs.length === 0 ? (
					<Card className="items-center py-16 text-center">
						<History className="text-muted-foreground size-8" aria-hidden />
						<div>
							<p className="font-medium">No runs yet</p>
							<p className="text-muted-foreground text-sm">
								Start one with <kbd className="bg-muted rounded border px-1.5 font-mono text-xs">n</kbd> or the button.
							</p>
						</div>
						<NewRunButton />
					</Card>
				) : (
					<Card className="py-0">
						<CardContent className="px-0">
							<Table>
								<TableHeader>
									<TableRow>
										<TableHead className="w-32 pl-6">Status</TableHead>
										<TableHead>Run</TableHead>
										<TableHead className="text-right">Modules</TableHead>
										<TableHead className="hidden md:table-cell">Started</TableHead>
										<TableHead className="hidden text-right sm:table-cell">Duration</TableHead>
										<TableHead className="w-0 pr-6" />
									</TableRow>
								</TableHeader>
								<TableBody>
									{runs.map((r) => {
										const done = r.modules.filter((m) => m.state === "done" && m.outcome !== "not-run");
										const failed = done.filter((m) => !isOk(m.outcome)).length;
										return (
											<TableRow key={r.id}>
												<TableCell className="pl-6">
													<RunStatusBadge status={r.status} />
												</TableCell>
												<TableCell className="max-w-0 min-w-48">
													<Link href={`/runs/${r.id}`} className="font-mono text-sm font-medium hover:underline">
														{r.label}
													</Link>
													<p className="text-muted-foreground truncate font-mono text-[11px]">{r.command}</p>
												</TableCell>
												<TableCell className="text-right text-sm tabular-nums">
													{done.length}/{r.modules.length}
													{failed > 0 && <span className="text-failure ml-2 font-medium">{failed} failing</span>}
												</TableCell>
												<TableCell className="text-muted-foreground hidden text-sm md:table-cell">
													{formatDateTime(r.startedAt)}
												</TableCell>
												<TableCell className="text-muted-foreground hidden text-right text-sm tabular-nums sm:table-cell">
													{r.endedAt ? formatDuration(r.endedAt - r.startedAt) : "..."}
												</TableCell>
												<TableCell className="pr-6">
													<Link
														href={`/runs/${r.id}`}
														aria-label={`Open run ${r.label}`}
														className="hover:bg-accent text-muted-foreground inline-flex size-8 items-center justify-center rounded-md"
													>
														<ChevronRight className="size-4" />
													</Link>
												</TableCell>
											</TableRow>
										);
									})}
								</TableBody>
							</Table>
						</CardContent>
					</Card>
				)}
			</main>
		</>
	);
}
