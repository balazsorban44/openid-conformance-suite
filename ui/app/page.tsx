import { ArrowRight, CircleCheck, CircleX, Clock, FolderKanban, Play } from "lucide-react";
import Link from "next/link";
import { ModuleStrip } from "@/components/module-strip.tsx";
import { PageHeader, PageTitle } from "@/components/page-header.tsx";
import { OutcomeBadge } from "@/components/result-badge.tsx";
import { NewRunButton } from "@/components/run-dialog.tsx";
import { Badge } from "@/components/ui/badge.tsx";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card.tsx";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table.tsx";
import { plans } from "@/lib/catalog.ts";
import { formatRelative, moduleIntent, outcomeOf, stripModules } from "@/lib/format.ts";
import { displayPath, reportDir, resultsDir } from "@/lib/paths.ts";
import { projectStatuses } from "@/lib/reports.ts";

export default async function OverviewPage() {
	const statuses = await projectStatuses();
	const totals = statuses.reduce(
		(t, s) => ({ ok: t.ok + s.counts.ok, failed: t.failed + s.counts.failed, notRun: t.notRun + s.counts.notRun }),
		{ ok: 0, failed: 0, notRun: 0 },
	);
	const ran = statuses.filter((s) => s.lastRunAt != null);
	const last = ran.toSorted((a, b) => (b.lastRunAt ?? 0) - (a.lastRunAt ?? 0))[0];
	const attention = statuses.flatMap((s) =>
		s.modules
			.filter(
				(m) =>
					m.record &&
					outcomeOf(m.record.report) !== "passed" &&
					!["expected-failure", "skipped"].includes(outcomeOf(m.record.report)),
			)
			.map((m) => ({ project: s.project.name, module: m })),
	);

	return (
		<>
			<PageHeader crumbs={[{ label: "Overview" }]} actions={<NewRunButton size="sm" />} />
			<main className="flex flex-col gap-6 p-4 md:p-6">
				<PageTitle
					title="Overview"
					description={
						<>
							Latest result of every module per CI project, read from{" "}
							<code className="font-mono text-xs">{displayPath(reportDir)}</code> and{" "}
							<code className="font-mono text-xs">{displayPath(resultsDir)}</code>.
						</>
					}
				/>

				<div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
					<Stat
						icon={CircleCheck}
						tone="text-success"
						label="Modules OK"
						value={totals.ok}
						hint={`of ${totals.ok + totals.failed} that ran`}
					/>
					<Stat
						icon={CircleX}
						tone="text-failure"
						label="Modules failing"
						value={totals.failed}
						hint={totals.failed ? "unexpected results" : "nothing unexpected"}
					/>
					<Stat
						icon={FolderKanban}
						tone="text-info"
						label="Projects run"
						value={`${ran.length}/${statuses.length}`}
						hint={`${totals.notRun} modules not run yet`}
					/>
					<Stat
						icon={Clock}
						tone="text-muted-foreground"
						label="Last run"
						value={formatRelative(last?.lastRunAt)}
						hint={last ? last.project.name : "start one with New run"}
					/>
				</div>

				<Card className="gap-0 py-0">
					<CardHeader className="border-b py-4 [.border-b]:pb-4">
						<CardTitle>Projects</CardTitle>
						<CardDescription>
							The CI matrix: each project is a plan, a variant and a configuration with its bundled target.
						</CardDescription>
					</CardHeader>
					<CardContent className="px-0">
						<Table>
							<TableHeader>
								<TableRow>
									<TableHead className="pl-6">Project</TableHead>
									<TableHead className="hidden md:table-cell">Modules</TableHead>
									<TableHead className="text-right">OK</TableHead>
									<TableHead className="text-right">Failing</TableHead>
									<TableHead className="hidden text-right sm:table-cell">Not run</TableHead>
									<TableHead className="hidden lg:table-cell">Last run</TableHead>
									<TableHead className="w-0 pr-6" />
								</TableRow>
							</TableHeader>
							<TableBody>
								{statuses.map((s) => (
									<TableRow key={s.project.name} className="group">
										<TableCell className="pl-6">
											<div className="flex items-center gap-2">
												<Badge variant="outline" className="w-8 justify-center font-mono text-[10px]">
													{s.kind}
												</Badge>
												<div className="min-w-0">
													<Link
														href={`/projects/${s.project.name}`}
														className="font-mono text-sm font-medium hover:underline"
													>
														{s.project.name}
													</Link>
													<p className="text-muted-foreground max-w-[22rem] truncate text-xs">
														{plans[s.project.plan]?.title}
													</p>
												</div>
											</div>
										</TableCell>
										<TableCell className="hidden max-w-[16rem] md:table-cell">
											<ModuleStrip modules={stripModules(s.modules)} />
										</TableCell>
										<TableCell className="text-right tabular-nums">{s.counts.ok || <Dim />}</TableCell>
										<TableCell className="text-failure text-right font-medium tabular-nums">
											{s.counts.failed || <Dim />}
										</TableCell>
										<TableCell className="text-muted-foreground hidden text-right tabular-nums sm:table-cell">
											{s.counts.notRun || <Dim />}
										</TableCell>
										<TableCell className="text-muted-foreground hidden text-sm lg:table-cell">
											{formatRelative(s.lastRunAt)}
										</TableCell>
										<TableCell className="pr-6">
											<div className="flex justify-end gap-1">
												<NewRunButton
													size="icon"
													variant="ghost"
													className="size-8"
													aria-label={`Run ${s.project.name}`}
													prefill={{ kind: "project", project: s.project.name }}
												>
													<Play />
												</NewRunButton>
											</div>
										</TableCell>
									</TableRow>
								))}
							</TableBody>
						</Table>
					</CardContent>
				</Card>

				{attention.length > 0 && (
					<Card className="gap-0 py-0">
						<CardHeader className="border-b py-4 [.border-b]:pb-4">
							<CardTitle>Needs attention</CardTitle>
							<CardDescription>
								Modules whose latest result is not a pass: failures, warnings and screenshots to review.
							</CardDescription>
						</CardHeader>
						<CardContent className="divide-y px-0">
							{attention.map(({ project, module: m }) => (
								<Link
									key={`${project}/${m.name}`}
									href={`/modules/${m.record!.report.testId}`}
									className="hover:bg-muted/50 flex items-center gap-3 px-6 py-3 transition-colors"
								>
									<OutcomeBadge outcome={outcomeOf(m.record!.report)} className="w-28 justify-center" />
									<div className="min-w-0 flex-1">
										<p className="truncate font-mono text-sm">{m.name}</p>
										<p className="text-muted-foreground truncate text-xs">{moduleIntent(m.record!.report.title)}</p>
									</div>
									<span className="text-muted-foreground hidden font-mono text-xs sm:block">{project}</span>
									<ArrowRight className="text-muted-foreground size-4" />
								</Link>
							))}
						</CardContent>
					</Card>
				)}
			</main>
		</>
	);
}

function Dim() {
	return <span className="text-muted-foreground/40">-</span>;
}

function Stat({
	icon: Icon,
	tone,
	label,
	value,
	hint,
}: {
	icon: typeof Clock;
	tone: string;
	label: string;
	value: React.ReactNode;
	hint: string;
}) {
	return (
		<Card className="gap-2 py-4">
			<CardHeader className="flex flex-row items-center justify-between px-4">
				<CardDescription className="text-xs font-medium">{label}</CardDescription>
				<Icon className={`size-4 ${tone}`} aria-hidden />
			</CardHeader>
			<CardContent className="px-4">
				<div className="text-2xl font-semibold tabular-nums">{value}</div>
				<p className="text-muted-foreground truncate text-xs">{hint}</p>
			</CardContent>
		</Card>
	);
}
