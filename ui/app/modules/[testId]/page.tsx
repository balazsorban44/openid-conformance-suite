import { CircleAlert, FileJson, FileText, Film, Footprints, ScrollText } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { LogView } from "@/components/log-view.tsx";
import { PageHeader, PageTitle } from "@/components/page-header.tsx";
import { LogResultBadge, OutcomeBadge, ResultText } from "@/components/result-badge.tsx";
import { NewRunButton, type RunPrefill } from "@/components/run-dialog.tsx";
import { ScreenshotGallery, type Screenshot } from "@/components/screenshot-gallery.tsx";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert.tsx";
import { Badge } from "@/components/ui/badge.tsx";
import { Button } from "@/components/ui/button.tsx";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card.tsx";
import { plans, projects } from "@/lib/catalog.ts";
import { fileUrl, formatDateTime, formatDuration, moduleIntent, outcomeOf } from "@/lib/format.ts";
import { findModuleRecord, readModuleFiles, recordInProject } from "@/lib/reports.ts";
import type { ConditionRef, LogEntry, ModuleAnalysis } from "@/lib/types.ts";

interface Props {
	params: Promise<{ testId: string }>;
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
	const record = await findModuleRecord((await params).testId);
	return { title: record?.report.testName ?? "Module" };
}

interface Finding {
	label: string;
	tone: "failure" | "warning" | "ok";
	refs: ConditionRef[];
}

/** The expected-failures analysis (src/suite/expected.ts findings) grouped for display */
function analysisFindings(a: ModuleAnalysis): {
	findings: Finding[];
	flags: { label: string; tone: Finding["tone"] }[];
} {
	const findings: Finding[] = [
		{ label: "Unexpected failures", tone: "failure" as const, refs: a.unexpected_failures },
		{ label: "Unexpected warnings", tone: "warning" as const, refs: a.unexpected_warnings },
		{
			label: "Expected failures that did not happen",
			tone: "failure" as const,
			refs: a.expected_failures_did_not_happen,
		},
		{
			label: "Expected warnings that did not happen",
			tone: "failure" as const,
			refs: a.expected_warnings_did_not_happen,
		},
		{ label: "Expected failures", tone: "ok" as const, refs: a.expected_failures },
		{ label: "Expected warnings", tone: "ok" as const, refs: a.expected_warnings },
	].filter((f) => f.refs.length > 0);
	const flags: { label: string; tone: Finding["tone"] }[] = [];
	if (a.unexpected_skip) {
		flags.push({ label: "The module was skipped, which the configuration does not expect", tone: "failure" });
	}
	if (a.expected_skip_did_not_happen) {
		flags.push({ label: "The configuration expects a skip that did not happen", tone: "failure" });
	}
	if (a.expected_skip) {
		flags.push({ label: "Skipped, as the configuration expects", tone: "ok" });
	}
	return { findings, flags };
}

function entryFor(log: LogEntry[] | null, ref: ConditionRef): LogEntry | undefined {
	return log?.find(
		(e) =>
			e.src === ref.src &&
			(e["result"] === "FAILURE" || e["result"] === "WARNING") &&
			(ref.msg == null || e["msg"] === ref.msg),
	);
}

function screenshotCaption(name: string, log: LogEntry[] | null): string | undefined {
	const placeholder = /^placeholder-(.+)\.png$/.exec(name)?.[1];
	if (placeholder) {
		const entry = log?.find((e) => e["upload"] === placeholder);
		return entry ? String(entry["msg"] ?? "") : undefined;
	}
	if (name.startsWith("webrunner-failure")) {
		return "The scripted browser's page when its task failed";
	}
	if (name.startsWith("test-failed")) {
		return "Playwright's screenshot when the test failed";
	}
	return undefined;
}

export default async function ModulePage({ params }: Props) {
	const record = await findModuleRecord((await params).testId);
	if (!record) {
		notFound();
	}
	const r = record.report;
	const files = await readModuleFiles(record);
	const project = projects.find((p) => record.dir && recordInProject(record, p));
	const outcome = outcomeOf(r);
	const { findings, flags } = analysisFindings(r.analysis);
	const highlight = findings
		.filter((f) => f.tone !== "ok")
		.flatMap((f) => f.refs.map((ref) => entryFor(files.log, ref)?.seq))
		.filter((s): s is number => s != null);
	const screenshots: Screenshot[] = files.screenshots.map((path) => {
		const name = path.split("/").at(-1) ?? path;
		return { name, url: fileUrl(path), caption: screenshotCaption(name, files.log) };
	});
	const prefill: RunPrefill = project
		? { kind: "project", project: project.name, module: r.testName }
		: { kind: "plan", plan: r.plan, module: r.testName };

	return (
		<>
			<PageHeader
				crumbs={[
					project
						? { label: project.name, href: `/projects/${project.name}` }
						: { label: r.plan, href: `/plans/${r.plan}` },
					{ label: r.testName },
				]}
				actions={
					<NewRunButton size="sm" variant="outline" prefill={prefill}>
						Run again
					</NewRunButton>
				}
			/>
			<main className="flex flex-col gap-6 p-4 md:p-6">
				<PageTitle
					title={<span className="font-mono text-xl break-words md:text-2xl">{r.testName}</span>}
					description={moduleIntent(r.title)}
				>
					<div className="mt-3 flex flex-wrap items-center gap-2">
						<OutcomeBadge outcome={outcome} className="h-6 px-2 text-xs" />
						<span className="text-muted-foreground text-xs">result</span>
						<ResultText result={r.result} />
						<span className="text-muted-foreground text-xs">status</span>
						<Badge variant="outline" className="font-mono text-[11px] font-normal">
							{r.status}
						</Badge>
						<span className="text-muted-foreground text-xs">
							{formatDuration(r.durationMs)}
							{record.finishedAt > 0 && <> · {formatDateTime(record.finishedAt)}</>} · test{" "}
							<span className="font-mono">{r.testId}</span>
						</span>
					</div>
				</PageTitle>

				<div className="grid gap-4 lg:grid-cols-3">
					<Card className="gap-3 py-4 lg:col-span-2">
						<CardHeader className="px-4">
							<CardTitle className="text-sm">Variant</CardTitle>
							<CardDescription>
								<Link href={`/plans/${r.plan}`} className="font-mono hover:underline">
									{r.plan}
								</Link>{" "}
								· {plans[r.plan]?.title}
							</CardDescription>
						</CardHeader>
						<CardContent className="flex flex-wrap gap-1.5 px-4">
							{Object.keys(r.variant).length === 0 && <span className="text-muted-foreground text-sm">none</span>}
							{Object.entries(r.variant).map(([k, v]) => (
								<Badge key={k} variant="outline" className="font-mono text-[11px] font-normal">
									<span className="text-muted-foreground">{k}=</span>
									{v}
								</Badge>
							))}
						</CardContent>
					</Card>
					<Card className="gap-3 py-4">
						<CardHeader className="px-4">
							<CardTitle className="text-sm">Files</CardTitle>
							<CardDescription>The module&apos;s log and recordings as the run wrote them.</CardDescription>
						</CardHeader>
						<CardContent className="flex flex-wrap gap-2 px-4">
							<FileLink path={files.logJson} icon={FileJson} label="log.json" />
							<FileLink path={files.logHtml} icon={ScrollText} label="log.html" />
							<FileLink path={files.targetOutput} icon={FileText} label="target output" />
							<FileLink path={files.video} icon={Film} label="video" />
							<FileLink path={files.trace} icon={Footprints} label="trace.zip" />
							{!files.logJson && (
								<span className="text-muted-foreground text-sm">
									The test directory is gone; only results.json has this module.
								</span>
							)}
						</CardContent>
					</Card>
				</div>

				{r.error && (
					<Alert variant="destructive">
						<CircleAlert />
						<AlertTitle>The test stopped with an error</AlertTitle>
						<AlertDescription>
							<pre className="font-mono text-xs break-all whitespace-pre-wrap">{r.error}</pre>
						</AlertDescription>
					</Alert>
				)}

				{(findings.length > 0 || flags.length > 0) && (
					<Card className="gap-0 py-0">
						<CardHeader className="border-b py-4 [.border-b]:pb-4">
							<CardTitle>Expected-failures analysis</CardTitle>
							<CardDescription>
								The log compared with the configuration&apos;s expected failures and skips, as upstream&apos;s CI does.{" "}
								{r.ok ? "Nothing unexpected: the module is OK." : "Something unexpected happened: the module fails."}
							</CardDescription>
						</CardHeader>
						<CardContent className="divide-y px-0">
							{flags.map((f) => (
								<p
									key={f.label}
									className={f.tone === "ok" ? "px-6 py-3 text-sm" : "text-failure px-6 py-3 text-sm font-medium"}
								>
									{f.label}
								</p>
							))}
							{findings.map((f) => (
								<div key={f.label} className="px-6 py-3">
									<p
										className={
											f.tone === "failure"
												? "text-failure text-sm font-medium"
												: f.tone === "warning"
													? "text-warning text-sm font-medium"
													: "text-success text-sm font-medium"
										}
									>
										{f.label}
									</p>
									<ul className="mt-2 flex flex-col gap-2">
										{f.refs.map((ref, i) => {
											const entry = entryFor(files.log, ref);
											return (
												<li key={i} className="flex flex-col gap-0.5 text-sm sm:flex-row sm:items-baseline sm:gap-3">
													{entry && typeof entry["result"] === "string" && (
														<LogResultBadge result={entry["result"]} className="self-start" />
													)}
													<span className="font-mono text-xs font-medium">{ref.src}</span>
													<span className="text-muted-foreground min-w-0 flex-1">
														{ref.msg}
														{ref.current_block && <span className="italic"> (in &quot;{ref.current_block}&quot;)</span>}
													</span>
													{entry && (
														<a href={`#entry-${entry.seq}`} className="text-xs whitespace-nowrap hover:underline">
															Show in log
														</a>
													)}
												</li>
											);
										})}
									</ul>
								</div>
							))}
						</CardContent>
					</Card>
				)}

				{screenshots.length > 0 && (
					<Card className="gap-4">
						<CardHeader>
							<CardTitle>Screenshots</CardTitle>
							<CardDescription>
								What the scripted browser saw: pages to review (upstream&apos;s images to upload) and failures.
							</CardDescription>
						</CardHeader>
						<CardContent>
							<ScreenshotGallery screenshots={screenshots} />
						</CardContent>
					</Card>
				)}

				<Card className="gap-0 py-0">
					<CardHeader className="border-b py-4 [.border-b]:pb-4">
						<CardTitle>Log</CardTitle>
						<CardDescription>
							{files.log
								? `${files.log.length} entries in the order the module logged them.`
								: "No log.json for this module."}
						</CardDescription>
					</CardHeader>
					{files.log && <LogView entries={files.log} highlight={highlight} />}
				</Card>
			</main>
		</>
	);
}

function FileLink({ path, icon: Icon, label }: { path: string | null; icon: typeof FileText; label: string }) {
	if (!path) {
		return null;
	}
	return (
		<Button asChild variant="outline" size="sm" className="h-7 text-xs">
			<a href={fileUrl(path)} target="_blank" rel="noreferrer">
				<Icon className="size-3.5" /> {label}
			</a>
		</Button>
	);
}
