import { FileCode2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { ModuleStrip } from "@/components/module-strip.tsx";
import { ModulesTable } from "@/components/modules-table.tsx";
import { PageHeader, PageTitle } from "@/components/page-header.tsx";
import { NewRunButton } from "@/components/run-dialog.tsx";
import { Badge } from "@/components/ui/badge.tsx";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card.tsx";
import { findProject, plans } from "@/lib/catalog.ts";
import { formatRelative, parseVariant, stripModules } from "@/lib/format.ts";
import { projectStatus, readModuleRecords } from "@/lib/reports.ts";

interface Props {
	params: Promise<{ name: string }>;
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
	return { title: (await params).name };
}

export default async function ProjectPage({ params }: Props) {
	const project = findProject((await params).name);
	if (!project) {
		notFound();
	}
	const status = projectStatus(project, await readModuleRecords());
	const plan = plans[project.plan];
	const ran = status.counts.ok + status.counts.failed;
	return (
		<>
			<PageHeader
				crumbs={[{ label: "Overview", href: "/" }, { label: project.name }]}
				actions={
					<NewRunButton size="sm" prefill={{ kind: "project", project: project.name }}>
						Run project
					</NewRunButton>
				}
			/>
			<main className="flex flex-col gap-6 p-4 md:p-6">
				<PageTitle
					title={<span className="font-mono">{project.name}</span>}
					description={
						<>
							<Link href={`/plans/${project.plan}`} className="hover:underline">
								{plan?.title}
							</Link>
						</>
					}
				>
					<div className="mt-2 flex flex-wrap items-center gap-1.5">
						<Badge variant="secondary">{status.kind === "OP" ? "OpenID Provider" : "Relying Party"}</Badge>
						{Object.entries(parseVariant(project.variant)).map(([k, v]) => (
							<Badge key={k} variant="outline" className="font-mono text-[11px] font-normal">
								{k}={v}
							</Badge>
						))}
						<span className="text-muted-foreground ml-1 inline-flex items-center gap-1 font-mono text-xs">
							<FileCode2 className="size-3.5" aria-hidden />
							{project.config}
						</span>
					</div>
				</PageTitle>

				<Card className="py-4">
					<CardContent className="flex flex-col gap-3 px-4">
						<div className="flex flex-wrap items-baseline gap-x-6 gap-y-1 text-sm">
							<span>
								<span className="text-2xl font-semibold tabular-nums">{status.counts.ok}</span>
								<span className="text-muted-foreground"> of {ran} OK</span>
							</span>
							{status.counts.failed > 0 && (
								<span className="text-failure font-medium">{status.counts.failed} failing</span>
							)}
							{status.counts.notRun > 0 && (
								<span className="text-muted-foreground">{status.counts.notRun} not run</span>
							)}
							<span className="text-muted-foreground ml-auto text-xs">last run {formatRelative(status.lastRunAt)}</span>
						</div>
						<ModuleStrip modules={stripModules(status.modules)} />
					</CardContent>
				</Card>

				<Card className="gap-0 py-0">
					<CardHeader className="border-b py-4 [.border-b]:pb-4">
						<CardTitle>Modules</CardTitle>
						<CardDescription>
							{plan?.modules.length} modules of <span className="font-mono">{project.plan}</span>, in plan order. The
							play button runs one module.
						</CardDescription>
					</CardHeader>
					<CardContent className="px-0">
						<ModulesTable modules={status.modules} runPrefill={{ kind: "project", project: project.name }} />
					</CardContent>
				</Card>
			</main>
		</>
	);
}
