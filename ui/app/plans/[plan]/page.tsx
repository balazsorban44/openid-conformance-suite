import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { ModulesTable } from "@/components/modules-table.tsx";
import { PageHeader, PageTitle } from "@/components/page-header.tsx";
import { NewRunButton } from "@/components/run-dialog.tsx";
import { Badge } from "@/components/ui/badge.tsx";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card.tsx";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table.tsx";
import { planInfos, projects } from "@/lib/catalog.ts";
import { parseVariant } from "@/lib/format.ts";
import { latestByModule, readModuleRecords } from "@/lib/reports.ts";

interface Props {
	params: Promise<{ plan: string }>;
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
	return { title: (await params).plan };
}

export default async function PlanPage({ params }: Props) {
	const name = (await params).plan;
	const plan = planInfos().find((p) => p.name === name);
	if (!plan) {
		notFound();
	}
	const latest = latestByModule(plan.name, await readModuleRecords());
	const modules = plan.modules.map((m) => ({ name: m, record: latest.get(m) ?? null }));
	const planProjects = projects.filter((p) => p.plan === plan.name);
	return (
		<>
			<PageHeader
				crumbs={[{ label: "Plans", href: "/plans" }, { label: plan.name }]}
				actions={
					<NewRunButton size="sm" prefill={{ kind: "plan", plan: plan.name }}>
						Run plan
					</NewRunButton>
				}
			/>
			<main className="flex flex-col gap-6 p-4 md:p-6">
				<PageTitle
					title={<span className="font-mono text-xl break-words md:text-2xl">{plan.name}</span>}
					description={plan.title}
				>
					<div className="mt-2 flex flex-wrap gap-1.5">
						<Badge variant="secondary">{plan.kind === "OP" ? "OpenID Provider" : "Relying Party"}</Badge>
						<Badge variant="outline" className="font-mono text-[11px] font-normal">
							{plan.spec}
						</Badge>
					</div>
				</PageTitle>

				<div className="grid gap-4 lg:grid-cols-2">
					<Card className="gap-0 py-0">
						<CardHeader className="border-b py-4 [.border-b]:pb-4">
							<CardTitle>Variant parameters</CardTitle>
							<CardDescription>
								What you choose when you run the plan (`--variant k=v`); the spec fixes the rest.
							</CardDescription>
						</CardHeader>
						<CardContent className="px-0">
							{Object.keys(plan.variants).length === 0 ? (
								<p className="text-muted-foreground px-6 py-4 text-sm">None: the plan runs as it is.</p>
							) : (
								<Table>
									<TableBody>
										{Object.entries(plan.variants).map(([k, values]) => (
											<TableRow key={k}>
												<TableCell className="pl-6 font-mono text-xs font-medium">{k}</TableCell>
												<TableCell className="pr-6">
													<div className="flex flex-wrap gap-1">
														{values.map((v) => (
															<Badge key={v} variant="outline" className="font-mono text-[10px] font-normal">
																{v}
															</Badge>
														))}
													</div>
												</TableCell>
											</TableRow>
										))}
									</TableBody>
								</Table>
							)}
						</CardContent>
					</Card>
					<Card className="gap-0 py-0">
						<CardHeader className="border-b py-4 [.border-b]:pb-4">
							<CardTitle>CI projects</CardTitle>
							<CardDescription>The configurations this repository runs the plan with.</CardDescription>
						</CardHeader>
						<CardContent className="px-0">
							{planProjects.length === 0 ? (
								<p className="text-muted-foreground px-6 py-4 text-sm">None.</p>
							) : (
								<Table>
									<TableHeader>
										<TableRow>
											<TableHead className="pl-6">Project</TableHead>
											<TableHead className="pr-6">Variant</TableHead>
										</TableRow>
									</TableHeader>
									<TableBody>
										{planProjects.map((p) => (
											<TableRow key={p.name}>
												<TableCell className="pl-6">
													<Link href={`/projects/${p.name}`} className="font-mono text-sm hover:underline">
														{p.name}
													</Link>
												</TableCell>
												<TableCell className="pr-6">
													<div className="flex flex-wrap gap-1">
														{Object.entries(parseVariant(p.variant)).map(([k, v]) => (
															<Badge key={k} variant="outline" className="font-mono text-[10px] font-normal">
																{k}={v}
															</Badge>
														))}
													</div>
												</TableCell>
											</TableRow>
										))}
									</TableBody>
								</Table>
							)}
						</CardContent>
					</Card>
				</div>

				<Card className="gap-0 py-0">
					<CardHeader className="border-b py-4 [.border-b]:pb-4">
						<CardTitle>Modules</CardTitle>
						<CardDescription>The latest result of each module in any variant or project.</CardDescription>
					</CardHeader>
					<CardContent className="px-0">
						<ModulesTable modules={modules} showVariant runPrefill={{ kind: "plan", plan: plan.name }} />
					</CardContent>
				</Card>
			</main>
		</>
	);
}
