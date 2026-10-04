import { ArrowRight } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { PageHeader, PageTitle } from "@/components/page-header.tsx";
import { NewRunButton } from "@/components/run-dialog.tsx";
import { Badge } from "@/components/ui/badge.tsx";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card.tsx";
import { planInfos } from "@/lib/catalog.ts";

export const metadata: Metadata = { title: "Plans" };

export default function PlansPage() {
	const infos = planInfos();
	return (
		<>
			<PageHeader crumbs={[{ label: "Plans" }]} actions={<NewRunButton size="sm" prefill={{ kind: "plan" }} />} />
			<main className="flex flex-col gap-6 p-4 md:p-6">
				<PageTitle
					title="Test plans"
					description="Every plan this suite implements: its spec file, its modules and the variant parameters you choose."
				/>
				{(["OP", "RP"] as const).map((kind) => (
					<section key={kind} className="flex flex-col gap-3">
						<h2 className="text-muted-foreground text-sm font-medium">
							{kind === "OP" ? "Testing an OpenID Provider" : "Testing a Relying Party"}
						</h2>
						<div className="grid gap-4 md:grid-cols-2 2xl:grid-cols-3">
							{infos
								.filter((p) => p.kind === kind)
								.map((p) => (
									<Link key={p.name} href={`/plans/${p.name}`} className="group focus-visible:outline-none">
										<Card className="group-hover:border-foreground/20 group-focus-visible:ring-ring/50 h-full gap-3 transition-colors group-focus-visible:ring-[3px]">
											<CardHeader>
												<CardTitle className="flex items-start justify-between gap-2 font-mono text-sm leading-snug break-words">
													{p.name}
													<ArrowRight className="text-muted-foreground mt-0.5 size-4 shrink-0 transition-transform group-hover:translate-x-0.5" />
												</CardTitle>
												<CardDescription>{p.title}</CardDescription>
											</CardHeader>
											<CardContent className="mt-auto flex flex-wrap items-center gap-1.5">
												<Badge variant="secondary">
													{p.modules.length} {p.modules.length === 1 ? "module" : "modules"}
												</Badge>
												{Object.keys(p.variants).map((k) => (
													<Badge key={k} variant="outline" className="font-mono text-[10px] font-normal">
														{k}
													</Badge>
												))}
												{p.projects.length > 0 && (
													<span className="text-muted-foreground ml-auto font-mono text-[11px]">
														{p.projects.join(", ")}
													</span>
												)}
											</CardContent>
										</Card>
									</Link>
								))}
						</div>
					</section>
				))}
			</main>
		</>
	);
}
