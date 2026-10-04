"use client";

import { Play, Terminal } from "lucide-react";
import { useRouter } from "next/navigation";
import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge.tsx";
import { Button } from "@/components/ui/button.tsx";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogFooter,
	DialogHeader,
	DialogTitle,
} from "@/components/ui/dialog.tsx";
import { Input } from "@/components/ui/input.tsx";
import { Label } from "@/components/ui/label.tsx";
import {
	Select,
	SelectContent,
	SelectGroup,
	SelectItem,
	SelectLabel,
	SelectTrigger,
	SelectValue,
} from "@/components/ui/select.tsx";
import { Switch } from "@/components/ui/switch.tsx";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs.tsx";
import { globMatch, parseVariant } from "@/lib/format.ts";
import type { ConformanceProject, PlanInfo, RunRequest } from "@/lib/types.ts";

export interface RunCatalog {
	projects: (ConformanceProject & { kind: "OP" | "RP" })[];
	plans: PlanInfo[];
	configs: string[];
}

export type RunPrefill =
	| { kind: "project"; project?: string; module?: string }
	| { kind: "plan"; plan?: string; config?: string; module?: string };

const RunDialogContext = createContext<{ open: (prefill?: RunPrefill) => void } | null>(null);

export function useRunDialog(): { open: (prefill?: RunPrefill) => void } {
	const ctx = useContext(RunDialogContext);
	if (!ctx) {
		throw new Error("useRunDialog() outside <RunDialogProvider>");
	}
	return ctx;
}

/** Holds the "new run" dialog; `n` opens it from anywhere (outside text fields) */
export function RunDialogProvider({ catalog, children }: { catalog: RunCatalog; children: React.ReactNode }) {
	const [open, setOpen] = useState(false);
	const [prefill, setPrefill] = useState<RunPrefill>({ kind: "project" });
	const [key, setKey] = useState(0);
	const value = useMemo(
		() => ({
			open: (p?: RunPrefill) => {
				setPrefill(p ?? { kind: "project" });
				setKey((k) => k + 1);
				setOpen(true);
			},
		}),
		[],
	);
	useEffect(() => {
		const onKey = (e: KeyboardEvent) => {
			const t = e.target as HTMLElement | null;
			if (
				e.key === "n" &&
				!e.metaKey &&
				!e.ctrlKey &&
				!e.altKey &&
				!(t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName)))
			) {
				e.preventDefault();
				value.open();
			}
		};
		window.addEventListener("keydown", onKey);
		return () => window.removeEventListener("keydown", onKey);
	}, [value]);
	return (
		<RunDialogContext.Provider value={value}>
			{children}
			<Dialog open={open} onOpenChange={setOpen}>
				<DialogContent className="sm:max-w-xl">
					<RunForm key={key} catalog={catalog} prefill={prefill} onStarted={() => setOpen(false)} />
				</DialogContent>
			</Dialog>
		</RunDialogContext.Provider>
	);
}

export function NewRunButton({
	prefill,
	children,
	...props
}: { prefill?: RunPrefill; children?: React.ReactNode } & Omit<React.ComponentProps<typeof Button>, "onClick">) {
	const { open } = useRunDialog();
	return (
		<Button {...props} onClick={() => open(prefill)}>
			{children ?? (
				<>
					<Play /> New run
				</>
			)}
		</Button>
	);
}

const DEFAULT = "__default";

/** A plan's form defaults: the configuration and variant of its first CI project */
function planDefaults(catalog: RunCatalog, plan: string): { config: string; variant: Record<string, string> } {
	const project = catalog.projects.find((x) => x.plan === plan);
	const selectable = catalog.plans.find((p) => p.name === plan)?.variants ?? {};
	return {
		config: project?.config ?? "",
		variant: Object.fromEntries(Object.entries(parseVariant(project?.variant ?? "")).filter(([k]) => k in selectable)),
	};
}

function RunForm({ catalog, prefill, onStarted }: { catalog: RunCatalog; prefill: RunPrefill; onStarted: () => void }) {
	const router = useRouter();
	const [kind, setKind] = useState<RunRequest["kind"]>(prefill.kind);
	const [project, setProject] = useState(
		(prefill.kind === "project" && prefill.project) || catalog.projects[0]?.name || "",
	);
	const initialPlan = (prefill.kind === "plan" && prefill.plan) || catalog.plans[0]?.name || "";
	const [plan, setPlan] = useState(initialPlan);
	const [config, setConfig] = useState(
		(prefill.kind === "plan" && prefill.config) || planDefaults(catalog, initialPlan).config,
	);
	const [variant, setVariant] = useState(() => planDefaults(catalog, initialPlan).variant);
	const [module, setModule] = useState(prefill.module ?? "");
	const [tls, setTls] = useState(true);
	const [verbose, setVerbose] = useState(true);
	const [video, setVideo] = useState(false);
	const [busy, setBusy] = useState(false);

	const selectedProject = catalog.projects.find((p) => p.name === project);
	const selectedPlan = catalog.plans.find((p) => p.name === (kind === "project" ? selectedProject?.plan : plan));
	const modules = selectedPlan?.modules ?? [];
	const matching = module.trim() ? modules.filter((m) => globMatch(module.trim(), m)).length : modules.length;

	const request: RunRequest =
		kind === "project"
			? { kind, project, module: module.trim() || undefined, options: { verbose, video } }
			: { kind, plan, config, variant, module: module.trim() || undefined, tls, options: { verbose, video } };

	const preview =
		kind === "project"
			? `node bin/cli.ts ci --project ${project}`
			: [
					`node bin/cli.ts run --plan ${plan} --config ${config || "<config>"}`,
					...Object.entries(variant)
						.filter(([, v]) => v)
						.map(([k, v]) => `--variant ${k}=${v}`),
					module.trim() ? `--module '${module.trim()}'` : "",
					tls ? "--tls" : "",
				]
					.filter(Boolean)
					.join(" ");

	async function submit(e: React.FormEvent) {
		e.preventDefault();
		setBusy(true);
		try {
			const res = await fetch("/api/runs", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify(request),
			});
			const body = (await res.json()) as { run?: { id: string; label: string }; error?: string; runId?: string };
			if (!res.ok || !body.run) {
				toast.error("Could not start the run", {
					description: body.error,
					action: body.runId ? { label: "View run", onClick: () => router.push(`/runs/${body.runId}`) } : undefined,
				});
				return;
			}
			toast.success(`Started ${body.run.label}`);
			onStarted();
			router.push(`/runs/${body.run.id}`);
		} catch (err) {
			toast.error("Could not start the run", { description: String(err) });
		} finally {
			setBusy(false);
		}
	}

	return (
		<form onSubmit={submit} className="grid gap-5">
			<DialogHeader>
				<DialogTitle>New run</DialogTitle>
				<DialogDescription>
					Run a CI project against its bundled target, or a test plan with a configuration of your own.
				</DialogDescription>
			</DialogHeader>

			<Tabs value={kind} onValueChange={(v) => setKind(v as RunRequest["kind"])}>
				<TabsList className="grid w-full grid-cols-2">
					<TabsTrigger value="project">CI project</TabsTrigger>
					<TabsTrigger value="plan">Test plan</TabsTrigger>
				</TabsList>
			</Tabs>

			{kind === "project" ? (
				<div className="grid gap-2">
					<Label htmlFor="run-project">Project</Label>
					<Select value={project} onValueChange={setProject}>
						<SelectTrigger id="run-project" className="w-full">
							<SelectValue placeholder="Select a project" />
						</SelectTrigger>
						<SelectContent>
							{(["OP", "RP"] as const).map((k) => (
								<SelectGroup key={k}>
									<SelectLabel>{k === "OP" ? "OpenID Provider plans" : "Relying Party plans"}</SelectLabel>
									{catalog.projects
										.filter((p) => p.kind === k)
										.map((p) => (
											<SelectItem key={p.name} value={p.name}>
												{p.name}
											</SelectItem>
										))}
								</SelectGroup>
							))}
						</SelectContent>
					</Select>
					{selectedProject && (
						<div className="text-muted-foreground flex flex-wrap items-center gap-1.5 text-xs">
							<span className="font-mono">{selectedProject.plan}</span>
							{Object.entries(parseVariant(selectedProject.variant)).map(([k, v]) => (
								<Badge key={k} variant="outline" className="font-mono text-[10px] font-normal">
									{k}={v}
								</Badge>
							))}
						</div>
					)}
				</div>
			) : (
				<>
					<div className="grid gap-2">
						<Label htmlFor="run-plan">Plan</Label>
						<Select
							value={plan}
							onValueChange={(v) => {
								const defaults = planDefaults(catalog, v);
								setPlan(v);
								setConfig(defaults.config);
								setVariant(defaults.variant);
							}}
						>
							<SelectTrigger id="run-plan" className="w-full">
								<SelectValue placeholder="Select a plan" />
							</SelectTrigger>
							<SelectContent>
								{catalog.plans.map((p) => (
									<SelectItem key={p.name} value={p.name}>
										<span className="font-mono text-xs">{p.name}</span>
									</SelectItem>
								))}
							</SelectContent>
						</Select>
						{selectedPlan && <p className="text-muted-foreground text-xs">{selectedPlan.title}</p>}
					</div>
					<div className="grid gap-2">
						<Label htmlFor="run-config">Configuration</Label>
						<Input
							id="run-config"
							list="run-configs"
							value={config}
							onChange={(e) => setConfig(e.target.value)}
							placeholder="configs/oidc-provider/oidcc-basic-dynamic.json"
							className="font-mono text-xs"
							required
						/>
						<datalist id="run-configs">
							{catalog.configs.map((c) => (
								<option key={c} value={c} />
							))}
						</datalist>
					</div>
					{selectedPlan && Object.keys(selectedPlan.variants).length > 0 && (
						<div className="grid gap-3 sm:grid-cols-2">
							{Object.entries(selectedPlan.variants).map(([k, values]) => (
								<div key={k} className="grid gap-2">
									<Label htmlFor={`run-variant-${k}`} className="font-mono text-xs">
										{k}
									</Label>
									<Select
										value={variant[k] || DEFAULT}
										onValueChange={(v) => setVariant((x) => ({ ...x, [k]: v === DEFAULT ? "" : v }))}
									>
										<SelectTrigger id={`run-variant-${k}`} className="w-full font-mono text-xs">
											<SelectValue />
										</SelectTrigger>
										<SelectContent>
											<SelectItem value={DEFAULT}>
												<span className="text-muted-foreground">not set</span>
											</SelectItem>
											{values.map((v) => (
												<SelectItem key={v} value={v} className="font-mono text-xs">
													{v}
												</SelectItem>
											))}
										</SelectContent>
									</Select>
								</div>
							))}
						</div>
					)}
				</>
			)}

			<div className="grid gap-2">
				<div className="flex items-baseline justify-between">
					<Label htmlFor="run-module">Modules</Label>
					<span className="text-muted-foreground text-xs tabular-nums">
						{matching} of {modules.length} modules
					</span>
				</div>
				<Input
					id="run-module"
					list="run-modules"
					value={module}
					onChange={(e) => setModule(e.target.value)}
					placeholder="all modules, or a glob such as oidcc-server*"
					className="font-mono text-xs"
				/>
				<datalist id="run-modules">
					{modules.map((m) => (
						<option key={m} value={m} />
					))}
				</datalist>
			</div>

			<div className="grid gap-3 rounded-lg border p-3">
				<Toggle
					id="run-verbose"
					checked={verbose}
					onChange={setVerbose}
					label="Stream the condition log to the console"
				/>
				<Toggle id="run-video" checked={video} onChange={setVideo} label="Keep a video of failing modules" />
				{kind === "plan" && (
					<Toggle
						id="run-tls"
						checked={tls}
						onChange={setTls}
						label="Serve the suite over https (bundled certificate)"
					/>
				)}
			</div>

			<div className="bg-muted/60 text-muted-foreground flex items-start gap-2 rounded-md px-3 py-2 font-mono text-[11px] leading-relaxed break-all">
				<Terminal className="mt-0.5 size-3.5 shrink-0" aria-hidden />
				{preview}
			</div>

			<DialogFooter>
				<Button type="submit" disabled={busy || matching === 0 || (kind === "plan" && !config)}>
					<Play /> {busy ? "Starting..." : "Start run"}
				</Button>
			</DialogFooter>
		</form>
	);
}

function Toggle({
	id,
	checked,
	onChange,
	label,
}: {
	id: string;
	checked: boolean;
	onChange: (v: boolean) => void;
	label: string;
}) {
	return (
		<div className="flex items-center justify-between gap-4">
			<Label htmlFor={id} className="text-sm font-normal">
				{label}
			</Label>
			<Switch id={id} checked={checked} onCheckedChange={onChange} />
		</div>
	);
}
