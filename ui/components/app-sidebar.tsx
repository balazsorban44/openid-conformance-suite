"use client";

import { History, LayoutDashboard, ListChecks, Loader2, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import {
	Sidebar,
	SidebarContent,
	SidebarFooter,
	SidebarGroup,
	SidebarGroupContent,
	SidebarGroupLabel,
	SidebarHeader,
	SidebarMenu,
	SidebarMenuBadge,
	SidebarMenuButton,
	SidebarMenuItem,
	SidebarRail,
} from "@/components/ui/sidebar.tsx";
import { cn } from "@/lib/utils.ts";

export interface SidebarProject {
	name: string;
	kind: "OP" | "RP";
	/** ok: every module that ran is fine; failed: one is not; none: nothing ran yet */
	state: "ok" | "failed" | "none";
}

const NAV = [
	{ href: "/", label: "Overview", icon: LayoutDashboard },
	{ href: "/plans", label: "Plans", icon: ListChecks },
	{ href: "/runs", label: "Runs", icon: History },
];

const STATE_DOT: Record<SidebarProject["state"], string> = {
	ok: "bg-success",
	failed: "bg-failure",
	none: "bg-muted-foreground/25",
};

export function AppSidebar({
	projects,
	reportDir,
	hosted = false,
}: {
	projects: SidebarProject[];
	reportDir: string;
	/** the hosted UI is read-only: no run to poll for, and the directory is the bundled sample data */
	hosted?: boolean;
}) {
	const pathname = usePathname();
	const active = useActiveRun(!hosted);
	const isActive = (href: string) => (href === "/" ? pathname === "/" : pathname.startsWith(href));
	return (
		<Sidebar collapsible="icon">
			<SidebarHeader>
				<SidebarMenu>
					<SidebarMenuItem>
						<SidebarMenuButton size="lg" asChild>
							<Link href="/">
								<div className="bg-sidebar-primary text-sidebar-primary-foreground flex aspect-square size-8 items-center justify-center rounded-lg">
									<ShieldCheck className="size-4" />
								</div>
								<div className="grid flex-1 text-left text-sm leading-tight">
									<span className="truncate font-semibold">OpenID Conformance</span>
									<span className="text-muted-foreground truncate text-xs">OpenID Connect Core</span>
								</div>
							</Link>
						</SidebarMenuButton>
					</SidebarMenuItem>
				</SidebarMenu>
			</SidebarHeader>
			<SidebarContent>
				<SidebarGroup>
					<SidebarGroupContent>
						<SidebarMenu>
							{NAV.map((item) => (
								<SidebarMenuItem key={item.href}>
									<SidebarMenuButton asChild isActive={isActive(item.href)} tooltip={item.label}>
										<Link href={item.href}>
											<item.icon />
											<span>{item.label}</span>
										</Link>
									</SidebarMenuButton>
									{item.href === "/runs" && active && (
										<SidebarMenuBadge>
											<Loader2 className="text-info size-3.5 animate-spin" />
										</SidebarMenuBadge>
									)}
								</SidebarMenuItem>
							))}
						</SidebarMenu>
					</SidebarGroupContent>
				</SidebarGroup>
				{(["OP", "RP"] as const).map((kind) => (
					<SidebarGroup key={kind} className="group-data-[collapsible=icon]:hidden">
						<SidebarGroupLabel>
							{kind === "OP" ? "OpenID Provider projects" : "Relying Party projects"}
						</SidebarGroupLabel>
						<SidebarGroupContent>
							<SidebarMenu>
								{projects
									.filter((p) => p.kind === kind)
									.map((p) => (
										<SidebarMenuItem key={p.name}>
											<SidebarMenuButton asChild size="sm" isActive={pathname === `/projects/${p.name}`}>
												<Link href={`/projects/${p.name}`}>
													<span
														className={cn("size-2 shrink-0 rounded-full", STATE_DOT[p.state])}
														aria-label={p.state === "ok" ? "all ok" : p.state === "failed" ? "failing" : "not run"}
													/>
													<span className="font-mono text-xs">{p.name}</span>
												</Link>
											</SidebarMenuButton>
											{active?.project === p.name && (
												<SidebarMenuBadge>
													<Loader2 className="text-info size-3 animate-spin" />
												</SidebarMenuBadge>
											)}
										</SidebarMenuItem>
									))}
							</SidebarMenu>
						</SidebarGroupContent>
					</SidebarGroup>
				))}
			</SidebarContent>
			<SidebarFooter className="group-data-[collapsible=icon]:hidden">
				{active && (
					<Link
						href={`/runs/${active.id}`}
						className="bg-info-soft text-info flex items-center gap-2 rounded-md px-2 py-1.5 text-xs font-medium"
					>
						<Loader2 className="size-3.5 animate-spin" />
						<span className="truncate">Running {active.label}</span>
					</Link>
				)}
				<p className="text-muted-foreground truncate px-2 font-mono text-[10px]" title={reportDir}>
					{hosted ? "bundled sample results" : reportDir}
				</p>
			</SidebarFooter>
			<SidebarRail />
		</Sidebar>
	);
}

interface ActiveRun {
	id: string;
	label: string;
	project?: string;
}

/** The run in progress (polled, unless `enabled` is false); refreshes the server-rendered pages when it ends */
function useActiveRun(enabled: boolean): ActiveRun | null {
	const router = useRouter();
	const [active, setActive] = useState<ActiveRun | null>(null);
	const last = useRef<string | null>(null);
	useEffect(() => {
		if (!enabled) {
			return;
		}
		let stopped = false;
		const poll = async () => {
			if (document.visibilityState !== "visible") {
				return;
			}
			try {
				const res = await fetch("/api/runs", { cache: "no-store" });
				const body = (await res.json()) as {
					active: string | null;
					runs: { id: string; label: string; request: { kind: string; project?: string } }[];
				};
				const run = body.runs.find((r) => r.id === body.active);
				if (stopped) {
					return;
				}
				setActive(run ? { id: run.id, label: run.label, project: run.request.project } : null);
				if (last.current && !body.active) {
					router.refresh();
				}
				last.current = body.active;
			} catch {
				// the server is restarting
			}
		};
		void poll();
		const timer = setInterval(poll, 2000);
		return () => {
			stopped = true;
			clearInterval(timer);
		};
	}, [router, enabled]);
	return active;
}
