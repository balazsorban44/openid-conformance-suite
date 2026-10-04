import { GeistMono } from "geist/font/mono";
import { GeistSans } from "geist/font/sans";
import type { Metadata } from "next";
import Script from "next/script";
import { AppSidebar, type SidebarProject } from "@/components/app-sidebar.tsx";
import { RunDialogProvider } from "@/components/run-dialog.tsx";
import { ThemeProvider } from "@/components/theme-toggle.tsx";
import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar.tsx";
import { Toaster } from "@/components/ui/sonner.tsx";
import { TooltipProvider } from "@/components/ui/tooltip.tsx";
import { listConfigs, planInfos, planKind, projects } from "@/lib/catalog.ts";
import { displayPath, reportDir } from "@/lib/paths.ts";
import { projectStatuses } from "@/lib/reports.ts";
import { THEME_SCRIPT } from "@/lib/theme-script.ts";
import "./globals.css";

export const metadata: Metadata = {
	title: { default: "OpenID Conformance", template: "%s · OpenID Conformance" },
	description: "Run the OpenID Connect conformance tests and read their logs",
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
	const statuses = await projectStatuses();
	const sidebarProjects: SidebarProject[] = statuses.map((s) => ({
		name: s.project.name,
		kind: s.kind,
		state: s.counts.failed > 0 ? "failed" : s.lastRunAt ? "ok" : "none",
	}));
	const catalog = {
		projects: projects.map((p) => ({ ...p, kind: planKind(p.plan) })),
		plans: planInfos(),
		configs: await listConfigs(),
	};
	return (
		<html lang="en" suppressHydrationWarning className={`${GeistSans.variable} ${GeistMono.variable}`}>
			<body>
				<Script id="theme" strategy="beforeInteractive">
					{THEME_SCRIPT}
				</Script>
				<ThemeProvider>
					<TooltipProvider delayDuration={200}>
						<RunDialogProvider catalog={catalog}>
							<SidebarProvider>
								<AppSidebar projects={sidebarProjects} reportDir={displayPath(reportDir)} />
								<SidebarInset className="min-w-0">{children}</SidebarInset>
							</SidebarProvider>
						</RunDialogProvider>
					</TooltipProvider>
					<Toaster richColors position="bottom-right" />
				</ThemeProvider>
			</body>
		</html>
	);
}
