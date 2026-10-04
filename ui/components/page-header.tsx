import Link from "next/link";
import { Fragment } from "react";
import { ThemeToggle } from "@/components/theme-toggle.tsx";
import {
	Breadcrumb,
	BreadcrumbItem,
	BreadcrumbLink,
	BreadcrumbList,
	BreadcrumbPage,
	BreadcrumbSeparator,
} from "@/components/ui/breadcrumb.tsx";
import { Separator } from "@/components/ui/separator.tsx";
import { SidebarTrigger } from "@/components/ui/sidebar.tsx";

export interface Crumb {
	label: string;
	href?: string;
}

/** The bar above every page: sidebar toggle, breadcrumbs, the page's actions and the theme switch */
export function PageHeader({ crumbs, actions }: { crumbs: Crumb[]; actions?: React.ReactNode }) {
	return (
		<header className="bg-background/80 sticky top-0 z-20 flex h-14 shrink-0 items-center gap-2 border-b px-4 backdrop-blur">
			<SidebarTrigger className="-ml-1" />
			<Separator orientation="vertical" className="mr-1 data-[orientation=vertical]:h-4" />
			<Breadcrumb className="min-w-0 flex-1">
				<BreadcrumbList className="flex-nowrap">
					{crumbs.map((c, i) => (
						<Fragment key={i}>
							{i > 0 && <BreadcrumbSeparator className="hidden sm:block" />}
							<BreadcrumbItem className={i < crumbs.length - 1 ? "hidden sm:inline-flex" : "min-w-0"}>
								{c.href && i < crumbs.length - 1 ? (
									<BreadcrumbLink asChild>
										<Link href={c.href}>{c.label}</Link>
									</BreadcrumbLink>
								) : (
									<BreadcrumbPage className="truncate">{c.label}</BreadcrumbPage>
								)}
							</BreadcrumbItem>
						</Fragment>
					))}
				</BreadcrumbList>
			</Breadcrumb>
			<div className="flex items-center gap-2">
				{actions}
				<ThemeToggle />
			</div>
		</header>
	);
}

/** Title block at the top of a page's content */
export function PageTitle({
	title,
	description,
	children,
}: {
	title: React.ReactNode;
	description?: React.ReactNode;
	children?: React.ReactNode;
}) {
	return (
		<div className="flex flex-col gap-1.5">
			<h1 className="text-2xl font-semibold tracking-tight break-words">{title}</h1>
			{description && <div className="text-muted-foreground text-sm">{description}</div>}
			{children}
		</div>
	);
}
