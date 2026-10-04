import Link from "next/link";
import { PageHeader } from "@/components/page-header.tsx";
import { Button } from "@/components/ui/button.tsx";

export default function NotFound() {
	return (
		<>
			<PageHeader crumbs={[{ label: "Not found" }]} />
			<main className="flex flex-1 flex-col items-center justify-center gap-3 p-10 text-center">
				<p className="text-muted-foreground font-mono text-sm">404</p>
				<h1 className="text-xl font-semibold">Nothing here</h1>
				<p className="text-muted-foreground max-w-sm text-sm">
					The plan, project, run or module does not exist, or its results were removed from the report directory.
				</p>
				<Button asChild variant="outline" size="sm">
					<Link href="/">Back to the overview</Link>
				</Button>
			</main>
		</>
	);
}
