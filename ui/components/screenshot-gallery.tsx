"use client";

import { ExternalLink } from "lucide-react";
import { useState } from "react";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog.tsx";

export interface Screenshot {
	name: string;
	url: string;
	/** what it shows (the REVIEW entry's message for a placeholder screenshot) */
	caption?: string;
}

/** Thumbnails of a module's screenshots; one opens large in a dialog */
export function ScreenshotGallery({ screenshots }: { screenshots: Screenshot[] }) {
	const [current, setCurrent] = useState<Screenshot | null>(null);
	return (
		<>
			<div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
				{screenshots.map((s) => (
					<button
						key={s.url}
						type="button"
						onClick={() => setCurrent(s)}
						className="group bg-muted/30 hover:border-foreground/20 focus-visible:ring-ring/50 overflow-hidden rounded-lg border text-left transition-colors outline-none focus-visible:ring-[3px]"
					>
						<div className="bg-muted aspect-[16/10] overflow-hidden border-b">
							{/* oxlint-disable-next-line nextjs/no-img-element -- screenshots served from the results directory */}
							<img
								src={s.url}
								alt={s.caption ?? s.name}
								loading="lazy"
								className="size-full object-cover object-top transition-transform duration-300 group-hover:scale-[1.02]"
							/>
						</div>
						<div className="px-3 py-2">
							<p className="truncate font-mono text-xs font-medium">{s.name}</p>
							{s.caption && <p className="text-muted-foreground line-clamp-2 text-xs">{s.caption}</p>}
						</div>
					</button>
				))}
			</div>
			<Dialog open={current != null} onOpenChange={(o) => !o && setCurrent(null)}>
				<DialogContent className="max-h-[92vh] overflow-auto sm:max-w-5xl">
					<DialogHeader>
						<DialogTitle className="font-mono text-sm">{current?.name}</DialogTitle>
						<DialogDescription className="flex items-center gap-3">
							{current?.caption}
							{current && (
								<a
									href={current.url}
									target="_blank"
									rel="noreferrer"
									className="inline-flex items-center gap-1 hover:underline"
								>
									Open <ExternalLink className="size-3" />
								</a>
							)}
						</DialogDescription>
					</DialogHeader>
					{/* oxlint-disable-next-line nextjs/no-img-element -- screenshots served from the results directory */}
					{current && (
						<img src={current.url} alt={current.caption ?? current.name} className="w-full rounded-md border" />
					)}
				</DialogContent>
			</Dialog>
		</>
	);
}
