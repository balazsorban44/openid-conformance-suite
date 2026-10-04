"use client";

// a client component: Radix's Slot (TooltipTrigger asChild) needs its child to be an element, and an element a
// server component passes to a client component can arrive as a lazy reference
import Link from "next/link";
import { OUTCOME_DOT } from "@/components/result-badge.tsx";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip.tsx";
import { OUTCOME_LABEL } from "@/lib/format.ts";
import type { StripModule } from "@/lib/types.ts";
import { cn } from "@/lib/utils.ts";

/** One square per module, coloured by its latest outcome (the plan's "visual overview") */
export function ModuleStrip({ modules, className }: { modules: StripModule[]; className?: string }) {
	return (
		<div className={cn("flex flex-wrap gap-[3px]", className)}>
			{modules.map((m) => {
				const label = `${m.name}: ${m.note ?? OUTCOME_LABEL[m.outcome]}`;
				const square = (
					<span
						className={cn("block size-2.5 rounded-[3px] transition-transform hover:scale-125", OUTCOME_DOT[m.outcome])}
					/>
				);
				return (
					<Tooltip key={m.name}>
						<TooltipTrigger asChild>
							{m.testId ? (
								<Link href={`/modules/${m.testId}`} aria-label={label}>
									{square}
								</Link>
							) : (
								<span aria-label={label}>{square}</span>
							)}
						</TooltipTrigger>
						<TooltipContent>
							<span className="font-mono">{m.name}</span> · {m.note ?? OUTCOME_LABEL[m.outcome]}
						</TooltipContent>
					</Tooltip>
				);
			})}
		</div>
	);
}
