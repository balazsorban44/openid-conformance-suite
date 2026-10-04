"use client";

import { ChevronRight, ChevronsDownUp, ChevronsUpDown, Copy, Search } from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "sonner";
import { FieldValue } from "@/components/json-value.tsx";
import { LogResultBadge } from "@/components/result-badge.tsx";
import { Button } from "@/components/ui/button.tsx";
import { Input } from "@/components/ui/input.tsx";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs.tsx";
import { formatTime } from "@/lib/format.ts";
import { specLink } from "@/lib/spec-links.ts";
import type { LogEntry } from "@/lib/types.ts";
import { cn } from "@/lib/utils.ts";

/** Fields every entry has or that the row shows itself */
const ROW_FIELDS = new Set([
	"_id",
	"testId",
	"src",
	"time",
	"seq",
	"msg",
	"result",
	"requirements",
	"blockId",
	"startBlock",
	"http",
]);

/** The order HTTP fields are shown in (the rest follow alphabetically) */
const FIELD_ORDER = [
	"request_method",
	"request_uri",
	"request_headers",
	"request_body",
	"response_status_code",
	"response_status_text",
	"response_headers",
	"response_body",
	"incoming_method",
	"incoming_path",
	"incoming_query_string_params",
	"incoming_headers",
	"incoming_body",
	"incoming_body_json",
	"incoming_body_form_params",
	"outgoing_path",
	"outgoing_status_code",
	"outgoing_headers",
	"outgoing",
	"redirect_to",
	"img",
];

type Filter = "all" | "problems" | "conditions";

interface Block {
	id: string | null;
	title: string | null;
	start: LogEntry | null;
	entries: LogEntry[];
}

function blocks(entries: LogEntry[]): Block[] {
	const out: Block[] = [];
	let current: Block = { id: null, title: null, start: null, entries: [] };
	for (const e of entries) {
		if (e.src === "-START-BLOCK-") {
			if (current.entries.length > 0 || current.start) {
				out.push(current);
			}
			current = {
				id: typeof e["blockId"] === "string" ? e["blockId"] : null,
				title: String(e["msg"] ?? ""),
				start: e,
				entries: [],
			};
			continue;
		}
		const blockId = typeof e["blockId"] === "string" ? e["blockId"] : null;
		if (blockId !== current.id) {
			// an entry outside the open block: the block ended (upstream endBlock)
			if (current.entries.length > 0 || current.start) {
				out.push(current);
			}
			current = { id: blockId, title: null, start: null, entries: [] };
		}
		current.entries.push(e);
	}
	if (current.entries.length > 0 || current.start) {
		out.push(current);
	}
	return out;
}

function fieldRank(k: string): number {
	const i = FIELD_ORDER.indexOf(k);
	return i < 0 ? FIELD_ORDER.length : i;
}

function extraFields(e: LogEntry): [string, unknown][] {
	const fields = Object.entries(e).filter(([k]) => !ROW_FIELDS.has(k));
	return fields.sort(([a], [b]) => fieldRank(a) - fieldRank(b) || a.localeCompare(b));
}

/** One line under the message that says what an HTTP entry was */
function httpSummary(e: LogEntry): string | null {
	switch (e["http"]) {
		case "request":
			return `${String(e["request_method"] ?? "")} ${String(e["request_uri"] ?? "")}`;
		case "response":
			return `${String(e["response_status_code"] ?? "")} ${String(e["response_status_text"] ?? "")}`;
		case "incoming":
			return `${String(e["incoming_method"] ?? "")} ${String(e["incoming_path"] ?? "")}`;
		case "outgoing":
			return `${String(e["outgoing_status_code"] ?? "")} ${String(e["outgoing_path"] ?? "")}`;
		case "redirect":
			return `→ ${String(e["redirect_to"] ?? "")}`;
		default:
			return null;
	}
}

const PROBLEMS = new Set(["FAILURE", "WARNING", "REVIEW"]);

/**
 * A module's log like upstream's log page: entries in order under their block headings, with the condition, the
 * result, the message, the requirements and the details (HTTP exchanges, JSON) one click away.
 */
export function LogView({ entries, highlight }: { entries: LogEntry[]; highlight?: number[] }) {
	const [filter, setFilter] = useState<Filter>("all");
	const [query, setQuery] = useState("");
	const [open, setOpen] = useState<Set<number>>(() => new Set(highlight ?? []));
	const counts = useMemo(() => {
		const c: Record<string, number> = {};
		for (const e of entries) {
			if (typeof e["result"] === "string") {
				c[e["result"]] = (c[e["result"]] ?? 0) + 1;
			}
		}
		return c;
	}, [entries]);
	const visible = useMemo(() => {
		const q = query.trim().toLowerCase();
		return entries.filter((e) => {
			if (e.src === "-START-BLOCK-") {
				return true;
			}
			const result = typeof e["result"] === "string" ? e["result"] : "";
			if (filter === "problems" && !PROBLEMS.has(result)) {
				return false;
			}
			if (filter === "conditions" && !result) {
				return false;
			}
			return (
				!q || `${e.src} ${String(e["msg"] ?? "")} ${JSON.stringify(e["requirements"] ?? "")}`.toLowerCase().includes(q)
			);
		});
	}, [entries, filter, query]);
	const grouped = useMemo(
		() => blocks(visible).filter((b) => b.entries.length > 0 || filter === "all"),
		[visible, filter],
	);
	const expandable = useMemo(() => visible.filter((e) => extraFields(e).length > 0).map((e) => e.seq), [visible]);
	const allOpen = expandable.length > 0 && expandable.every((s) => open.has(s));
	const problems = (counts["FAILURE"] ?? 0) + (counts["WARNING"] ?? 0) + (counts["REVIEW"] ?? 0);

	const toggle = (seq: number) =>
		setOpen((o) => {
			const next = new Set(o);
			if (!next.delete(seq)) {
				next.add(seq);
			}
			return next;
		});

	return (
		<div className="flex flex-col">
			<div className="bg-card/95 sticky top-14 z-10 flex flex-wrap items-center gap-2 border-b px-4 py-3 backdrop-blur md:px-6">
				<Tabs value={filter} onValueChange={(v) => setFilter(v as Filter)}>
					<TabsList>
						<TabsTrigger value="all">All {entries.length}</TabsTrigger>
						<TabsTrigger value="conditions">Conditions</TabsTrigger>
						<TabsTrigger value="problems" disabled={problems === 0}>
							Problems {problems}
						</TabsTrigger>
					</TabsList>
				</Tabs>
				<div className="hidden items-center gap-1 lg:flex">
					{["SUCCESS", "INFO", "WARNING", "FAILURE", "REVIEW"].map((r) =>
						counts[r] ? (
							<span key={r} className="flex items-center gap-1">
								<LogResultBadge result={r} />
								<span className="text-muted-foreground mr-1 text-xs tabular-nums">{counts[r]}</span>
							</span>
						) : null,
					)}
				</div>
				<div className="relative ml-auto w-full sm:w-64">
					<Search className="text-muted-foreground absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2" aria-hidden />
					<Input
						value={query}
						onChange={(e) => setQuery(e.target.value)}
						placeholder="Filter by condition or message"
						className="h-8 pl-8 text-sm"
						aria-label="Filter the log"
					/>
				</div>
				<Button
					variant="outline"
					size="sm"
					className="h-8"
					onClick={() => setOpen(allOpen ? new Set() : new Set(expandable))}
					disabled={expandable.length === 0}
				>
					{allOpen ? <ChevronsDownUp /> : <ChevronsUpDown />}
					{allOpen ? "Collapse all" : "Expand all"}
				</Button>
			</div>

			{grouped.length === 0 && (
				<p className="text-muted-foreground px-6 py-10 text-center text-sm">No entry matches.</p>
			)}

			<div className="flex flex-col">
				{grouped.map((b, i) => (
					<section key={`${b.start?.seq ?? "top"}-${i}`} className="border-b last:border-b-0">
						{b.title != null && (
							<h3 className="bg-muted/40 flex items-center gap-2 px-4 py-2 text-sm font-semibold md:px-6">
								<span
									className="h-4 w-1 rounded-full"
									style={{ backgroundColor: b.id ? `#${b.id}` : undefined }}
									aria-hidden
								/>
								{b.title}
								<span className="text-muted-foreground ml-auto text-xs font-normal tabular-nums">
									{b.entries.length} {b.entries.length === 1 ? "entry" : "entries"}
								</span>
							</h3>
						)}
						<ol className="divide-y" style={b.id ? { borderLeft: `3px solid #${b.id}` } : undefined}>
							{b.entries.map((e) => (
								<EntryRow key={e._id} entry={e} open={open.has(e.seq)} onToggle={() => toggle(e.seq)} />
							))}
						</ol>
					</section>
				))}
			</div>
		</div>
	);
}

const ROW_TONE: Record<string, string> = {
	FAILURE: "bg-failure-soft/60",
	WARNING: "bg-warning-soft/60",
	REVIEW: "bg-review-soft/50",
};

function EntryRow({ entry: e, open, onToggle }: { entry: LogEntry; open: boolean; onToggle: () => void }) {
	const result = typeof e["result"] === "string" ? e["result"] : null;
	const requirements = Array.isArray(e["requirements"]) ? (e["requirements"] as string[]) : [];
	const fields = extraFields(e);
	const http = httpSummary(e);
	const img = typeof e["img"] === "string" ? e["img"] : null;
	const hasDetails = fields.some(([k]) => k !== "img");
	return (
		<li
			id={`entry-${e.seq}`}
			className={cn("scroll-mt-32 target:ring-2 target:ring-ring target:ring-inset", result && ROW_TONE[result])}
		>
			<div
				role={hasDetails ? "button" : undefined}
				tabIndex={hasDetails ? 0 : undefined}
				aria-expanded={hasDetails ? open : undefined}
				onClick={hasDetails ? onToggle : undefined}
				onKeyDown={
					hasDetails
						? (ev) => {
								if (ev.key === "Enter" || ev.key === " ") {
									ev.preventDefault();
									onToggle();
								}
							}
						: undefined
				}
				className={cn(
					"grid grid-cols-[1rem_minmax(0,1fr)] gap-x-2 gap-y-1 px-4 py-2 md:grid-cols-[1rem_6.5rem_minmax(0,16rem)_6.5rem_minmax(0,1fr)] md:px-6",
					hasDetails && "hover:bg-muted/40 focus-visible:bg-muted/40 cursor-pointer outline-none",
				)}
			>
				<ChevronRight
					className={cn(
						"text-muted-foreground mt-0.5 size-4 transition-transform",
						open && "rotate-90",
						!hasDetails && "invisible",
					)}
					aria-hidden
				/>
				<time className="text-muted-foreground hidden pt-0.5 font-mono text-[11px] tabular-nums md:block">
					{formatTime(e.time)}
				</time>
				<span className="truncate pt-0.5 font-mono text-xs font-medium" title={e.src}>
					{e.src}
				</span>
				<span className="col-start-2 md:col-start-auto">{result && <LogResultBadge result={result} />}</span>
				<div className="col-start-2 min-w-0 md:col-start-auto">
					<p className="text-sm break-words">{String(e["msg"] ?? "")}</p>
					{http && <p className="text-muted-foreground truncate font-mono text-[11px]">{http}</p>}
					{requirements.length > 0 && (
						<div className="mt-1 flex flex-wrap gap-1">
							{requirements.map((r) => {
								const href = specLink(r);
								return href ? (
									<a
										key={r}
										href={href}
										target="_blank"
										rel="noreferrer"
										onClick={(ev) => ev.stopPropagation()}
										className="bg-background hover:bg-accent rounded border px-1.5 py-px font-mono text-[10px] text-sky-700 dark:text-sky-300"
									>
										{r}
									</a>
								) : (
									<span key={r} className="bg-background rounded border px-1.5 py-px font-mono text-[10px]">
										{r}
									</span>
								);
							})}
						</div>
					)}
					{img && (
						// oxlint-disable-next-line nextjs/no-img-element -- a data: URL screenshot from the log
						<img
							src={img}
							alt={`Screenshot: ${String(e["msg"] ?? "")}`}
							className="mt-2 max-h-80 max-w-full rounded-md border shadow-sm"
						/>
					)}
				</div>
			</div>
			{open && hasDetails && <EntryDetails entry={e} fields={fields.filter(([k]) => k !== "img")} />}
		</li>
	);
}

function EntryDetails({ entry, fields }: { entry: LogEntry; fields: [string, unknown][] }) {
	return (
		<div className="flex flex-col gap-3 px-4 pt-1 pb-4 md:pr-6 md:pl-[calc(1.5rem+1rem+0.5rem)]">
			<dl className="grid gap-3">
				{fields.map(([k, v]) => (
					<div key={k} className="grid gap-1">
						<dt className="text-muted-foreground font-mono text-[11px]">{k}</dt>
						<dd className="min-w-0">
							<FieldValue value={v} />
						</dd>
					</div>
				))}
			</dl>
			<div className="flex items-center gap-3">
				<Button
					variant="ghost"
					size="sm"
					className="text-muted-foreground h-7 px-2 text-xs"
					onClick={() => {
						void navigator.clipboard
							.writeText(JSON.stringify(entry, null, 2))
							.then(() => toast.success("Copied the entry as JSON"));
					}}
				>
					<Copy className="size-3" /> Copy JSON
				</Button>
				<a href={`#entry-${entry.seq}`} className="text-muted-foreground font-mono text-[11px] hover:underline">
					{entry._id}
				</a>
			</div>
		</div>
	);
}
