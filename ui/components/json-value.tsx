import { cn } from "@/lib/utils.ts";

/** Pretty JSON with light syntax colouring */
export function JsonBlock({ value, className }: { value: unknown; className?: string }) {
	const text = typeof value === "string" ? value : JSON.stringify(value, null, 2);
	const parts: React.ReactNode[] = [];
	const re = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;
	let last = 0;
	let m: RegExpExecArray | null;
	while ((m = re.exec(text))) {
		if (m.index > last) {
			parts.push(text.slice(last, m.index));
		}
		if (m[1]) {
			parts.push(
				<span
					key={m.index}
					className={m[2] ? "text-sky-700 dark:text-sky-300" : "text-emerald-700 dark:text-emerald-300"}
				>
					{m[1]}
				</span>,
			);
			if (m[2]) {
				parts.push(m[2]);
			}
		} else if (m[3]) {
			parts.push(
				<span key={m.index} className="text-violet-700 dark:text-violet-300">
					{m[3]}
				</span>,
			);
		} else {
			parts.push(
				<span key={m.index} className="text-amber-700 dark:text-amber-300">
					{m[4]}
				</span>,
			);
		}
		last = re.lastIndex;
	}
	parts.push(text.slice(last));
	return <Pre className={className}>{parts}</Pre>;
}

export function Pre({ children, className }: { children: React.ReactNode; className?: string }) {
	return (
		<pre
			className={cn(
				"bg-muted/50 max-h-96 overflow-auto rounded-md border px-3 py-2 font-mono text-[11.5px] leading-5 break-all whitespace-pre-wrap",
				className,
			)}
		>
			{children}
		</pre>
	);
}

function parseJson(s: string): unknown {
	const t = s.trim();
	if (!(t.startsWith("{") || t.startsWith("["))) {
		return undefined;
	}
	try {
		return JSON.parse(t);
	} catch {
		return undefined;
	}
}

/** A logged value: headers-like objects as a table, JSON (also JSON in strings) pretty, images inline */
export function FieldValue({ value }: { value: unknown }) {
	if (typeof value === "string") {
		if (value.startsWith("data:image/")) {
			// oxlint-disable-next-line nextjs/no-img-element -- a data: URL from the log
			return <img src={value} alt="" className="max-h-[32rem] max-w-full rounded-md border" />;
		}
		const json = parseJson(value);
		if (json !== undefined) {
			return <JsonBlock value={json} />;
		}
		return <Pre>{value === "" ? <span className="text-muted-foreground">(empty)</span> : value}</Pre>;
	}
	if (value && typeof value === "object" && !Array.isArray(value)) {
		const entries = Object.entries(value);
		if (
			entries.length > 0 &&
			entries.length <= 40 &&
			entries.every(([, v]) => typeof v === "string" || typeof v === "number")
		) {
			return (
				<div className="overflow-hidden rounded-md border">
					<table className="w-full font-mono text-[11.5px]">
						<tbody className="divide-y">
							{entries.map(([k, v]) => (
								<tr key={k} className="align-top">
									<td className="bg-muted/50 text-muted-foreground w-0 px-3 py-1 whitespace-nowrap">{k}</td>
									<td className="px-3 py-1 break-all">{String(v)}</td>
								</tr>
							))}
						</tbody>
					</table>
				</div>
			);
		}
	}
	if (typeof value === "number" || typeof value === "boolean" || value === null) {
		return <span className="font-mono text-xs">{String(value)}</span>;
	}
	return <JsonBlock value={value} />;
}
