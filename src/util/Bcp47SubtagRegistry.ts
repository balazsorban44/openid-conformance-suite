import { readFileSync } from "node:fs";

/**
 * Validates BCP47 subtags against a bundled snapshot of the IANA Language Subtag Registry
 * (src/util/data/language-subtag-registry.txt, copied from upstream src/main/resources/iana/). Only the canonical
 * forms (language lowercase, region uppercase, script Title-case) are stored — callers should
 * pass the values returned by `Locale.getLanguage()`, `Locale.getCountry()`, etc. (see
 * `Bcp47LocaleValidation`), which already match those forms.
 */
export class Bcp47SubtagRegistry {
	private static readonly RESOURCE_PATH = new URL("./data/language-subtag-registry.txt", import.meta.url);

	private static INSTANCE: Bcp47SubtagRegistry | null = null;

	private readonly languages: ReadonlySet<string>;
	private readonly regions: ReadonlySet<string>;
	private readonly scripts: ReadonlySet<string>;
	private readonly variants: ReadonlySet<string>;
	private readonly fileDate: string | null;

	private constructor() {
		const langs = new Set<string>();
		const regs = new Set<string>();
		const scr = new Set<string>();
		const vars = new Set<string>();
		let date: string | null = null;
		let text: string;
		try {
			text = readFileSync(Bcp47SubtagRegistry.RESOURCE_PATH, "utf8");
		} catch (e) {
			if ((e as NodeJS.ErrnoException).code === "ENOENT") {
				throw new Error(
					"IANA Language Subtag Registry resource not found at " + Bcp47SubtagRegistry.RESOURCE_PATH.pathname,
				);
			}
			throw new Error("Failed to load IANA Language Subtag Registry", { cause: e });
		}
		let type: string | null = null;
		let subtag: string | null = null;
		for (const line of text.split(/\r?\n/)) {
			if (line === "%%") {
				Bcp47SubtagRegistry.addEntry(type, subtag, langs, regs, scr, vars);
				type = null;
				subtag = null;
			} else if (line.startsWith("File-Date: ")) {
				date = line.substring("File-Date: ".length).trim();
			} else if (line.startsWith("Type: ")) {
				type = line.substring("Type: ".length).trim();
			} else if (line.startsWith("Subtag: ")) {
				subtag = line.substring("Subtag: ".length).trim();
			}
		}
		Bcp47SubtagRegistry.addEntry(type, subtag, langs, regs, scr, vars);
		this.languages = langs;
		this.regions = regs;
		this.scripts = scr;
		this.variants = vars;
		this.fileDate = date;
	}

	static getInstance(): Bcp47SubtagRegistry {
		// Lazy initialization-on-demand: the ~49k-line IANA registry is parsed only when a
		// locale check first needs it, not eagerly at module load.
		if (Bcp47SubtagRegistry.INSTANCE == null) {
			Bcp47SubtagRegistry.INSTANCE = new Bcp47SubtagRegistry();
		}
		return Bcp47SubtagRegistry.INSTANCE;
	}

	isRegisteredLanguage(subtag: string): boolean {
		return this.languages.has(subtag);
	}

	isRegisteredRegion(subtag: string): boolean {
		return this.regions.has(subtag);
	}

	isRegisteredScript(subtag: string): boolean {
		return this.scripts.has(subtag);
	}

	isRegisteredVariant(subtag: string): boolean {
		return this.variants.has(subtag);
	}

	getFileDate(): string | null {
		return this.fileDate;
	}

	private static addEntry(
		type: string | null,
		subtag: string | null,
		langs: Set<string>,
		regs: Set<string>,
		scr: Set<string>,
		vars: Set<string>,
	): void {
		if (type == null || subtag == null) {
			return;
		}
		let target: Set<string> | null;
		switch (type) {
			case "language":
				target = langs;
				break;
			case "region":
				target = regs;
				break;
			case "script":
				target = scr;
				break;
			case "variant":
				target = vars;
				break;
			default:
				target = null;
		}
		if (target == null) {
			return;
		}
		if (subtag.includes("..")) {
			const parts = subtag.split("..");
			if (parts.length === 2 && parts[0].length === parts[1].length) {
				Bcp47SubtagRegistry.expandRange(target, parts[0], parts[1]);
			}
		} else {
			target.add(subtag);
		}
	}

	private static expandRange(target: Set<string>, from: string, to: string): void {
		if (from.charAt(0) !== to.charAt(0)) {
			// All current IANA registry ranges (qaa..qtz, Qaaa..Qabx, QM..QZ, XA..XZ) hold
			// position 0 fixed; the increment loop below relies on that to keep carries from
			// propagating past it. If a future registry adds a range that violates this,
			// surface it loudly so the limitation gets revisited rather than silently
			// emitting wrong subtags or looping forever.
			throw new Error(
				"Bcp47SubtagRegistry range '" +
					from +
					".." +
					to +
					"' would carry past position 0; expandRange does not support this. Update the parser.",
			);
		}
		let current = from;
		target.add(current);
		while (current !== to) {
			current = Bcp47SubtagRegistry.increment(current);
			target.add(current);
		}
	}

	private static increment(s: string): string {
		const chars = s.split("");
		for (let i = chars.length - 1; i >= 0; i--) {
			const c = chars[i];
			if (c === "z") {
				chars[i] = "a";
			} else if (c === "Z") {
				chars[i] = "A";
			} else {
				chars[i] = String.fromCharCode(c.charCodeAt(0) + 1);
				return chars.join("");
			}
		}
		return chars.join("");
	}
}
