/**
 * BCP47 language-tag validation as upstream does it (util/Bcp47LocaleValidation, used by the discovery metadata's
 * locale checks: `ui_locales_supported`, `claims_locales_supported`): a tag must be well-formed per Java's
 * `Locale.Builder#setLanguageTag` (emulated by {@link JavaLocale}) and each of its subtags registered in the IANA
 * Language Subtag Registry (util/Bcp47SubtagRegistry).
 */
import { readFileSync } from "node:fs";
import { NamedError } from "./errors.ts";

/** A snapshot of the IANA Language Subtag Registry, copied from upstream src/main/resources/iana/ */
const RESOURCE_PATH = new URL("./data/language-subtag-registry.txt", import.meta.url);

let INSTANCE: Bcp47SubtagRegistry | null = null;

/** upstream: util/Bcp47SubtagRegistry.java (getInstance) */
export function subtagRegistry(): Bcp47SubtagRegistry {
	// Lazy initialization-on-demand: the ~49k-line IANA registry is parsed only when a
	// locale check first needs it, not eagerly at module load.
	if (INSTANCE == null) {
		INSTANCE = new Bcp47SubtagRegistry();
	}
	return INSTANCE;
}

function addEntry(
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
			expandRange(target, parts[0], parts[1]);
		}
	} else {
		target.add(subtag);
	}
}

function expandRange(target: Set<string>, from: string, to: string): void {
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
		current = increment(current);
		target.add(current);
	}
}

function increment(s: string): string {
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

/**
 * The registered subtags. Only the canonical forms (language lowercase, region uppercase, script Title-case) are
 * stored; callers pass the values {@link JavaLocale}'s getters return, which already match those forms.
 */
export class Bcp47SubtagRegistry {
	private readonly languages: ReadonlySet<string>;
	private readonly regions: ReadonlySet<string>;
	private readonly scripts: ReadonlySet<string>;
	private readonly variants: ReadonlySet<string>;
	private readonly fileDate: string | null;

	constructor() {
		const langs = new Set<string>();
		const regs = new Set<string>();
		const scr = new Set<string>();
		const vars = new Set<string>();
		let date: string | null = null;
		let text: string;
		try {
			text = readFileSync(RESOURCE_PATH, "utf8");
		} catch (e) {
			if ((e as NodeJS.ErrnoException).code === "ENOENT") {
				throw new Error("IANA Language Subtag Registry resource not found at " + RESOURCE_PATH.pathname, { cause: e });
			}
			throw new Error("Failed to load IANA Language Subtag Registry", { cause: e });
		}
		let type: string | null = null;
		let subtag: string | null = null;
		for (const line of text.split(/\r?\n/)) {
			if (line === "%%") {
				addEntry(type, subtag, langs, regs, scr, vars);
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
		addEntry(type, subtag, langs, regs, scr, vars);
		this.languages = langs;
		this.regions = regs;
		this.scripts = scr;
		this.variants = vars;
		this.fileDate = date;
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
}

/** Port of `java.util.IllformedLocaleException` (message includes " [at index N]" as in Java). */
export class IllformedLocaleException extends NamedError {
	readonly errorIndex: number;

	constructor(message: string, errorIndex = -1) {
		super(message + (errorIndex < 0 ? "" : " [at index " + errorIndex + "]"));
		this.errorIndex = errorIndex;
	}
}

const LEGACY: Record<string, string> = {
	"art-lojban": "jbo",
	"cel-gaulish": "xtg-x-cel-gaulish",
	"en-gb-oed": "en-GB-x-oed",
	"i-ami": "ami",
	"i-bnn": "bnn",
	"i-default": "en-x-i-default",
	"i-enochian": "und-x-i-enochian",
	"i-hak": "hak",
	"i-klingon": "tlh",
	"i-lux": "lb",
	"i-mingo": "see-x-i-mingo",
	"i-navajo": "nv",
	"i-pwn": "pwn",
	"i-tao": "tao",
	"i-tay": "tay",
	"i-tsu": "tsu",
	"no-bok": "nb",
	"no-nyn": "nn",
	"sgn-be-fr": "sfb",
	"sgn-be-nl": "vgt",
	"sgn-ch-de": "sgg",
	"zh-guoyu": "cmn",
	"zh-hakka": "hak",
	"zh-min": "nan-x-zh-min",
	"zh-min-nan": "nan",
	"zh-xiang": "hsn",
};

function isAlpha(s: string): boolean {
	return /^[A-Za-z]+$/.test(s);
}

function isAlphaNumeric(s: string): boolean {
	return /^[A-Za-z0-9]+$/.test(s);
}

function isLanguage(s: string): boolean {
	return s.length >= 2 && s.length <= 8 && isAlpha(s);
}

function isExtlang(s: string): boolean {
	return s.length === 3 && isAlpha(s);
}

function isScript(s: string): boolean {
	return s.length === 4 && isAlpha(s);
}

function isRegion(s: string): boolean {
	return (s.length === 2 && isAlpha(s)) || (s.length === 3 && /^[0-9]{3}$/.test(s));
}

function isVariant(s: string): boolean {
	const len = s.length;
	if (len >= 5 && len <= 8) {
		return isAlphaNumeric(s);
	}
	if (len === 4) {
		return /^[0-9][A-Za-z0-9]{3}$/.test(s);
	}
	return false;
}

function isExtensionSingleton(s: string): boolean {
	return s.length === 1 && isAlphaNumeric(s) && s.toLowerCase() !== "x";
}

function isExtensionSubtag(s: string): boolean {
	return s.length >= 2 && s.length <= 8 && isAlphaNumeric(s);
}

function isPrivateuseSubtag(s: string): boolean {
	return s.length >= 1 && s.length <= 8 && isAlphaNumeric(s);
}

function toTitle(s: string): string {
	return s.length === 0 ? s : s.charAt(0).toUpperCase() + s.substring(1).toLowerCase();
}

/**
 * `new Locale.Builder().setLanguageTag(tag).build()`
 * @throws IllformedLocaleException
 */
export function forLanguageTagStrict(languageTag: string): JavaLocale {
	const legacy = LEGACY[languageTag.toLowerCase()];
	const source = legacy ?? languageTag;

	// StringTokenIterator over '-'
	const tokens: { s: string; start: number }[] = [];
	let pos = 0;
	for (const s of source.split("-")) {
		tokens.push({ s, start: pos });
		pos += s.length + 1;
	}
	let i = 0;
	const isDone = () => i >= tokens.length;
	const current = () => tokens[i].s;
	const currentEnd = () => tokens[i].start + tokens[i].s.length;
	let parseLength = 0;
	let errorIndex = -1;
	let errorMsg: string | null = null;
	const isError = () => errorIndex >= 0;

	let language = "";
	const extlangs: string[] = [];
	let script = "";
	let region = "";
	const variants: string[] = [];
	const extensions: string[] = [];
	let privateuse = "";

	// parseLanguage
	let foundLanguage = false;
	if (!isDone() && isLanguage(current())) {
		foundLanguage = true;
		language = current();
		parseLength = currentEnd();
		i++;
	}
	if (foundLanguage) {
		// parseExtlangs
		while (!isDone() && extlangs.length < 3 && isExtlang(current())) {
			extlangs.push(current());
			parseLength = currentEnd();
			i++;
		}
		// parseScript
		if (!isDone() && isScript(current())) {
			script = current();
			parseLength = currentEnd();
			i++;
		}
		// parseRegion
		if (!isDone() && isRegion(current())) {
			region = current();
			parseLength = currentEnd();
			i++;
		}
		// parseVariants
		while (!isDone() && isVariant(current())) {
			variants.push(current());
			parseLength = currentEnd();
			i++;
		}
		// parseExtensions
		while (!isDone()) {
			const s = current();
			if (!isExtensionSingleton(s)) {
				break;
			}
			const start = tokens[i].start;
			let sb = s;
			i++;
			while (!isDone()) {
				const sub = current();
				if (!isExtensionSubtag(sub)) {
					break;
				}
				sb += "-" + sub;
				parseLength = currentEnd();
				i++;
			}
			if (parseLength <= start) {
				errorIndex = start;
				errorMsg = "Incomplete extension '" + s + "'";
				break;
			}
			extensions.push(sb);
		}
	}
	// parsePrivateuse
	if (!isDone() && !isError() && current().toLowerCase() === "x") {
		const start = tokens[i].start;
		let sb = current();
		i++;
		while (!isDone()) {
			const s = current();
			if (!isPrivateuseSubtag(s)) {
				break;
			}
			sb += "-" + s;
			parseLength = currentEnd();
			i++;
		}
		if (parseLength <= start) {
			errorIndex = start;
			errorMsg = "Incomplete privateuse";
		} else {
			privateuse = sb;
		}
	}
	if (!isDone() && !isError()) {
		const s = current();
		errorIndex = tokens[i].start;
		errorMsg = s.length === 0 ? "Empty subtag" : "Invalid subtag: " + s;
	}
	if (isError()) {
		throw new IllformedLocaleException(errorMsg as string, errorIndex);
	}

	// InternalLocaleBuilder.setLanguageTag
	let lang = "";
	if (extlangs.length > 0) {
		lang = extlangs[0];
	} else if (language !== "und") {
		lang = language;
	}
	const ext = new Map<string, string>();
	for (const e of extensions) {
		const singleton = e.charAt(0).toLowerCase();
		if (ext.has(singleton)) {
			continue;
		}
		const value = e.substring(2).toLowerCase();
		ext.set(singleton, singleton === "u" ? canonicalUnicodeExtension(value) : value);
	}
	if (privateuse.length > 0) {
		ext.set("x", privateuse.substring(2).toLowerCase());
	}

	// BaseLocale.getInstance normalization
	lang = lang.toLowerCase();
	if (lang === "iw") {
		lang = "he";
	} else if (lang === "ji") {
		lang = "yi";
	} else if (lang === "in") {
		lang = "id";
	}
	return new JavaLocale(lang, toTitle(script), region.toUpperCase(), variants.join("_"), ext);
}

/** UnicodeLocaleExtension: attributes sorted, then keywords sorted by key (first occurrence of a key wins). */
function canonicalUnicodeExtension(value: string): string {
	const subtags = value.split("-");
	const attributes = new Set<string>();
	const keywords = new Map<string, string>();
	let idx = 0;
	while (idx < subtags.length && subtags[idx].length !== 2) {
		attributes.add(subtags[idx]);
		idx++;
	}
	while (idx < subtags.length) {
		const key = subtags[idx];
		idx++;
		const types: string[] = [];
		while (idx < subtags.length && subtags[idx].length !== 2) {
			types.push(subtags[idx]);
			idx++;
		}
		if (!keywords.has(key)) {
			keywords.set(key, types.join("-"));
		}
	}
	const parts: string[] = [...attributes].sort();
	for (const key of [...keywords.keys()].sort()) {
		const type = keywords.get(key) as string;
		parts.push(type.length > 0 ? key + "-" + type : key);
	}
	return parts.join("-");
}

/**
 * Minimal port of the parts of `java.util.Locale` / `Locale.Builder.setLanguageTag` / `Locale.toLanguageTag`
 * (sun.util.locale.LanguageTag + InternalLocaleBuilder, JDK 21) that the BCP47 checks rely on: the same
 * well-formedness rules and error messages, legacy (grandfathered) tag mapping, extlang handling, obsolete ISO
 * code conversion and canonical casing.
 */
export class JavaLocale {
	readonly language: string;
	readonly script: string;
	readonly region: string;
	readonly variant: string;
	/** singleton -> extension value (without the singleton), lowercased; 'x' holds the private use value */
	private readonly extensions: Map<string, string>;

	constructor(language: string, script: string, region: string, variant: string, extensions: Map<string, string>) {
		this.language = language;
		this.script = script;
		this.region = region;
		this.variant = variant;
		this.extensions = extensions;
	}

	getLanguage(): string {
		return this.language;
	}

	getCountry(): string {
		return this.region;
	}

	getScript(): string {
		return this.script;
	}

	getVariant(): string {
		return this.variant;
	}

	/** `Locale.toLanguageTag()` */
	toLanguageTag(): string {
		const parts: string[] = [];
		let hasSubtag = false;
		let language = isLanguage(this.language) ? this.language : "";
		if (isScript(this.script)) {
			hasSubtag = true;
		}
		if (isRegion(this.region)) {
			hasSubtag = true;
		}
		const variants = this.variant.length > 0 ? this.variant.split("_") : [];
		if (variants.length > 0) {
			hasSubtag = true;
		}
		const singletons = [...this.extensions.keys()].filter((k) => k !== "x").sort();
		if (singletons.length > 0) {
			hasSubtag = true;
		}
		const privateuse = this.extensions.get("x") ?? null;
		if (language.length === 0 && (hasSubtag || privateuse == null)) {
			language = "und";
		}
		if (language.length > 0) {
			parts.push(language.toLowerCase());
		}
		if (isScript(this.script)) {
			parts.push(toTitle(this.script));
		}
		if (isRegion(this.region)) {
			parts.push(this.region.toUpperCase());
		}
		// preserve casing of variants
		parts.push(...variants);
		for (const s of singletons) {
			parts.push(s + "-" + this.extensions.get(s));
		}
		if (privateuse != null) {
			parts.push("x-" + privateuse);
		}
		return parts.join("-");
	}
}

/**
 * Validates a single language tag, appending one issue per problem to `issues`.
 *
 * @param tag    the language tag to validate
 * @param label  the path/field prefix used in issue messages (everything before the `": "`),
 *               e.g. `"ui_locales_supported[0]"` or `"$.display[0].locale"`
 * @param issues collector for human-readable problem descriptions
 * @return the canonical form of the tag (for duplicate detection), or `null` if the tag is
 *         malformed (in which case an issue has already been added)
 *
 * upstream: util/Bcp47LocaleValidation.java
 */
export function validateSubtags(tag: string, label: string, issues: string[]): string | null {
	let locale: JavaLocale;
	try {
		locale = forLanguageTagStrict(tag);
	} catch (e) {
		if (!(e instanceof IllformedLocaleException)) {
			throw e;
		}
		issues.push(`${label}: '${tag}' is not a well-formed BCP47 language tag (${e.message})`);
		return null;
	}
	const registry = subtagRegistry();
	const language = locale.getLanguage();
	if (language.length > 0 && !registry.isRegisteredLanguage(language)) {
		issues.push(`${label}: '${tag}' contains unregistered language subtag '${language}'`);
	}
	const region = locale.getCountry();
	if (region.length > 0 && !registry.isRegisteredRegion(region)) {
		issues.push(`${label}: '${tag}' contains unregistered region subtag '${region}'`);
	}
	const script = locale.getScript();
	if (script.length > 0 && !registry.isRegisteredScript(script)) {
		issues.push(`${label}: '${tag}' contains unregistered script subtag '${script}'`);
	}
	const variant = locale.getVariant();
	if (variant.length > 0) {
		for (const v of variant.split("_")) {
			if (!registry.isRegisteredVariant(v.toLowerCase())) {
				issues.push(`${label}: '${tag}' contains unregistered variant subtag '${v}'`);
			}
		}
	}
	return locale.toLanguageTag();
}

/**
 * Detects a language tag that differs from its BCP47 canonical form *only* in case
 * (e.g. `"DE"` vs `"de"`, `"EN-us"` vs `"en-US"`). RFC 5646 §2.1.1
 * permits any case, so this is a convention/typo concern rather than a validity error.
 *
 * @return the canonical-cased form when `tag` is well-formed and differs from it only in
 *         case; `null` otherwise. `null` is returned for ill-formed tags (their
 *         well-formedness is a {@link validateSubtags} concern) and for tags whose canonical
 *         form differs substantively rather than just in case — e.g. grandfathered tags like
 *         `i-klingon` that `Locale#toLanguageTag()` rewrites to `tlh`, where
 *         the change is the tag itself, not its casing.
 *
 * upstream: util/Bcp47LocaleValidation.java
 */
export function nonCanonicalCasing(tag: string): string | null {
	let locale: JavaLocale;
	try {
		locale = forLanguageTagStrict(tag);
	} catch (e) {
		if (!(e instanceof IllformedLocaleException)) {
			throw e;
		}
		return null;
	}
	const canonical = locale.toLanguageTag();
	if (tag === canonical) {
		return null;
	}
	if (tag.toLowerCase() !== canonical.toLowerCase()) {
		return null;
	}
	return canonical;
}
