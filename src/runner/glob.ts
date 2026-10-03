/** fnmatch-style glob (`*` any run of characters, `?` one character) as an anchored RegExp */
export function globToRegExp(pattern: string): RegExp {
	const body = [...pattern]
		.map((c) => (c === "*" ? ".*" : c === "?" ? "." : c.replace(/[.+^${}()|[\]\\]/g, "\\$&")))
		.join("");
	return new RegExp(`^${body}$`);
}

export function fnmatch(pattern: string, s: string): boolean {
	return globToRegExp(pattern).test(s);
}
