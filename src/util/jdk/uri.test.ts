import assert from "node:assert/strict";
import { test } from "node:test";
import { parseJavaURI, URISyntaxException, type JavaURI } from "./uri.ts";

// Expected values were produced with `new java.net.URI(s)` on OpenJDK 21 (getScheme(), getHost(), getPort(),
// getRawFragment(), URISyntaxException.getMessage()).

function uri(scheme: string | null, host: string | null, port: number, fragment: string | null): JavaURI {
	return { scheme, host, port, fragment };
}

test("parseJavaURI: valid URIs", () => {
	const cases: [string, JavaURI][] = [
		["https://example.com/cb", uri("https", "example.com", -1, null)],
		["https://User:pw@Example.COM:8443/a/b?x=1&y=2#frag", uri("https", "Example.COM", 8443, "frag")],
		// an empty fragment is not a missing one
		["https://example.com/cb#", uri("https", "example.com", -1, "")],
		["https://example.com/cb?", uri("https", "example.com", -1, null)],
		["/relative/path?q=1#f", uri(null, null, -1, "f")],
		["relative", uri(null, null, -1, null)],
		["", uri(null, null, -1, null)],
		["//example.com/path", uri(null, "example.com", -1, null)],
		["com.example.app:/callback", uri("com.example.app", null, -1, null)],
		["urn:ietf:wg:oauth:2.0:oob", uri("urn", null, -1, null)],
		["mailto:a@b.c", uri("mailto", null, -1, null)],
		["http://[::1]:8080/x", uri("http", "[::1]", 8080, null)],
		["http://[fe80::1%25eth0]/", uri("http", "[fe80::1%25eth0]", -1, null)],
		["http://127.0.0.1:3000/cb", uri("http", "127.0.0.1", 3000, null)],
		["http://localhost/cb", uri("http", "localhost", -1, null)],
		// an empty port is -1, like a missing one
		["http://example.com:/", uri("http", "example.com", -1, null)],
		["https://example.com/ä", uri("https", "example.com", -1, null)],
	];
	for (const [input, expected] of cases) {
		assert.deepEqual(parseJavaURI(input), expected, input);
	}
});

test("parseJavaURI: registry-based authorities have no host and port -1", () => {
	for (const input of [
		"http://host:80x/",
		"http://exa_mple.com/",
		"http://-bad.com/",
		"http://example.123/",
		"http://256.1.1.1/",
		"https://example.com:99999999999/",
		"https://ex%41mple.com/",
		"https://exämple.com/",
	]) {
		const parsed = parseJavaURI(input);
		assert.equal(parsed.scheme, input.substring(0, input.indexOf(":")), input);
		assert.equal(parsed.host, null, input);
		assert.equal(parsed.port, -1, input);
	}
});

test("parseJavaURI: URISyntaxException messages", () => {
	const cases: [string, string][] = [
		["http://example.com/pa th", "Illegal character in path at index 21: http://example.com/pa th"],
		[":foo", "Expected scheme name at index 0: :foo"],
		["1http://x", "Illegal character in scheme name at index 0: 1http://x"],
		["http:", "Expected scheme-specific part at index 5: http:"],
		["http://", "Expected authority at index 7: http://"],
		["http://[::1/", "Expected closing bracket for IPv6 address at index 11: http://[::1/"],
		["http://[zz::1]/", "Malformed IPv6 address at index 8: http://[zz::1]/"],
		["http://example.com/%zz", "Malformed escape pair at index 19: http://example.com/%zz"],
		["http://example.com/#a#b", "Illegal character in fragment at index 21: http://example.com/#a#b"],
		["http://example.com/?a b", "Illegal character in query at index 21: http://example.com/?a b"],
	];
	for (const [input, message] of cases) {
		assert.throws(
			() => parseJavaURI(input),
			(e: unknown) => e instanceof URISyntaxException && e.name === "URISyntaxException" && e.message === message,
			input,
		);
	}
});
