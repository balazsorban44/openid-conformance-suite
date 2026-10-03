import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { test } from "node:test";
import { NamedError } from "./exceptions.ts";

const src = join(import.meta.dirname, "..");

/** Every non-test module under src/framework and src/util that declares a class extending something. */
function modulesDeclaringSubclasses(): string[] {
	const files: string[] = [];
	for (const dir of ["framework", "util"]) {
		for (const entry of readdirSync(join(src, dir), { recursive: true, withFileTypes: true })) {
			const path = join(entry.parentPath, entry.name);
			if (entry.isFile() && path.endsWith(".ts") && !path.endsWith(".test.ts")) {
				if (/^export class \w+ extends \w+/m.test(readFileSync(path, "utf8"))) {
					files.push(path);
				}
			}
		}
	}
	return files.sort();
}

test("every exported framework/util exception class is a NamedError whose name is its class name", async () => {
	const seen: string[] = [];
	for (const path of modulesDeclaringSubclasses()) {
		const mod = (await import(path)) as Record<string, unknown>;
		for (const [exported, value] of Object.entries(mod)) {
			if (typeof value !== "function" || !(value.prototype instanceof Error)) {
				continue;
			}
			const where = relative(src, path) + " " + exported;
			const cls = value as new (...args: unknown[]) => Error;
			// one argument (a number, for the TLS alerts) is enough for every constructor of these classes
			const e = new cls(0);
			assert.ok(e instanceof Error, where);
			assert.ok(e instanceof NamedError, where + " extends NamedError");
			assert.equal(e.name, cls.name, where);
			assert.equal(e.name, e.constructor.name, where);
			assert.ok(!Object.hasOwn(e, "name"), where + " has no own name property");
			assert.ok(e.stack?.startsWith(cls.name), where + " stack header");
			seen.push(exported);
		}
	}
	for (const expected of [
		"NamedError",
		"TestInterruptedException",
		"TestFailureException",
		"TestSkippedException",
		"ConditionError",
		"JsonParseException",
		"UnexpectedTypeException",
		"HttpClientException",
		"VariantConfigurationError",
		"ParseException",
		"JOSEException",
		"KeyLengthException",
		"SocketException",
		"TlsFatalAlert",
		"ServerHelloReceived",
		"URISyntaxException",
		"InvalidNameException",
		"CertificateException",
		"IllegalArgumentException",
		"JsonSchemaValidationException",
	]) {
		assert.ok(seen.includes(expected), expected + " was checked");
	}
});
