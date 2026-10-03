import assert from "node:assert/strict";
import { test } from "vitest";
import { inetAddressBytes } from "./inet.ts";

// Expected equality as InetAddress.equals() reports it on OpenJDK 21.
function sameAddress(a: string, b: string): boolean {
	const x = inetAddressBytes(a);
	const y = inetAddressBytes(b);
	return x.length === y.length && x.every((v, i) => v === y[i]);
}

test("inetAddressBytes: raw address bytes", () => {
	assert.deepEqual(inetAddressBytes("192.0.2.1"), [192, 0, 2, 1]);
	assert.deepEqual(inetAddressBytes("2001:db8::1"), [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
	// an IPv4-mapped IPv6 address is an IPv4 address
	assert.deepEqual(inetAddressBytes("::ffff:192.0.2.1"), [192, 0, 2, 1]);
	assert.deepEqual(
		inetAddressBytes("::"),
		Array.from({ length: 16 }, () => 0),
	);
});

test("inetAddressBytes: InetAddress.equals() semantics", () => {
	const cases: [string, string, boolean][] = [
		["127.0.0.1", "127.0.0.1", true],
		["127.0.0.1", "::ffff:127.0.0.1", true],
		["127.0.0.1", "::ffff:7f00:1", true],
		["::1", "0:0:0:0:0:0:0:1", true],
		["2001:db8::1", "2001:DB8:0:0:0:0:0:1", true],
		["2001:db8::1", "2001:db8::2", false],
		["1.2.3.4", "1.2.3.5", false],
		// an IPv4-compatible IPv6 address is not an IPv4 address
		["::127.0.0.1", "127.0.0.1", false],
		["::", "0:0:0:0:0:0:0:0", true],
		["fe80::1:2", "fe80:0:0:0:0:0:1:2", true],
	];
	for (const [a, b, expected] of cases) {
		assert.equal(sameAddress(a, b), expected, `${a} ${b}`);
	}
});

test("inetAddressBytes: not an IP literal (Guava InetAddresses.forString message)", () => {
	assert.throws(() => inetAddressBytes("example.com"), { message: "'example.com' is not an IP string literal." });
	assert.throws(() => inetAddressBytes("1.2.3"), { message: "'1.2.3' is not an IP string literal." });
});
