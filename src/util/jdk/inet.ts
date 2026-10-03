/** Emulation of `java.net.InetAddress` as returned by Guava's `InetAddresses.forString`. */
import { isIP } from "node:net";

/** java.net.InetAddress comparison: the raw address bytes (an IPv4-mapped IPv6 address is an IPv4 address) */
export function inetAddressBytes(address: string): number[] {
	// Guava InetAddresses.forString
	const version = isIP(address);
	if (version === 0) {
		throw new Error("'" + address + "' is not an IP string literal.");
	}
	if (version === 4) {
		return address.split(".").map((p) => parseInt(p, 10));
	}
	let text = address;
	const zone = text.indexOf("%");
	if (zone >= 0) {
		text = text.substring(0, zone);
	}
	// embedded IPv4 tail
	const lastColon = text.lastIndexOf(":");
	const tail = text.substring(lastColon + 1);
	if (tail.includes(".")) {
		const v4 = tail.split(".").map((p) => parseInt(p, 10));
		text =
			text.substring(0, lastColon + 1) +
			((v4[0] << 8) | v4[1]).toString(16) +
			":" +
			((v4[2] << 8) | v4[3]).toString(16);
	}
	const [head, rest] = text.split("::");
	const headGroups = head === "" ? [] : head.split(":");
	const restGroups = rest === undefined ? null : rest === "" ? [] : rest.split(":");
	let groups: string[];
	if (restGroups === null) {
		groups = headGroups;
	} else {
		groups = [
			...headGroups,
			...Array.from({ length: 8 - headGroups.length - restGroups.length }, () => "0"),
			...restGroups,
		];
	}
	const bytes: number[] = [];
	for (const g of groups) {
		const v = parseInt(g, 16);
		bytes.push((v >> 8) & 0xff, v & 0xff);
	}
	const isV4Mapped = bytes.slice(0, 10).every((b) => b === 0) && bytes[10] === 0xff && bytes[11] === 0xff;
	return isV4Mapped ? bytes.slice(12) : bytes;
}
