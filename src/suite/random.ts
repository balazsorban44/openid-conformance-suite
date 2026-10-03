import { randomInt } from "node:crypto";

const ALPHANUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/** A random string of letters and digits (upstream RandomStringUtils.secure().nextAlphanumeric) */
export function randomAlphanumeric(length: number): string {
	let out = "";
	for (let i = 0; i < length; i++) {
		out += ALPHANUMERIC[randomInt(ALPHANUMERIC.length)];
	}
	return out;
}
