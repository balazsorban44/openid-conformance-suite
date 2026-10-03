import { AbstractCondition, isJsonObject, OIDFJSON, type JsonObject, type JsonValue } from "../../framework/index.ts";
import { isBlank } from "../../util/jdk/strings.ts";

export interface ElementValidator {
	getDescription(): string;

	isValid(elt: JsonValue | undefined): boolean;
}

const VALIDATE_STRING: ElementValidator = {
	getDescription(): string {
		return "a string with content";
	},

	isValid(elt: JsonValue | undefined): boolean {
		// If a Claim is not returned, that Claim Name SHOULD be omitted from the JSON object representing the Claims; it SHOULD NOT be present with a null or empty string value.
		if (typeof elt !== "string") {
			return false;
		}
		if (isBlank(OIDFJSON.getString(elt))) {
			return false;
		}
		// Not explicitly stated in any spec, but we've seen servers return this incorrectly as a user's name
		if (OIDFJSON.getString(elt).toLowerCase() === "null") {
			return false;
		}
		return true;
	},
};

const VALIDATE_BIRTHDATE: ElementValidator = {
	getDescription(): string {
		return "a valid birthdate in the format stated in OpenID Connect Standard - YYYY-MM-DD, 0000-MM-DD or YYYY";
	},

	isValid(elt: JsonValue | undefined): boolean {
		if (!VALIDATE_STRING.isValid(elt)) {
			return false;
		}
		return isValidBirthDate(OIDFJSON.getString(elt));
	},
};

function isValidBirthDate(date: string): boolean {
	return isValidFullDate(date) || isValidYearOnly(date);
}

function isValidFullDate(date: string): boolean {
	// Java parses with DateTimeFormatter "uuuu-MM-dd" (Locale.US) in ResolverStyle.STRICT; any year that is not
	// exactly four digits either fails to parse or is rejected by isSaneBirthYear, so only four digit years matter.
	const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(date);
	if (m == null) {
		return false;
	}
	const year = Number(m[1]);
	const month = Number(m[2]);
	const day = Number(m[3]);
	if (month < 1 || month > 12) {
		return false;
	}
	const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
	const daysInMonth = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1];
	if (day < 1 || day > daysInMonth) {
		return false;
	}
	if (year === 0) {
		// as per OIDCC, the year can optionally be 0000 to indicate year not held/not released
		return true;
	}
	if (!isSaneBirthYear(year)) {
		return false;
	}

	return true;
}

// true if seems like a real date of birth, or at least a fake that results in a non-negative non-excessive age.
function isSaneBirthYear(year: number): boolean {
	return year >= 1850 && year <= new Date().getFullYear();
}

function isValidYearOnly(yearStr: string): boolean {
	// Integer.parseInt accepts an optional sign followed by digits
	if (!/^[+-]?\d+$/.test(yearStr)) {
		return false;
	}
	const year = Number.parseInt(yearStr, 10);
	return isSaneBirthYear(year);
}

const VALIDATE_BOOLEAN: ElementValidator = {
	getDescription(): string {
		return "a boolean";
	},

	isValid(elt: JsonValue | undefined): boolean {
		return typeof elt === "boolean";
	},
};

const VALIDATE_NUMBER: ElementValidator = {
	getDescription(): string {
		return "a number";
	},

	isValid(elt: JsonValue | undefined): boolean {
		return typeof elt === "number";
	},
};

const VALIDATE_JSON_OBJECT: ElementValidator = {
	getDescription(): string {
		return "a JSON object";
	},

	isValid(elt: JsonValue | undefined): boolean {
		return isJsonObject(elt);
	},
};

export abstract class AbstractValidateOpenIdStandardClaims extends AbstractCondition {
	private static readonly ADDRESS_CLAIMS = new Map<string, ElementValidator>([
		["formatted", VALIDATE_STRING],
		["street_address", VALIDATE_STRING],
		["locality", VALIDATE_STRING],
		["region", VALIDATE_STRING],
		["postal_code", VALIDATE_STRING],
		["country", VALIDATE_STRING],
	]);

	protected readonly STANDARD_CLAIMS = new Map<string, ElementValidator>([
		["sub", VALIDATE_STRING],
		["name", VALIDATE_STRING],
		["given_name", VALIDATE_STRING],
		["family_name", VALIDATE_STRING],
		["middle_name", VALIDATE_STRING],
		["nickname", VALIDATE_STRING],
		["preferred_username", VALIDATE_STRING],
		["profile", VALIDATE_STRING],
		["picture", VALIDATE_STRING],
		["website", VALIDATE_STRING],
		["email", VALIDATE_STRING],
		["email_verified", VALIDATE_BOOLEAN],
		["gender", VALIDATE_STRING],
		["birthdate", VALIDATE_BIRTHDATE],
		["zoneinfo", VALIDATE_STRING],
		["locale", VALIDATE_STRING],
		["phone_number", VALIDATE_STRING],
		["phone_number_verified", VALIDATE_BOOLEAN],
		["address", this.createObjectValidator("address", AbstractValidateOpenIdStandardClaims.ADDRESS_CLAIMS)],
		["updated_at", VALIDATE_NUMBER],
		["_claim_names", VALIDATE_JSON_OBJECT],
		["_claim_sources", VALIDATE_JSON_OBJECT],
		// digitalid-financial-api-04.md
		["txn", VALIDATE_STRING],
	]);

	protected unknownClaims: JsonObject = {};

	/**
	 * Port of the Java inner class ObjectValidator (an inner class so that it can log through the enclosing
	 * condition and record into its unknownClaims). Use `new ObjectValidator(context, claims)` in Java ==
	 * `this.createObjectValidator(context, claims)` here.
	 */
	protected createObjectValidator(context: string | null, claims: Map<string, ElementValidator>): ElementValidator {
		const outer = this;
		return {
			getDescription(): string {
				return "a valid object or contains invalid claims";
			},

			isValid(elt: JsonValue | undefined): boolean {
				if (!isJsonObject(elt) || Object.keys(elt).length === 0) {
					outer.logFailure("Not a JSON object or no identity claims");
					return false;
				}

				let ok = true;

				for (const [key, value] of Object.entries(elt)) {
					const name = context != null ? context + "." + key : key;
					const validator = claims.get(key);
					if (validator == null) {
						outer.log("Skipping unknown claim: " + name);
						outer.unknownClaims[name] = value;
						continue;
					}

					if (validator.isValid(value)) {
						outer.log(name + " is " + validator.getDescription());
					} else {
						outer.logFailure(name + " is not " + validator.getDescription());
						ok = false;
					}
				}

				return ok;
			},
		};
	}
}
