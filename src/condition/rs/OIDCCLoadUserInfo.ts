import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class OIDCCLoadUserInfo extends AbstractCondition {
	static readonly SUPPORTED_CLAIMS: readonly string[] = [
		"sub",
		"name",
		"given_name",
		"family_name",
		"middle_name",
		"nickname",
		"preferred_username",
		"gender",
		"birthdate",
		"address",
		"zoneinfo",
		"locale",
		"phone_number",
		"phone_number_verified",
		"email",
		"email_verified",
		"website",
		"profile",
		"updated_at",
		"txn",
		// TODO add a picture?
		// "picture"
	];

	/**
	 * Java has getUserInfoClaimsValues(String... claimsList) and a no-argument overload using SUPPORTED_CLAIMS.
	 * Here no arguments means SUPPORTED_CLAIMS; an array (Java: passing a String[] as the varargs) may be passed
	 * instead of / in addition to individual claim names, and an empty array yields an empty object.
	 */
	static getUserInfoClaimsValues(...claimsList: (string | readonly string[])[]): JsonObject {
		const claims = claimsList.length === 0 ? OIDCCLoadUserInfo.SUPPORTED_CLAIMS : claimsList.flat();
		const user: JsonObject = {};

		for (const claim of claims) {
			switch (claim) {
				case "sub":
					user["sub"] = "user-subject-1234531";
					break;

				case "name":
					user["name"] = "Demo T. User";
					break;

				case "given_name":
					user["given_name"] = "Demo";
					break;

				case "family_name":
					user["family_name"] = "User";
					break;

				case "middle_name":
					user["middle_name"] = "Theresa";
					break;

				case "nickname":
					user["nickname"] = "Dee";
					break;

				case "preferred_username":
					user["preferred_username"] = "d.tu";
					break;

				case "gender":
					user["gender"] = "female";
					break;

				case "birthdate":
					user["birthdate"] = "2000-02-03";
					break;

				case "address": {
					const address: JsonObject = {};
					address["street_address"] = "100 Universal City Plaza";
					address["locality"] = "Hollywood";
					address["region"] = "CA";
					address["postal_code"] = "91608";
					address["country"] = "USA";
					user["address"] = address;
					break;
				}

				case "zoneinfo":
					user["zoneinfo"] = "America/Los_Angeles";
					break;

				case "locale":
					user["locale"] = "en-US";
					break;

				case "phone_number":
					user["phone_number"] = "+1 555 5550000";
					break;

				case "phone_number_verified":
					user["phone_number_verified"] = false;
					break;

				case "email":
					user["email"] = "user@example.com";
					break;

				case "email_verified":
					user["email_verified"] = false;
					break;

				case "website":
					user["website"] = "https://openid.net/";
					break;

				case "profile":
					user["profile"] = "https://example.com/user";
					break;

				case "updated_at":
					user["updated_at"] = 1580000000;
					break;

				case "txn":
					user["txn"] = "2c6fb585-d51b-465a-9dca-b8cd22a11451";
					break;

				default:
					break;

				// TODO add a picture?
				// user.addProperty("picture");
			}
		}
		return user;
	}

	static override post: EnvironmentRequirements = { required: ["user_info"] };

	override evaluate(env: Environment): Environment {
		const user = OIDCCLoadUserInfo.getUserInfoClaimsValues();

		env.putObject("user_info", user);

		this.logSuccess("Added user information", args("user_info", user));

		return env;
	}
}
