import {
	AbstractCondition,
	args,
	OIDFJSON,
	isJsonArray,
	type Environment,
	type EnvironmentRequirements,
	type JsonArray,
	type JsonObject,
} from "../../../framework/index.ts";

/**
 * contacts
 * OPTIONAL. Array of e-mail addresses of people responsible for this Client.
 * This might be used by some providers to enable a Web user interface to modify the Client information.
 *
 * Although contacts is optional, the python suite requires at least one contact in registration requests.
 * Python suite also checks if the first entry in contacts contains a @ character
 * See Provider.registration_endpoint in oidctest/src/oidctest/rp/provider.py
 */
export class EnsureRegistrationRequestContainsAtLeastOneContact extends AbstractCondition {
	private static readonly CONTACTS = "contacts";

	static override pre: EnvironmentRequirements = { required: ["dynamic_registration_request"] };

	override evaluate(env: Environment): Environment {
		const request = env.getObject("dynamic_registration_request") as JsonObject;
		if (!(EnsureRegistrationRequestContainsAtLeastOneContact.CONTACTS in request)) {
			throw this.error("This application requires that registration requests contain at least one contact.");
		}
		const contacts = request[EnsureRegistrationRequestContainsAtLeastOneContact.CONTACTS];
		if (!isJsonArray(contacts)) {
			throw this.error(
				"This application requires that registration requests contain at least one contact. " +
					"Provided contacts is not encoded as a json array",
			);
		}
		const contactsArray: JsonArray = contacts;
		if (contactsArray.length < 1) {
			throw this.error(
				"This application requires that registration requests contain at least one contact. " +
					"Provided contacts array is empty",
			);
		}
		for (const element of contactsArray) {
			const contactFromElement = OIDFJSON.getString(element);
			if (contactFromElement != null && !contactFromElement.includes("@")) {
				throw this.error("Invalid contact. Only email addresses are expected in contacts", args("contact", element));
			}
		}
		this.logSuccess("Registration request contains valid contacts", args("contacts", contactsArray));
		return env;
	}
}
