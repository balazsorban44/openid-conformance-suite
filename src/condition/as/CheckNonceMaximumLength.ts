import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

/**
 * The relevant authorization specs do not bound the nonce length. This check
 * exists to promote interoperability: 43 characters is the length of
 * base64url(32 random bytes), the canonical "256-bit" nonce size, and is the
 * longest nonce the conformance suite itself generates in any happy-flow
 * scenario when acting on the opposite side of the protocol. Subclasses may
 * override the message-building methods to add spec-specific detail.
 */
export class CheckNonceMaximumLength extends AbstractCondition {
	protected static readonly MAX_LEN = 43;

	static override pre: EnvironmentRequirements = { strings: ["nonce"] };

	override evaluate(env: Environment): Environment {
		const nonce = env.getString("nonce");

		if (!nonce) {
			throw this.error("nonce is empty");
		}

		if (nonce.length > CheckNonceMaximumLength.MAX_LEN) {
			throw this.error(this.buildOverlongMessage(), args("nonce", nonce, "length", nonce.length));
		}

		this.logSuccess(this.buildSuccessMessage(), args("nonce", nonce, "length", nonce.length));
		return env;
	}

	protected buildOverlongMessage(): string {
		const MAX_LEN = CheckNonceMaximumLength.MAX_LEN;
		return (
			`Nonce contains in excess of ${MAX_LEN} characters. To promote interoperability we expect nonces no longer than ${MAX_LEN} characters ` +
			"(the longest the conformance suite generates when testing an authorization server); " +
			"longer values may not be accepted by all wallets/clients."
		);
	}

	protected buildSuccessMessage(): string {
		const MAX_LEN = CheckNonceMaximumLength.MAX_LEN;
		return (
			`Nonce does not exceed ${MAX_LEN} characters ` +
			"(the longest the conformance suite generates when testing an authorization server)."
		);
	}
}
