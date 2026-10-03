import { AbstractCondition, args, type Environment } from "../../framework/index.ts";

export class CheckForSubjectInIdToken extends AbstractCondition {
	override evaluate(env: Environment): Environment {
		const sub = env.getString("id_token", "claims.sub");

		if (!sub) {
			throw this.error("id_token does not contain 'sub'");
		}

		// As per https://openid.net/specs/openid-connect-core-1_0.html#IDToken :
		// "It MUST NOT exceed 255 ASCII characters in length."
		if (sub.length > 255) {
			throw this.error("id_token 'sub' exceeds 255 ASCII characters", args("sub", sub));
		}

		for (let i = 0; i < sub.length; i++) {
			const c = sub.charCodeAt(i);
			if (c < 0x20) {
				throw this.error(
					`id_token 'sub' contains non-printable character 0x${c.toString(16).padStart(2, "0")} at offset ${i}`,
					args("sub", sub),
				);
			}
			if (c >= 0x7f) {
				throw this.error(
					`id_token 'sub' contains non-ASCII character 0x${c.toString(16).padStart(2, "0")} at offset ${i}`,
					args("sub", sub),
				);
			}
		}

		this.logSuccess("Found 'sub' in id_token", args("sub", sub));
		return env;
	}
}
