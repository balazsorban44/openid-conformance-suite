import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { RFC6749AppendixASyntaxUtils } from "../util/RFC6749AppendixASyntaxUtils.ts";

export class CreateRandomEndSessionState extends AbstractCondition {
	static override post: EnvironmentRequirements = { strings: ["end_session_state"] };

	override evaluate(env: Environment): Environment {
		// https://openid.net/specs/openid-connect-session-1_0.html#RPLogout does not appear to define a character
		// set for state; assume it is in same as state defined in RFC6749
		let state = RFC6749AppendixASyntaxUtils.generateVSChar(50, 10, 30);

		// the way we encode urls escapes + incorrectly in the url query currently, so don't include '+'s
		// @see net.openid.conformance.condition.client.BuildPlainRedirectToAuthorizationEndpoint_UnitTest.testEscape
		state = state.replaceAll("+", "~");
		state = state.replaceAll(" ", "~");
		// avoid ; as spring seems to not process them correctly when they're returned to us unescaped; see
		// https://gitlab.com/openid/conformance-suite/-/issues/871
		state = state.replaceAll(";", "~");

		env.putString("end_session_state", state);

		this.log("Created end_session_state value", args("end_session_state", state));

		return env;
	}
}
