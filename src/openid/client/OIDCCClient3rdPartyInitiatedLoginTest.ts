import { Status, TestFailureException, args, sleep, type PublishTestModule } from "../../framework/index.ts";
import { ValidateClientInitiateLoginUri } from "../../condition/as/dynregistration/ValidateClientInitiateLoginUri.ts";
import { AbstractOIDCCClientTest } from "./AbstractOIDCCClientTest.ts";

export class OIDCCClient3rdPartyInitiatedLoginTest extends AbstractOIDCCClientTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-3rd-party-init-login",
		displayName: "OIDCC: Relying party test, 3rd party initiated login",
		summary:
			"The client is expected to register with a valid 'initiate_login_uri'. The user is sent to that url, which should result in the RP redirecting the user to the authorization endpoint and the normal 'happy path' sequence completing.",
		profile: "OIDCC",
		configurationFields: [],
	};

	protected override async validateClientMetadata(): Promise<void> {
		await this.callAndStopOnFailure(ValidateClientInitiateLoginUri, "OIDCR-2");

		// run in background so it gets recorded in the log after the response is sent to the client
		this.getTestExecutionManager().runInBackground(async () => {
			// TS: a Java background thread starts after the current flow has moved on; yield to the event loop so
			// configure()/the registration handler can finish before this task takes the lock
			await sleep(0, this.getTestExecutionManager().signal);
			await this.setStatus(Status.RUNNING);
			const initiateLoginUri = this.env.getString("client", "initiate_login_uri") as string;
			const issuer = this.env.getString("issuer") as string;

			const builder = new URL(initiateLoginUri);

			builder.searchParams.append("iss", issuer);

			const redirectTo = builder.toString();

			this.eventLog.log(
				this.getName(),
				args(
					"msg",
					"Redirecting user to initiate_login_uri - press 'Proceed with test' to continue",
					"redirect_to",
					redirectTo,
					"http",
					"redirect",
				),
			);

			await this.setStatus(Status.WAITING);

			this.browser.goToUrl(redirectTo);

			return "done";
		});
	}

	protected override async handleAuthorizationEndpointRequest(requestId: string): Promise<Response> {
		if (this.browser.getVisited().length === 0) {
			throw new TestFailureException(
				this.getId(),
				"Authorization endpoint called before user has been sent to initiate_login_uri",
			);
		}
		return super.handleAuthorizationEndpointRequest(requestId);
	}
}
