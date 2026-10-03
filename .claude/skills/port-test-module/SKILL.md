---
name: port-test-module
description: How to port an upstream Java test module (AbstractOIDCCServerTest, OIDCCServerTest, AbstractOIDCCClientTest, logout modules, ...) or test plan (OIDCCBasicTestPlan, ...) and its variant enums to this TypeScript port. Use when porting, adding, or re-syncing test modules/plans/variants from the Java conformance suite.
---

# Porting test modules, plans and variants

Prerequisite: `.claude/skills/java-to-ts-porting/SKILL.md`. The framework base classes are in `src/framework/`
(`AbstractTestModule`, `AbstractRedirectServerTestModule`): read them once, they document every method.

## Module skeleton

```ts
import {
	AbstractRedirectServerTestModule, ConditionResult, Status, args, jsonResponse, redirectView, modelAndView,
	TestFailureException, type JsonObject, type PublishTestModule, type ModuleVariantMetadata, type ConditionSequence,
	type ConditionSequenceClass, type ConditionSequenceSupplier,
} from "../framework/index.ts";
import { ClientAuthType } from "../variant/ClientAuthType.ts";

export abstract class AbstractOIDCCServerTest extends AbstractRedirectServerTestModule {
	// @VariantParameters / @VariantConfigurationFields / @VariantNotApplicable / @VariantSetup ->
	static override variants: ModuleVariantMetadata = {
		parameters: [ServerMetadata, ClientAuthType, ResponseType, ResponseMode, ClientRegistration],
		configurationFields: [
			{ parameter: ServerMetadata, value: "static", configurationFields: ["server.issuer", "server.jwks_uri"] },
		],
		hidesConfigurationFields: [{ parameter: ResponseType, value: "id_token", configurationFields: ["server.token_endpoint"] }],
		notApplicable: [{ parameter: ClientAuthType, values: ["client_attestation"] }],
		setup: [
			{ parameter: ClientAuthType, value: "none", method: "setupNone" },
			{ parameter: ClientAuthType, value: "client_secret_basic", method: "setupClientSecretBasic" },
		],
	};

	protected responseType!: ResponseType;
	protected profileStaticClientConfiguration: ConditionSequenceClass | null = null;
	protected profileCompleteClientConfiguration: ConditionSequenceSupplier | null = null;

	// @VariantSetup(parameter = ClientAuthType.class, value = "none")
	setupNone(): void { ... }

	override async configure(config: JsonObject, baseUrl: string, externalUrlOverride: string, baseMtlsUrl: string): Promise<void> {
		this.env.putString("base_url", baseUrl);
		...
		await this.callAndStopOnFailure(CreateRedirectUri);
		switch (this.getVariant(ServerMetadata)) {
			case ServerMetadata.DISCOVERY: await this.callAndStopOnFailure(GetDynamicServerConfiguration); break;
			case ServerMetadata.STATIC: await this.callAndStopOnFailure(GetStaticServerConfiguration); break;
		}
		await this.setStatus(Status.CONFIGURED);
		this.fireSetupDone();
	}

	override async start(): Promise<void> {
		await this.setStatus(Status.RUNNING);
		await this.performAuthorizationFlow();
	}
}

export class OIDCCServerTest extends AbstractOIDCCServerTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-server",
		displayName: "OIDCC",
		summary: "Tests primarily 'happy' flows",
		profile: "OIDCC",
	};
	...
}
```

## Mapping table

| Java                                                                                                     | TypeScript                                                                                                |
| -------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `@PublishTestModule(testName=..., displayName=..., summary=..., profile=..., configurationFields={...})` | `static override readonly meta: PublishTestModule = {...}`                                                |
| `@VariantParameters({A.class, B.class})`                                                                 | `variants.parameters: [A, B]`                                                                             |
| `@VariantNotApplicable(parameter = A.class, values = {"x"})` (repeatable)                                | `variants.notApplicable: [{ parameter: A, values: ["x"] }]`                                               |
| `@VariantApplicableOnly`                                                                                 | `variants.applicableOnly`                                                                                 |
| `@VariantNotApplicableWhen(...)`                                                                         | `variants.notApplicableWhen: [{ parameter, values, whenParameter, hasValues }]`                           |
| `@VariantConfigurationFields(parameter = A.class, value = "x", configurationFields = {...})`             | `variants.configurationFields: [{ parameter: A, value: "x", configurationFields: [...] }]`                |
| `@VariantHidesConfigurationFields(...)`                                                                  | `variants.hidesConfigurationFields`                                                                       |
| `@ConfigurationFields({...})` on the class                                                               | `variants.plainConfigurationFields: [...]`                                                                |
| `@VariantSetup(parameter = A.class, value = "x") public void setupX()`                                   | `variants.setup: [{ parameter: A, value: "x", method: "setupX" }]` + a public `setupX(): void` method     |
| `getVariant(A.class)`                                                                                    | `this.getVariant(A)`                                                                                      |
| `getVariant(A.class) == A.FOO`                                                                           | `this.getVariant(A) === A.FOO`                                                                            |
| `switch (getVariant(A.class)) { case FOO: }`                                                             | `switch (this.getVariant(A)) { case A.FOO: }`                                                             |
| `callAndStopOnFailure(X.class, "REQ")`                                                                   | `await this.callAndStopOnFailure(X, "REQ")`                                                               |
| `callAndContinueOnFailure(X.class, ConditionResult.WARNING, "REQ")`                                      | `await this.callAndContinueOnFailure(X, ConditionResult.WARNING, "REQ")`                                  |
| `skipIfMissing(new String[]{"a"}, null, INFO, X.class, FAILURE, "REQ")`                                  | `await this.skipIfMissing(["a"], null, ConditionResult.INFO, X, ConditionResult.FAILURE, "REQ")`          |
| `skipIfElementMissing("obj", "path", INFO, X.class, WARNING, "REQ")`                                     | `await this.skipIfElementMissing("obj", "path", ConditionResult.INFO, X, ConditionResult.WARNING, "REQ")` |
| `call(sequence(X.class))`                                                                                | `await this.call(this.sequence(X))`                                                                       |
| `call(sequence(() -> new X(arg)))` / `call(sequence(supplier))`                                          | `await this.call(this.sequence(() => new X(arg)))`                                                        |
| `call(new X(args))` (a sequence instance)                                                                | `await this.call(new X(args))`                                                                            |
| `call(condition(X.class).skipIfElementMissing(...).onFail(...).dontStopOnFailure())`                     | `await this.call(this.condition(X)....)`                                                                  |
| `call(exec().mapKey("a", "b"))` / `exec().startBlock("...")` / `exec().unmapKey(...).endBlock()`         | `await this.call(this.exec().mapKey("a", "b"))` ...                                                       |
| `eventLog.startBlock("...")` / `eventLog.endBlock()` / `eventLog.log(getName(), args(...))`              | `this.eventLog.startBlock(...)` ...                                                                       |
| `Class<? extends ConditionSequence> field` / `Supplier<? extends ConditionSequence> field`               | `ConditionSequenceClass \| null` / `ConditionSequenceSupplier \| null`                                    |
| `Class<? extends Condition> field`                                                                       | `ConditionClass \| null`                                                                                  |
| `setStatus(Status.RUNNING)`                                                                              | `await this.setStatus(Status.RUNNING)`                                                                    |
| `fireTestFinished()`                                                                                     | `await this.fireTestFinished()`                                                                           |
| `fireTestSkipped("msg")`                                                                                 | `this.fireTestSkipped("msg")` (throws; use `return this.fireTestSkipped(...)` where Java `return`s after) |
| `fireSetupDone()`                                                                                        | `this.fireSetupDone()`                                                                                    |
| `expose("k", v)` / `exposeEnvString("k")`                                                                | same (sync)                                                                                               |
| `env.mapKey(...)` / `env.putObject(...)`                                                                 | same (sync)                                                                                               |
| `throw new TestFailureException(getId(), "msg")`                                                         | `throw new TestFailureException(this.getId(), "msg")`                                                     |
| `new TestFailureException(getId(), "error", "error_description")`                                        | `TestFailureException.oauthError(this.getId(), "error", "error_description")`                             |
| `getTestExecutionManager().runInBackground(() -> {...; return "done";})`                                 | `this.getTestExecutionManager().runInBackground(async () => {...; return "done";})`                       |
| `Thread.sleep(ms)` inside background tasks                                                               | `await sleep(ms, this.getTestExecutionManager().signal)`                                                  |
| `browser.goToUrl(url)` / `(url, placeholder)` / `(url, placeholder, method)`                             | `this.browser.goToUrl(url, placeholder, method)`                                                          |
| `imageService.getRemainingPlaceholders(getId(), true)`                                                   | `this.imageService.getRemainingPlaceholders(this.getId(), true)`                                          |
| `handleHttp(path, req, res, session, requestParts)` returning `Object`                                   | `override async handleHttp(path, req, res, session, requestParts): Promise<Response>`                     |
| `new ResponseEntity<>(jsonObject, HttpStatus.OK)`                                                        | `jsonResponse(jsonObject, 200)`                                                                           |
| `new ResponseEntity<>(body, headers, HttpStatus.X)`                                                      | `jsonResponse(body, status, headersObject)` or `responseEntity(...)`                                      |
| `new ResponseEntity<Object>("", HttpStatus.NO_CONTENT)`                                                  | `noContent()`                                                                                             |
| `new RedirectView(url, false, false, false)`                                                             | `redirectView(url)`                                                                                       |
| `new ModelAndView("name", ImmutableMap.of("k", v))`                                                      | `modelAndView("name", { k: v })` (register missing templates in `src/framework/views/`)                   |
| `@UserFacing`                                                                                            | drop (comment)                                                                                            |
| `HttpServletRequest req` uses (TLS info)                                                                 | `req.tls?.cipher` etc. (`IncomingHttpRequest`)                                                            |
| `ResponseType.CODE.includesCode()`                                                                       | `ResponseType.CODE.includesCode()` (enum methods are kept)                                                |
| `responseType.toString()`                                                                                | `this.responseType.toString()`                                                                            |
| `Instant.now().getEpochSecond()`                                                                         | `Math.floor(Date.now() / 1000)`                                                                           |

All methods that (transitively) call conditions become `protected async foo(): Promise<void>` and every call site
awaits them. Hooks that Java leaves empty (`onConfigure`, `onPostAuthorizationFlowComplete`) stay `async` too so
subclasses can override them.

**Background tasks and HTTP handlers**: anything Java runs via `runInBackground` keeps that shape; the task's
errors are routed to `handleException` by the framework exactly like Java's BackgroundTask.

**Status/lock**: `setStatus(RUNNING)` acquires the module's async mutex, `WAITING` releases it. Keep every
`setStatus` call where Java has it (incoming HTTP handlers start with `await this.setStatus(Status.RUNNING)` and
end with `await this.setStatus(Status.WAITING)` unless they finish the test).

## Variant enums (`src/variant/*.ts`)

```ts
import { VariantEnum, type VariantParameterInfo } from "../framework/index.ts";

export class ResponseType extends VariantEnum {
	static override readonly parameter: VariantParameterInfo = {
		name: "response_type",
		sortOrder: 40,
		displayName: "Response Type",
		description: "...",
	};
	static readonly CODE = new ResponseType("CODE", ["code"]);
	static readonly ID_TOKEN = new ResponseType("ID_TOKEN", ["id_token"]);
	private readonly types: string[];
	private constructor(name: string, types: string[]) {
		super(name, types.join(" "));
		this.types = types;
	}
	includesCode(): boolean {
		return this.types.includes("code");
	}
}
```

Constants keep the Java names; `toString()`/`value` is the Java `toString()`. `ResponseType.values()`,
`ResponseType.fromString("code id_token")` are provided by the base class.

## Plans (`src/openid/*TestPlan.ts`)

```ts
import { ModuleListEntry, TestPlan, Variant, ProfileNames, SpecFamilyNames, type PublishTestPlan, type VariantSelection } from "../framework/index.ts";

export class OIDCCBasicTestPlan extends TestPlan {
	static override readonly meta: PublishTestPlan = {
		testPlanName: "oidcc-basic-certification-test-plan",
		displayName: "OpenID Connect Core: Basic Certification Profile Authorization server test",
		profile: ProfileNames.optest,
		specFamily: SpecFamilyNames.oidcc,
	};

	override testModulesWithVariants(): ModuleListEntry[] {
		const variantCodeBasic = [new Variant(ResponseType, "code"), new Variant(ClientAuthType, "client_secret_basic"), new Variant(ResponseMode, "default")];
		return [new ModuleListEntry([OIDCCServerTest, OIDCCResponseTypeMissing /* OP-Response-Missing */], variantCodeBasic), ...];
	}

	override certificationProfileName(_variant: VariantSelection): string[] { return ["Basic OP"]; }
}
```

Plans whose `@PublishTestPlan(testModules = {...})` lists modules directly put them in `meta.testModules`.
Keep the comments naming the python test ids (`// OP-Response-code`).

## Registration

Every module and plan must be exported from `src/registry.ts` (modules in `modules`, plans in `plans`) so the
runner and CLI can find them by `testName` / `testPlanName`. Add yours there.
