---
name: java-to-ts-porting
description: The rulebook for porting a Java class (condition, sequence, test module, plan, util) from the upstream OpenID Foundation conformance suite (https://gitlab.com/openid/Conformance-suite) to this TypeScript port. Read it before porting or reviewing any ported file. Covers the 1:1 file mapping, the framework API equivalents, Gson -> JSON mapping, Nimbus -> jose, Spring HTTP -> HttpClient, and the fidelity rules (identical log messages, severities, spec requirement tags).
---

# Porting Java upstream code to TypeScript

The port is **1:1**: one Java class = one TS file with the same name, same relative path, same public
behaviour, same log messages, same spec requirement tags. This is what keeps syncing with upstream cheap
(`.claude/skills/sync-upstream`). Do not "improve" logic, messages, or severities while porting. If upstream
is wrong, port it as is and mark it (see [Marking differences](#marking-differences-from-upstream)).

## Where things live

| Java (`src/main/java/net/openid/conformance/...`)                                                               | TypeScript                                                                      |
| --------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `condition/client/Foo.java`                                                                                     | `src/condition/client/Foo.ts`                                                   |
| `condition/as/Foo.java`, `common/`, `rs/`, `util/`                                                              | `src/condition/as/Foo.ts`, ...                                                  |
| `sequence/client/Foo.java`, `sequence/as/`, `sequence/Foo.java`                                                 | `src/sequence/client/Foo.ts`, ...                                               |
| `util/JWKUtil.java`                                                                                             | `src/util/JWKUtil.ts`                                                           |
| `variant/ClientAuthType.java`                                                                                   | `src/variant/ClientAuthType.ts`                                                 |
| `openid/OIDCCServerTest.java`, `openid/client/...`                                                              | `src/openid/OIDCCServerTest.ts`, ...                                            |
| `testmodule/*`, `condition/AbstractCondition`, `sequence/AbstractConditionSequence`, `frontchannel/*`, `plan/*` | `src/framework/*` (already ported, do not re-port)                              |
| `src/main/resources/templates/foo.html` (Thymeleaf)                                                             | `src/framework/views/foo.ts` (see `port-test-module`)                           |
| Nimbus JOSE+JWT / JDK / Spring library behaviour (not upstream code)                                            | `src/util/nimbus/*.ts`, `src/util/jdk/*.ts`, `src/util/UriComponentsBuilder.ts` |

`upstream.lock.json` lists every lock-tracked file with its Java source path and the blob hash at the pinned
upstream commit (`src/framework` entries are tracked for change detection although the TS is not 1:1; a key
`file.ts::Name` maps a further Java class into an existing TS file). The library emulation in `src/util/nimbus`,
`src/util/jdk` and `src/util/UriComponentsBuilder.ts` has no Java counterpart and is not in the lock. The
upstream checkout used for porting is at `$UPSTREAM` (see the task prompt) or can be fetched with
`npm run sync-upstream -- --fetch`.

## File skeleton

```ts
import { AbstractCondition, args, ConditionResult, OIDFJSON, type Environment, type EnvironmentRequirements, type JsonObject } from "../../framework/index.ts";
import { JWKUtil } from "../../util/JWKUtil.ts";

/** <copy the Java class javadoc, if any> */
export class CheckStateInAuthorizationResponse extends AbstractCondition {
	// @PreEnvironment(required = "authorization_endpoint_response")  ->
	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_response"] };
	// @PostEnvironment(strings = "code") ->
	static override post: EnvironmentRequirements = { strings: ["code"] };

	override evaluate(env: Environment): Environment {
		...
		return env;
	}
}
```

Rules:

- Always import from the barrel `../../framework/index.ts` (adjust the number of `../`). Never from
  `src/framework/<file>.ts` directly (framework files themselves must not import the barrel).
- Imports of other ported classes use relative paths with the `.ts` extension:
  `import { ValidateIdToken } from "./ValidateIdToken.ts";` / `"../common/CheckServerConfiguration.ts"`.
- `extends AbstractX` where AbstractX is another ported class in the same package works as in Java.
- `evaluate` is `override evaluate(env: Environment): Environment` when synchronous, or
  `override async evaluate(env: Environment): Promise<Environment>` when it awaits (HTTP calls, jose).
  Abstract base conditions declare `abstract` members in the same way as Java.
- `static override pre` / `static override post` replace the method annotations (`required`, `strings`,
  `integers`). Omit when absent in Java. Values are arrays even for a single Java string.
  `@PreEnvironment(required = {"a","b"}, strings = "c")` -> `{ required: ["a", "b"], strings: ["c"] }`.
- Node runs the TypeScript directly (type stripping). **Do not use** enums, namespaces, parameter
  properties (`constructor(private x)`), decorators, or `import x = require()`. Use `import type` for types.
  tsconfig has `erasableSyntaxOnly` + `verbatimModuleSyntax` + `noImplicitOverride` to catch this.
- Tabs for indentation, double quotes (oxfmt). Run `npx oxfmt <files>` after writing.
- Keep Java comments, including spec citations and links.

## Framework API equivalents (conditions)

| Java                                                                          | TypeScript                                                                    |
| ----------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| `throw error("msg")`                                                          | `throw this.error("msg")`                                                     |
| `throw error("msg", args("k", v))`                                            | `throw this.error("msg", args("k", v))`                                       |
| `throw error("msg", e)` / `error(e)` / `error("msg", e, args(...))`           | same shapes on `this.error(...)`                                              |
| `logSuccess("msg")`, `logSuccess("msg", args(...))`, `logSuccess(jsonObject)` | `this.logSuccess(...)` (same overloads)                                       |
| `log("msg")`, `log("msg", args(...))`, `log(map)`                             | `this.log(...)`                                                               |
| `logFailure(...)`                                                             | `this.logFailure(...)`                                                        |
| `args("a", 1, "b", 2)`                                                        | `args("a", 1, "b", 2)` (imported from the barrel)                             |
| `ex(e)`, `ex(e, map)`                                                         | `ex(e)`, `ex(e, map)`                                                         |
| `getRequirements()`                                                           | `this.getRequirements()` (a `Set<string>`)                                    |
| `getStringFromEnvironment(env, key, path, name)`                              | `this.getStringFromEnvironment(env, key, path, name)`                         |
| `getJsonObjectFromEnvironment(...)`, `getJsonArrayFromEnvironment(...)`       | same                                                                          |
| `createBrowserInteractionPlaceholder(msg)`                                    | `this.createBrowserInteractionPlaceholder(msg)`                               |
| `Condition.ConditionResult.FAILURE`                                           | `ConditionResult.FAILURE`                                                     |
| `getMessage()`                                                                | `this.getMessage()`                                                           |
| `RandomStringUtils.secure().nextAlphanumeric(n)`                              | `RandomStringUtils.nextAlphanumeric(n)`                                       |
| `Strings.isNullOrEmpty(s)`                                                    | `!s` (for `string \| null`)                                                   |
| `Strings.nullToEmpty(s)`                                                      | `s ?? ""`                                                                     |
| `Instant.now().getEpochSecond()`                                              | `Math.floor(Date.now() / 1000)`                                               |
| `String.format(...)` / `"%s".formatted(x)`                                    | template literal                                                              |
| `Objects.equals(a, b)`                                                        | `a === b`                                                                     |
| `List.of(...)` / `Set.of(...)`                                                | arrays / `new Set([...])`                                                     |
| `BaseEncoding.base64Url()...`                                                 | `Buffer.from(x).toString("base64url")` / `Buffer.from(s, "base64url")`        |
| `URL` parsing where only validity matters                                     | `new URL(s)` (throws on invalid), `URL.canParse(s)`; for `new URI(s)` see JDK |
| `UriComponentsBuilder.fromUriString(u).queryParam(k, v)...toUriString()`      | `toUriString(u, [[k, v], ...])` from `src/util/UriComponentsBuilder.ts`       |
| `URLEncodedUtils.parse(s, charset, '&')`                                      | `[...new URLSearchParams(s).entries()]`                                       |
| `MessageDigest.getInstance("SHA-256").digest(b)`                              | `createHash("sha256").update(b).digest()` from `node:crypto`                  |

## Environment

The Environment API is identical (`getString(key, path)`, `getString(key)`, `putString`, `putObject`, `getObject`,
`containsObject`, `removeObject`, `getElementFromObject`, `getInteger`, `getLong`, `getBoolean`, `putInteger`,
`putLong`, `putBoolean`, `putArray`, `removeElement`, `removeNativeValue`, `mapKey`, `unmapKey`, `isKeyShadowed`,
`getEffectiveKey`, `putObjectFromJsonString`). Nullability: getters return `string | null` etc.; narrow with
`if (x == null)` or `as string` when the Java relied on a `@PreEnvironment` guarantee.

`env.getElementFromObject(key, path)` returns `JsonValue | undefined` (undefined = missing, null = JSON null).
Port Java `if (el == null)` as `if (el == null)` (loose, covers both).

## Gson -> JSON

| Gson                                                         | TypeScript (`src/framework/json.ts`, re-exported by the barrel)                             |
| ------------------------------------------------------------ | ------------------------------------------------------------------------------------------- |
| `JsonObject`                                                 | `JsonObject` (`{ [k: string]: JsonValue }`)                                                 |
| `JsonArray`                                                  | `JsonArray` (`JsonValue[]`)                                                                 |
| `JsonElement`                                                | `JsonValue` (`JsonValue \| undefined` when it may be missing)                               |
| `new JsonObject()`                                           | `{}` typed as `const o: JsonObject = {}`                                                    |
| `o.addProperty("k", v)` / `o.add("k", el)`                   | `o["k"] = v`                                                                                |
| `o.get("k")` (null if missing)                               | `o["k"]` (undefined if missing)                                                             |
| `o.has("k")`                                                 | `has(o, "k")` or `"k" in o`                                                                 |
| `o.remove("k")`                                              | `const v = o["k"]; delete o["k"]`                                                           |
| `o.keySet()` / `o.entrySet()` / `o.size()`                   | `Object.keys(o)` / `Object.entries(o)` / `Object.keys(o).length`                            |
| `el.isJsonObject()` / `isJsonArray()` / `isJsonNull()`       | `isJsonObject(el)` / `isJsonArray(el)` / `el === null`                                      |
| `el.isJsonPrimitive() && el.getAsJsonPrimitive().isString()` | `typeof el === "string"` (or `OIDFJSON.isString(el)`)                                       |
| `...isNumber()` / `...isBoolean()`                           | `typeof el === "number"` / `typeof el === "boolean"`                                        |
| `el.getAsJsonObject()` / `getAsJsonArray()`                  | `el as JsonObject` after an `isJsonObject` check                                            |
| `OIDFJSON.getString(el)` etc.                                | `OIDFJSON.getString(el)` (same strict semantics, throws on wrong type)                      |
| `el.getAsString()` (avoid upstream too)                      | `OIDFJSON.getString(el)` or `String(el)` only where Java coerces                            |
| `JsonParser.parseString(s)`                                  | `parseJson(s)` (throws `JsonParseException`); `parseJsonObject(s)` for `.getAsJsonObject()` |
| `JsonSyntaxException` / `JsonParseException`                 | `JsonParseException`                                                                        |
| `el.toString()` / `gson.toJson(x)`                           | `JSON.stringify(el)`                                                                        |
| `el.deepCopy()`                                              | `deepCopy(el)`                                                                              |
| `a.equals(b)` on elements                                    | `jsonEquals(a, b)`                                                                          |
| `arr.contains(new JsonPrimitive("x"))`                       | `jsonArrayContains(arr, "x")`                                                               |
| `new JsonPrimitive(x)`                                       | `x`                                                                                         |
| `arr.add(x)` / `arr.size()` / `arr.get(i)`                   | `arr.push(x)` / `arr.length` / `arr[i]`                                                     |
| `JsonNull.INSTANCE`                                          | `null`                                                                                      |

`OIDFJSON` holds the `OIDFJSON.java` accessors (`getString`, `getNumber`, `forceConversionToString`, `isString`,
...); there are no Gson-style helpers (`get`, `keySet`, `entrySet`, `isJsonString`): use the object operations
above. `Map<String, Object>` log args are
`Record<string, unknown>`; `JsonObject` and maps are interchangeable in logs.

## Library emulation: `src/util/nimbus`, `src/util/jdk`

The ported util classes (`src/util/JWKUtil.ts`, `JWSUtil.ts`, `JWEUtil.ts`, `JWTUtil.ts`, `JWAUtil.ts`, ...) are
lock-tracked 1:1 ports and contain only their upstream methods (plus re-exports of the emulation, marked
`Not in upstream:`). Where the Java calls a library whose behaviour shows up in the test log (messages, accepted
inputs, JSON member order), the port emulates that library:

- `src/util/nimbus/` - the Nimbus JOSE+JWT API (version pinned by upstream's `pom.xml`, noted in
  `nimbus/algorithms.ts`) on top of `jose`: same JSON member order, exception classes and messages.
- `src/util/jdk/` - JDK behaviour that differs from JS: `java.net.URI` (`uri.ts`), `LdapName`/`Rdn` (`ldap.ts`),
  `InetAddress` (`inet.ts`), X.509 (`x509.ts`), `String`/`Base64`/`URLEncoder` (`strings.ts`).

**Rule: Nimbus or JDK behaviour lives only in `src/util/nimbus` / `src/util/jdk`; never define it inside a
condition or a ported util class.** Look there first; if something is missing, extend it there (one copy,
faithful to the library source, the decision documented in a comment) and give it a `node:test` unit test next to
it (`src/util/{nimbus,jdk}/*.test.ts`) that pins the result and the exception message. Exception messages end up
in the test log, so check them against the real library when you can (`java -cp nimbus-jose-jwt.jar Foo.java`;
the jdk tests were produced with OpenJDK 21).

### Nimbus JOSE -> `jose` / `src/util/nimbus`

| Nimbus                                                                                 | jose / port                                                                                                         |
| -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `JWT jwt = JWTParser.parse(s)`                                                         | `JWTUtil.parseJWT(s)` (adds upstream's character check) or `parseJWT(s)` from `nimbus/jwt.ts` -> `JWT` object       |
| `SignedJWT.parse(s)`                                                                   | `parseSignedJWT(s)` from `nimbus/jwt.ts` (not `JWTUtil.parseJWT` + a type check: the messages differ)               |
| `JWEObject.parse(s)` / `EncryptedJWT.parse(s)`                                         | `parseJWEObject(s)` from `nimbus/jwt.ts`                                                                            |
| `jwt instanceof EncryptedJWT`, `jwt.getHeader().toJSONObject()`, `jwt.serialize()`     | `jwt.type === "encrypted"`, `jwt.header`, `jwt.serialized`                                                          |
| `jwt.getJWTClaimsSet()` (as JSON)                                                      | `JWTUtil.jwtClaimsSetAsJsonObject(jwt)`; then `claims["iss"]` for `getStringClaim("iss")`                           |
| `JWTClaimsSet.parse(json.toString())` + `toJSONObject()` / `toPayload()`               | `parseClaimsSet(json, includeNullValues)` from `nimbus/jwt.ts`                                                      |
| `JWKSet.parse(json)` / `JWK.parse(json)`                                               | `JWKUtil.parseJWKSet(json)` / `parseJWK(json)` (`nimbus/jwk.ts`), JSON-shaped; `importKey(jwk, alg)` -> jose key    |
| `jwk.toPublicJWK()`, `jwk.isPrivate()`, `jwk.getRequiredParams()`                      | `toPublicJWK`, `isPrivate`, `getRequiredParams` (`nimbus/jwk.ts`; the first two also on `JWKUtil`)                  |
| `jwkSet.toJSONObject(publicOnly)`                                                      | `jwkSetToJSONObject` (`nimbus/jwk.ts`), `JWKUtil.getPublicJwksAsJsonObject` / `getPrivateJwksAsJsonObject`          |
| `JWKMatcher.forJWSHeader(header)`, `AlternateJWSVerificationKeySelector.selectJWSJwks` | `jwkMatcherForJWSHeader` (`nimbus/jwk.ts`), `selectJWSJwks(header, jwkSet)` (`nimbus/jws.ts`)                       |
| `KeyType.forAlgorithm`, `Curve.forJWSAlgorithm`, `ECDSA.resolveAlgorithm`              | `keyTypeForAlgorithm`, `curvesForJWSAlgorithm`, `EC_CURVE_ALGORITHM` (`nimbus/algorithms.ts`)                       |
| `JWSAlgorithm.Family.*`, `JWEAlgorithm.Family.*`, `EncryptionMethod.Family.*`          | `JWS_FAMILY_*`, `JWE_FAMILY_*`, `ENC_FAMILY_*` (`nimbus/algorithms.ts`, re-exported by `JWKUtil`)                   |
| `JWSAlgorithm.parse(alg)`                                                              | plain string; validity via `JWSUtil.isValidJWSAlgorithm(alg)`                                                       |
| `RSASSASigner`, `ECDSASigner`, `MACSigner`, `Ed25519Signer`, `DefaultJWSSignerFactory` | `JWSSigner.rsa/ec/mac/ed25519/create` (`nimbus/jws.ts`); `await signer.sign(header, payload)`                       |
| `jwt.verify(verifier)` (`RSASSAVerifier`, `ECDSAVerifier`, `MACVerifier`, ...)         | `await verifySignedJWT(jwt, { jwk, key })` (`nimbus/jws.ts`): the Nimbus verifier checks, then jose `compactVerify` |
| `AlgorithmSupportMessage.unsupportedJWSAlgorithm`                                      | `unsupportedJWSAlgorithm` (`nimbus/jws.ts`)                                                                         |
| `JWEEncrypter` / `JWEDecrypter` implementations                                        | `JWEEncrypter`, `JWEDecrypter` (`nimbus/jwe.ts`), created by `JWEUtil.createEncrypter/createDecrypter`              |
| `JSONObjectUtils.parse/getString/...`                                                  | `nimbusParseJsonObject`, `nimbusGetString`, ... (`nimbus/json.ts`)                                                  |
| `java.text.ParseException`, `JOSEException`, `KeyLengthException`                      | `ParseException`, `JOSEException`, `KeyLengthException`, `isJOSEException(e)` (`nimbus/errors.ts`)                  |
| a `HashMap` whose iteration order decides JSON member order                            | `JavaHashMap` (`nimbus/HashMap.ts`, JDK 21 order)                                                                   |
| `RSAKeyGenerator(2048).keyID(kid).generate()`                                          | `generateKeyPair("RS256", { modulusLength: 2048 })` + `exportJWK`                                                   |
| `Base64URL.encode(bytes)`                                                              | `base64url.encode(bytes)` from jose, or `Buffer...toString("base64url")`                                            |

jose is async: conditions that sign/verify become `async evaluate(...)`. jose also validates more strictly than
Nimbus in places (e.g. unsupported curves); when Java leniently skipped keys, do the same explicitly.

### JDK -> `src/util/jdk`

| Java                                                                  | TypeScript                                                       |
| --------------------------------------------------------------------- | ---------------------------------------------------------------- |
| `new URI(s)` (accept/reject, host, port matter), `URISyntaxException` | `parseJavaURI(s)`, `URISyntaxException` (`jdk/uri.ts`)           |
| `new LdapName(dn).getRdns()`, `Rdn.equals`, `InvalidNameException`    | `parseLdapName`, `rdnEquals`, `InvalidNameException` (`ldap.ts`) |
| `InetAddresses.forString(s)` compared with `InetAddress.equals`       | `inetAddressBytes(s)` (`jdk/inet.ts`)                            |
| `s.getBytes(US_ASCII)`                                                | `Buffer.from(toUsAscii(s), "latin1")` (`jdk/strings.ts`)         |
| `s.isBlank()`, `URLEncoder.encode(s, UTF_8)`                          | `isBlank(s)`, `urlEncode(s)` (`jdk/strings.ts`)                  |
| `Base64.getDecoder().decode(s)`, its `IllegalArgumentException`       | `javaBase64Decode(s)`, `IllegalArgumentException` (`strings.ts`) |
| `CertificateFactory.generateCertificates`, `CertificateException`     | `generateCertificates`, `CertificateException` (`jdk/x509.ts`)   |
| `publicKey.getAlgorithm()`                                            | `javaKeyAlgorithm(key)` (`jdk/x509.ts`)                          |
| `cert.getSubjectX500Principal().getName()`                            | `getSubjectX500PrincipalName(cert)` (`jdk/x509.ts`)              |
| `cert.getSubjectAlternativeNames()`                                   | `getSubjectAlternativeNames(cert)` (`jdk/x509.ts`)               |

## Spring HTTP -> HttpClient

Conditions that call endpoints use `this.createHttpClient(env, restrictAllowedTLSVersions = true, interceptor?)`
(Java `createRestTemplate(env)`; `this.createRestTemplate(env, restrict?)` is an alias, and
`await this.createRestTemplateWithCache(env)` adds the opt-in external endpoint cache, `CachingHttpInterceptor`).
The client uses the `mutual_tls_authentication` certificate unless the condition overrides
`useMtlsForHttpRequests()`, and times out after `getHttpClientTimeoutSeconds()`.

```ts
const client = this.createHttpClient(env);
try {
	const response = await client.exchange({
		url: tokenEndpoint,
		method: "POST",
		headers: headersFromJson(env.getObject("token_endpoint_request_headers")),
		body: new URLSearchParams(formParams), // or a string / JSON object
	});
	// response.status, response.statusText, response.headers (Headers), response.body (string | null)
	const responseInfo = this.convertJsonResponseForEnvironment("token endpoint", response, true);
	env.putObject("token_endpoint_response_full", responseInfo);
} catch (e) {
	if (e instanceof HttpClientException) {
		throw this.error("Call to token endpoint failed - " + e.message, e);
	}
	throw e;
} finally {
	await client.close();
}
```

- Every request/response is logged automatically (like LoggingRequestInterceptor); do not log them again. A
  response replayed by the cache carries `response.cacheAgeSeconds` (Java: `CachedHttpResponseMarker`) and is
  logged as such.
- Redirects are not followed; no HTTP status throws. Spring's default `RestTemplate` throws
  `RestClientResponseException` on 4xx/5xx: when Java relies on that (no custom `ResponseErrorHandler`), port the
  catch block as `if (response.status >= 400) { ...same error... }`. When Java installs a handler returning
  `false` from `hasError`, just use the response.
- `ResponseEntity<String>` -> `HttpResponse`; `response.getStatusCode().value()` -> `response.status`;
  `response.getHeaders()` -> `response.headers`; `response.getBody()` -> `response.body`.
- `mapToJsonObject(response.getHeaders(), true)` -> `mapToJsonObject(response.headers, true)`.
- `HttpHeaders` built from JSON -> `headersFromJson(obj)`; set a header: `headers.set("accept", "application/json")`.
- `MultiValueMap`/`LinkedMultiValueMap` form bodies -> `URLSearchParams` (`.append(k, v)`).
- TLS/cipher probing conditions (`setupSocket`, `FAPITLSClient`) use `node:tls` directly.

## Sequences

```ts
import { AbstractConditionSequence, ConditionResult } from "../../framework/index.ts";

export class PerformStandardIdTokenChecks extends AbstractConditionSequence {
	override evaluate(): void {
		this.callAndContinueOnFailure(ValidateIdToken, ConditionResult.FAILURE, "OIDCC-3.1.3.7");
		this.call(
			this.condition(ValidateEncryptedIdTokenHasKid)
				.skipIfElementMissing("id_token", "jwe_header")
				.onFail(ConditionResult.FAILURE)
				.onSkip(ConditionResult.INFO)
				.requirements("OIDCC-10.2", "OIDCC-10.2.1")
				.dontStopOnFailure(),
		);
	}
}
```

`evaluate()` stays synchronous (it only records calls). Constructor parameters are ordinary TS constructors with
explicit fields (no parameter properties). `call(sequence(Foo))`, `exec().mapKey(...)`, `sequenceOf(...)`,
`replace/skip/insertBefore/insertAfter/then/butFirst` all exist with the Java names. Java `Class<? extends Foo>`
arguments are the class itself (`Foo`), `Supplier<Foo>` is `() => new Foo(...)`.

The builders keep what they collected in a readonly `spec` instead of Java getters:
`ConditionCallBuilder.conditionClass` and `.spec.{requirements, onFail, onSkip, stopOnFailure, skips}`,
`Command.spec.{envCommands, startBlock, endBlock, exposeStrings}`. A unit's type is `unit.unitKind`
(`"condition" | "command" | "sequence" | "sequence-call" | "skipped"`), not `instanceof`. Java's static
`actionToConditionClass` function is `AbstractConditionSequence.actionToConditionClass` (use it with `.map(...)`).

## Test modules

See `.claude/skills/port-test-module/SKILL.md`. Short version: everything that runs conditions is `async` and
`await`ed; `@PublishTestModule` -> `static readonly meta`; variant annotations -> `static override variants`;
HTTP handlers return a web `Response` built with `jsonResponse` / `redirectView` / `modelAndView` / `noContent`;
the runner hands the module its collaborators with `attach({...})` (Java `setProperties`), modules never call it.

## Marking differences from upstream

- `// UPSTREAM: <what Java does>` at every spot where the TS knowingly behaves like questionable upstream code
  (a bug, a dead check, a misleading message) or cannot behave exactly like it (a `NullPointerException` that
  becomes a `TypeError`, a JDK/Spring behaviour with no JS equivalent). Keep the explanation to the difference;
  `grep -rn "UPSTREAM:" src` lists them all.
- `Not in upstream:` marks a member that exists only in the port (re-exports of the emulation, runner hooks).
- A deliberate behaviour change is a deviation: comment it at the code site and add it to the list below.

## Deliberate deviations from upstream

Everything else is 1:1; these are the known, intentional differences (each is commented at the code site):

- `src/util/UriComponentsBuilder.ts` encodes `+` in query parameters as `%2B`. Spring leaves it alone, but every
  form-decoding server reads a literal `+` as a space, which broke suite-vs-suite with the client ids the RP
  tests generate.
- `src/framework/BrowserControl.ts` records a url as visited when the navigation starts (Java: after
  `driver.get()` returns). A user-driven browser records it before the RP redirects, which is what
  `oidcc-client-test-3rd-party-init-login` checks for.
- `src/framework/views/checkSessionIFrame.ts` splits the postMessage `"client_id session_state"` on the last
  space; the template splits on the first one and breaks with client ids containing spaces.
- `AbstractTestModule.setKeepServingAfterFinish()` lets the RP test module acting as emulated OP in
  suite-vs-suite runs answer requests after its own flow finished (FINISHED -> RUNNING/WAITING is allowed then).
- `src/framework/server.ts` adds `x-ssl-protocol` / `x-ssl-cipher` to incoming requests over TLS, which the
  nginx/apache proxy adds upstream.
- `src/runner/TestRunner.ts` starts modules with `autoStart() == false` right away and logs a `TEST-RUNNER` INFO
  entry saying so (upstream's CI script does the same for `oidcc-server-rotate-keys`).

## Fidelity checklist (review every ported file against it)

- [ ] Same class name, same file path, same `extends`.
- [ ] Every `log*`/`error` message string is identical (copy-paste; keep typos).
- [ ] Every requirement tag (`"OIDCC-3.1.3.7"`, `"RFC6749-5.1"`) is preserved in the same call.
- [ ] Every `ConditionResult` severity is unchanged; `callAndStopOnFailure` vs `callAndContinueOnFailure` unchanged.
- [ ] Pre/Post environment requirements preserved.
- [ ] Order of checks and side effects on `env` unchanged (keys written/removed/mapped).
- [ ] Null/empty semantics match (`Strings.isNullOrEmpty` -> `!s`; missing vs JSON null).
- [ ] No behaviour added, removed or "fixed"; questionable upstream behaviour gets an `// UPSTREAM:` comment.
- [ ] No Nimbus/JDK emulation defined in the file: it imports it from `src/util/nimbus` / `src/util/jdk`.
- [ ] `npx tsc --noEmit` passes for the file's imports; `npx oxlint` and `npx oxfmt` clean.
