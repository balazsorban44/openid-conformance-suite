# Upstream changes

Upstream moved from [`949724883989`](https://gitlab.com/openid/Conformance-suite/-/commit/949724883989f9f067ea728c7c13cacc18bbd81f) to [`845ce4562d1c`](https://gitlab.com/openid/Conformance-suite/-/commit/845ce4562d1c483edd7c5cc2390f5e910c5f94da) (2026-10-16, [compare](https://gitlab.com/openid/Conformance-suite/-/compare/949724883989f9f067ea728c7c13cacc18bbd81f...845ce4562d1c483edd7c5cc2390f5e910c5f94da)). 9 ported symbols have upstream changes.

| Ported in | Upstream file | Change |
|---|---|---|
| `src/op/discovery-endpoint.ts#performFapi2EndpointVerification` | [fapi2spfinal/AbstractFAPI2SPFinalDiscoveryEndpointVerification.java](https://gitlab.com/openid/Conformance-suite/-/blob/845ce4562d1c483edd7c5cc2390f5e910c5f94da/src/main/java/net/openid/conformance/fapi2spfinal/AbstractFAPI2SPFinalDiscoveryEndpointVerification.java) | +2 −2 |
| `src/op/id-token.ts#validateIdTokenNonce` | [condition/client/ValidateIdTokenNonce.java](https://gitlab.com/openid/Conformance-suite/-/blob/845ce4562d1c483edd7c5cc2390f5e910c5f94da/src/main/java/net/openid/conformance/condition/client/ValidateIdTokenNonce.java) | +5 −1 |
| `src/op/tls.ts#checkInsecureCiphers` | [condition/common/AbstractCheckInsecureCiphers.java](https://gitlab.com/openid/Conformance-suite/-/blob/845ce4562d1c483edd7c5cc2390f5e910c5f94da/src/main/java/net/openid/conformance/condition/common/AbstractCheckInsecureCiphers.java) | +11 −4 |
| `src/op/token.ts#callTokenEndpointAllowingTLSFailure` | [condition/client/CallTokenEndpointAllowingTLSFailure.java](https://gitlab.com/openid/Conformance-suite/-/blob/845ce4562d1c483edd7c5cc2390f5e910c5f94da/src/main/java/net/openid/conformance/condition/client/CallTokenEndpointAllowingTLSFailure.java) | +2 −7 |
| `src/rp/fapi2.ts#startEmulatedFapi2As` | [fapi2spfinal/AbstractFAPI2SPFinalClientTest.java](https://gitlab.com/openid/Conformance-suite/-/blob/845ce4562d1c483edd7c5cc2390f5e910c5f94da/src/main/java/net/openid/conformance/fapi2spfinal/AbstractFAPI2SPFinalClientTest.java) | +16 −4 |
| `src/rp/jwks.ts#augmentRealJwksWithDecoys` | [condition/client/AugmentRealJwksWithDecoys.java](https://gitlab.com/openid/Conformance-suite/-/blob/845ce4562d1c483edd7c5cc2390f5e910c5f94da/src/main/java/net/openid/conformance/condition/client/AugmentRealJwksWithDecoys.java) | +85 −30 |
| `src/rp/jwks.ts#setRsaAltServerJwks` | [condition/as/SetRsaAltServerJwks.java](https://gitlab.com/openid/Conformance-suite/-/blob/845ce4562d1c483edd7c5cc2390f5e910c5f94da/src/main/java/net/openid/conformance/condition/as/SetRsaAltServerJwks.java) | +12 −7 |
| `tests/rp/3rdparty-init-login.spec.ts#oidcc-client-test-3rd-party-init-login` | [openid/client/OIDCCClient3rdPartyInitiatedLoginTest.java](https://gitlab.com/openid/Conformance-suite/-/blob/845ce4562d1c483edd7c5cc2390f5e910c5f94da/src/main/java/net/openid/conformance/openid/client/OIDCCClient3rdPartyInitiatedLoginTest.java) | +41 −16 |
| `tests/rp/fapi2-message-signing.spec.ts#fapi2-security-profile-final-client-test-happy-path-no-mtls-endpoint-aliases` | [fapi2spfinal/FAPI2SPFinalClientTestHappyPathNoMtlsEndpointAliases.java](https://gitlab.com/openid/Conformance-suite/-/blob/845ce4562d1c483edd7c5cc2390f5e910c5f94da/src/main/java/net/openid/conformance/fapi2spfinal/FAPI2SPFinalClientTestHappyPathNoMtlsEndpointAliases.java) | +3 −0 |

### `src/op/discovery-endpoint.ts#performFapi2EndpointVerification`

[fapi2spfinal/AbstractFAPI2SPFinalDiscoveryEndpointVerification.java](https://gitlab.com/openid/Conformance-suite/-/blob/845ce4562d1c483edd7c5cc2390f5e910c5f94da/src/main/java/net/openid/conformance/fapi2spfinal/AbstractFAPI2SPFinalDiscoveryEndpointVerification.java)

```diff
diff --git a/src/main/java/net/openid/conformance/fapi2spfinal/AbstractFAPI2SPFinalDiscoveryEndpointVerification.java b/src/main/java/net/openid/conformance/fapi2spfinal/AbstractFAPI2SPFinalDiscoveryEndpointVerification.java
index 58bfac73f..94b328d15 100644
--- a/src/main/java/net/openid/conformance/fapi2spfinal/AbstractFAPI2SPFinalDiscoveryEndpointVerification.java
+++ b/src/main/java/net/openid/conformance/fapi2spfinal/AbstractFAPI2SPFinalDiscoveryEndpointVerification.java
@@ -62,7 +62,7 @@ public abstract class AbstractFAPI2SPFinalDiscoveryEndpointVerification extends
 	{
 		@Override
 		public void evaluate() {
-			callAndContinueOnFailure(EnsureServerConfigurationSupportsMTLS.class, Condition.ConditionResult.FAILURE, "FAPI2-SP-FINAL-5.3.3.1-5");
+			callAndContinueOnFailure(EnsureServerConfigurationSupportsMTLS.class, Condition.ConditionResult.FAILURE, "FAPI2-SP-FINAL-5.3.2.1-6");
 
 		}
 	}
@@ -130,7 +130,7 @@ public abstract class AbstractFAPI2SPFinalDiscoveryEndpointVerification extends
 		if (isDpop) {
 			callAndContinueOnFailure(FAPI2CheckDpopSigningAlgValuesSupported.class, Condition.ConditionResult.FAILURE, "FAPI2-SP-FINAL-5.4-1");
 		} else {
-			callAndContinueOnFailure(CheckTLSClientCertificateBoundAccessTokensTrue.class, Condition.ConditionResult.FAILURE, "FAPI2-SP-FINAL-5.3.3.1-5", "RFC8705-3.3");
+			callAndContinueOnFailure(CheckTLSClientCertificateBoundAccessTokensTrue.class, Condition.ConditionResult.FAILURE, "FAPI2-SP-FINAL-5.3.2.1-5", "RFC8705-3.3");
 		}
 
 		if (! clientCredentialsGrant && isOpenId) {

```

### `src/op/id-token.ts#validateIdTokenNonce`

[condition/client/ValidateIdTokenNonce.java](https://gitlab.com/openid/Conformance-suite/-/blob/845ce4562d1c483edd7c5cc2390f5e910c5f94da/src/main/java/net/openid/conformance/condition/client/ValidateIdTokenNonce.java)

```diff
diff --git a/src/main/java/net/openid/conformance/condition/client/ValidateIdTokenNonce.java b/src/main/java/net/openid/conformance/condition/client/ValidateIdTokenNonce.java
index b1cd18992..eb46c4c53 100644
--- a/src/main/java/net/openid/conformance/condition/client/ValidateIdTokenNonce.java
+++ b/src/main/java/net/openid/conformance/condition/client/ValidateIdTokenNonce.java
@@ -14,7 +14,11 @@ public class ValidateIdTokenNonce extends AbstractCondition {
 
 		String expectedNonce = env.getString("nonce");
 
-		if (incomingNonce == null && expectedNonce == null) {
+		if (expectedNonce == null) {
+			if (incomingNonce != null) {
+				throw error("id_token contains a nonce claim, but no nonce was sent in the authorization request.",
+					args("actual", incomingNonce));
+			}
 			logSuccess("nonce is not in id_token, as expected.");
 			return env;
 		}

```

### `src/op/tls.ts#checkInsecureCiphers`

[condition/common/AbstractCheckInsecureCiphers.java](https://gitlab.com/openid/Conformance-suite/-/blob/845ce4562d1c483edd7c5cc2390f5e910c5f94da/src/main/java/net/openid/conformance/condition/common/AbstractCheckInsecureCiphers.java)

```diff
diff --git a/src/main/java/net/openid/conformance/condition/common/AbstractCheckInsecureCiphers.java b/src/main/java/net/openid/conformance/condition/common/AbstractCheckInsecureCiphers.java
index d0b7adf52..a81b91787 100644
--- a/src/main/java/net/openid/conformance/condition/common/AbstractCheckInsecureCiphers.java
+++ b/src/main/java/net/openid/conformance/condition/common/AbstractCheckInsecureCiphers.java
@@ -6,6 +6,7 @@ import net.openid.conformance.condition.ConditionError;
 import net.openid.conformance.condition.PreEnvironment;
 import net.openid.conformance.condition.util.NoopTlsAuthentication;
 import net.openid.conformance.testmodule.Environment;
+import net.openid.conformance.util.FAPITLSClient.ServerHelloReceived;
 import org.bouncycastle.tls.AlertDescription;
 import org.bouncycastle.tls.DefaultTlsClient;
 import org.bouncycastle.tls.NameType;
@@ -134,10 +135,9 @@ public abstract class AbstractCheckInsecureCiphers extends AbstractCondition {
 
 	/**
 	 * Connect with TLS 1.2 + BC's default cipher list to determine whether the server
-	 * supports TLS 1.2 at all. Returns true on a completed handshake; false when the
-	 * server rejects the handshake at the TLS layer (protocol_version, handshake_failure,
-	 * or TCP reset). Any other IOException is treated as an unexpected probe failure and
-	 * surfaced via {@code throw error(...)} so it remains attributable.
+	 * supports TLS 1.2. Stop at ServerHello so client authentication is not required.
+	 * Returns false when the server rejects the probe before ServerHello with
+	 * protocol_version, handshake_failure, or TCP reset. Other errors fail the probe.
 	 */
 	private boolean probeTls12Supported(String host, int port) {
 		Socket socket = null;
@@ -159,9 +159,16 @@ public abstract class AbstractCheckInsecureCiphers extends AbstractCondition {
 				protected Vector<ServerName> getSNIServerNames() {
 					return new Vector<ServerName>(List.of(new ServerName(NameType.host_name, host.getBytes(StandardCharsets.UTF_8))));
 				}
+
+				@Override
+				public void notifyServerVersion(ProtocolVersion serverVersion) throws IOException {
+					throw new ServerHelloReceived(serverVersion);
+				}
 			};
 			protocol.connect(client);
 			return true;
+		} catch (ServerHelloReceived e) {
+			return ProtocolVersion.TLSv12.equals(e.getServerVersion());
 		} catch (IOException e) {
 			if ((e instanceof TlsFatalAlertReceived received)
 					&& (received.getAlertDescription() == AlertDescription.protocol_version

```

### `src/op/token.ts#callTokenEndpointAllowingTLSFailure`

[condition/client/CallTokenEndpointAllowingTLSFailure.java](https://gitlab.com/openid/Conformance-suite/-/blob/845ce4562d1c483edd7c5cc2390f5e910c5f94da/src/main/java/net/openid/conformance/condition/client/CallTokenEndpointAllowingTLSFailure.java)

```diff
diff --git a/src/main/java/net/openid/conformance/condition/client/CallTokenEndpointAllowingTLSFailure.java b/src/main/java/net/openid/conformance/condition/client/CallTokenEndpointAllowingTLSFailure.java
index 3e56858ac..837f69ecb 100644
--- a/src/main/java/net/openid/conformance/condition/client/CallTokenEndpointAllowingTLSFailure.java
+++ b/src/main/java/net/openid/conformance/condition/client/CallTokenEndpointAllowingTLSFailure.java
@@ -3,12 +3,8 @@ package net.openid.conformance.condition.client;
 import com.google.gson.JsonParseException;
 import net.openid.conformance.condition.PreEnvironment;
 import net.openid.conformance.testmodule.Environment;
-import org.springframework.web.client.ResourceAccessException;
 import org.springframework.web.client.RestClientException;
 
-import javax.net.ssl.SSLException;
-import java.net.SocketException;
-
 public class CallTokenEndpointAllowingTLSFailure extends CallTokenEndpointAndReturnFullResponse {
 
 	@Override
@@ -22,10 +18,9 @@ public class CallTokenEndpointAllowingTLSFailure extends CallTokenEndpointAndRet
 
 	@Override
 	protected Environment handleClientException(Environment env, RestClientException e) {
-		if (e instanceof ResourceAccessException &&
-			(e.getCause() instanceof SSLException || e.getCause() instanceof SocketException)) {
+		if (TlsConnectionFailure.isTlsConnectionFailure(e)) {
 			env.putBoolean("token_endpoint_response_ssl_error", true);
-			logSuccess("Call to token_endpoint failed due to a TLS issue", ex(e));
+			logSuccess("Call to token_endpoint was rejected at the TLS or connection level", ex(e));
 			return env;
 		}
 		return super.handleClientException(env, e);

```

### `src/rp/fapi2.ts#startEmulatedFapi2As`

[fapi2spfinal/AbstractFAPI2SPFinalClientTest.java](https://gitlab.com/openid/Conformance-suite/-/blob/845ce4562d1c483edd7c5cc2390f5e910c5f94da/src/main/java/net/openid/conformance/fapi2spfinal/AbstractFAPI2SPFinalClientTest.java)

```diff
diff --git a/src/main/java/net/openid/conformance/fapi2spfinal/AbstractFAPI2SPFinalClientTest.java b/src/main/java/net/openid/conformance/fapi2spfinal/AbstractFAPI2SPFinalClientTest.java
index aa3013d71..ef25bda11 100644
--- a/src/main/java/net/openid/conformance/fapi2spfinal/AbstractFAPI2SPFinalClientTest.java
+++ b/src/main/java/net/openid/conformance/fapi2spfinal/AbstractFAPI2SPFinalClientTest.java
@@ -32,6 +32,8 @@ import net.openid.conformance.condition.as.CheckClientIdMatchesOnTokenRequestIfP
 import net.openid.conformance.condition.as.CheckForClientCertificate;
 import net.openid.conformance.condition.as.CheckForUnexpectedClaimsInRequestObject;
 import net.openid.conformance.condition.as.CheckForUnexpectedOpenIdClaims;
+import net.openid.conformance.condition.as.CheckForUnexpectedParametersInSignedPAREndpointRequest;
+import net.openid.conformance.condition.as.CheckForUnexpectedParametersInSignedPAREndpointRequestWithClientAssertion;
 import net.openid.conformance.condition.as.CheckPkceCodeVerifier;
 import net.openid.conformance.condition.as.CheckRequestClaimsParameterMemberValues;
 import net.openid.conformance.condition.as.CheckRequestClaimsParameterValues;
@@ -61,6 +63,8 @@ import net.openid.conformance.condition.as.EnsurePAREndpointRequestDoesNotContai
 import net.openid.conformance.condition.as.EnsureRequestObjectDoesNotContainRequestOrRequestUri;
 import net.openid.conformance.condition.as.EnsureRequestObjectDoesNotContainSubWithClientId;
 import net.openid.conformance.condition.as.EnsureResponseTypeIsCode;
+import net.openid.conformance.condition.as.EnsureSignedPAREndpointRequestContainsRequestParameter;
+import net.openid.conformance.condition.as.EnsureUnsignedPAREndpointRequestDoesNotContainRequestParameter;
 import net.openid.conformance.condition.as.ExtractClientCertificateFromRequestHeaders;
 import net.openid.conformance.condition.as.ExtractNonceFromAuthorizationRequest;
 import net.openid.conformance.condition.as.ExtractParAuthorizationCodeDpopBindingKey;
@@ -725,8 +729,7 @@ public abstract class AbstractFAPI2SPFinalClientTest extends AbstractTestModule
 		}
 		callAndContinueOnFailure(AugmentRealJwksWithDecoys.class, ConditionResult.WARNING, "FAPI2-SP-FINAL-5.4.3-3");
 		callAndStopOnFailure(SetRsaAltServerJwks.class);
-		// published in all RP tests so the check does not depend on when the client last fetched/cached
-		// the JWKS; must stay after SetRsaAltServerJwks, which rebuilds server_public_jwks
+		// published in all RP tests so the check does not depend on when the client last fetched/cached the JWKS
 		callAndStopOnFailure(AddUnusableKeysToServerPublicJwks.class, "RFC7517-5");
 	}
 
@@ -1199,9 +1202,18 @@ public abstract class AbstractFAPI2SPFinalClientTest extends AbstractTestModule
 	}
 
 	protected void extractParEndpointRequest() {
-		skipIfElementMissing("par_endpoint_http_request", "body_form_params.request", ConditionResult.INFO, ExtractRequestObjectFromPAREndpointRequest.class, ConditionResult.FAILURE, "PAR-3");
+		if (fapi2AuthRequestMethod == FAPI2AuthRequestMethod.SIGNED_NON_REPUDIATION) {
+			callAndStopOnFailure(EnsureSignedPAREndpointRequestContainsRequestParameter.class, "FAPI2-MS-ID1-5.3.2-1");
+			callAndStopOnFailure(ExtractRequestObjectFromPAREndpointRequest.class, "PAR-3");
+			if (clientAuthType == ClientAuthType.PRIVATE_KEY_JWT) {
+				callAndContinueOnFailure(CheckForUnexpectedParametersInSignedPAREndpointRequestWithClientAssertion.class, ConditionResult.FAILURE, "PAR-3");
+			} else {
+				callAndContinueOnFailure(CheckForUnexpectedParametersInSignedPAREndpointRequest.class, ConditionResult.FAILURE, "PAR-3");
+			}
+		} else {
+			callAndStopOnFailure(EnsureUnsignedPAREndpointRequestDoesNotContainRequestParameter.class);
+		}
 		callAndStopOnFailure(EnsurePAREndpointRequestDoesNotContainRequestUriParameter.class, "PAR-2.1");
-		call(profileBehavior.additionalParRequestChecks());
 		skipIfElementMissing("authorization_request_object", "jwe_header", ConditionResult.INFO, ValidateEncryptedRequestObjectHasKid.class, ConditionResult.FAILURE, "OIDCC-10.2", "OIDCC-10.2.1");
 	}
 

```

### `src/rp/jwks.ts#augmentRealJwksWithDecoys`

[condition/client/AugmentRealJwksWithDecoys.java](https://gitlab.com/openid/Conformance-suite/-/blob/845ce4562d1c483edd7c5cc2390f5e910c5f94da/src/main/java/net/openid/conformance/condition/client/AugmentRealJwksWithDecoys.java)

```diff
diff --git a/src/main/java/net/openid/conformance/condition/client/AugmentRealJwksWithDecoys.java b/src/main/java/net/openid/conformance/condition/client/AugmentRealJwksWithDecoys.java
index 04bb5b03c..2e5fbb06e 100644
--- a/src/main/java/net/openid/conformance/condition/client/AugmentRealJwksWithDecoys.java
+++ b/src/main/java/net/openid/conformance/condition/client/AugmentRealJwksWithDecoys.java
@@ -1,6 +1,9 @@
 package net.openid.conformance.condition.client;
 
+import com.google.gson.JsonArray;
+import com.google.gson.JsonElement;
 import com.google.gson.JsonObject;
+import com.google.gson.JsonParser;
 import com.nimbusds.jose.Algorithm;
 import com.nimbusds.jose.JOSEException;
 import com.nimbusds.jose.jwk.ECKey;
@@ -12,6 +15,7 @@ import com.nimbusds.jose.jwk.RSAKey;
 import net.openid.conformance.condition.AbstractCondition;
 import net.openid.conformance.condition.PreEnvironment;
 import net.openid.conformance.testmodule.Environment;
+import net.openid.conformance.testmodule.OIDFJSON;
 import net.openid.conformance.util.JWKUtil;
 
 import java.util.ArrayList;
@@ -25,6 +29,9 @@ import java.util.Set;
 /**
  * Adds additional "decoy" JWKs with the same kid but different algorithms to the {@code server_public_jwks} JWKSet to ensure that
  * clients perform proper JWK lookups by {@code kid} including {@code alg} and {@code kty}.
+ *
+ * <p>The signing key is selected from {@code server_jwks}. One decoy is inserted immediately before and one immediately after that
+ * key in {@code server_public_jwks} (derived from {@code server_jwks} if not yet present); all other published keys are kept.
  */
 public class AugmentRealJwksWithDecoys extends AbstractCondition {
 
@@ -81,17 +88,78 @@ public class AugmentRealJwksWithDecoys extends AbstractCondition {
 			return env;
 		}
 
-		JsonObject publicJwksWithDecoys = generateDecoyPublicKeysAroundGivenPublicKey(env, publicKey);
+		// decoys exercise selection among keys sharing a kid; without a kid there is nothing to share
+		if (publicKey.getKeyID() == null) {
+			logSuccess("Skipping JWKS decoy generation for server_jwks signing key without a kid.");
+			return env;
+		}
+
+		// edited as JSON rather than via JWKSet so already-published keys Nimbus cannot parse are kept
+		JsonObject existingPublicJwks = env.getObject("server_public_jwks");
+		if (existingPublicJwks == null) {
+			existingPublicJwks = JWKUtil.getPublicJwksAsJsonObject(publicJWKSet);
+		}
+		if (!JWKUtil.hasKeysArray(existingPublicJwks)) {
+			throw error("server_public_jwks does not contain a 'keys' array", args("server_public_jwks", existingPublicJwks));
+		}
+		JsonArray existingKeys = existingPublicJwks.getAsJsonArray("keys");
+
+		int realKeyIndex = indexOfKey(existingKeys, publicKey);
+		if (realKeyIndex < 0) {
+			throw error("server_public_jwks does not contain the server signing key from server_jwks",
+				args("server_public_jwks", existingPublicJwks, "kid", publicKey.getKeyID(), "alg", publicKey.getAlgorithm().getName()));
+		}
+
+		List<JWK> decoys = generateDecoyPublicKeys(env, publicKey);
+		JsonArray keysWithDecoys = new JsonArray();
+		for (int i = 0; i < existingKeys.size(); i++) {
+			if (i == realKeyIndex) {
+				keysWithDecoys.add(toJsonObject(decoys.get(0)));
+			}
+			keysWithDecoys.add(existingKeys.get(i).deepCopy());
+			if (i == realKeyIndex) {
+				keysWithDecoys.add(toJsonObject(decoys.get(1)));
+			}
+		}
+		JsonObject publicJwksWithDecoys = existingPublicJwks.deepCopy();
+		publicJwksWithDecoys.add("keys", keysWithDecoys);
 
-		// augment the current server_public_jwks with additional decoy keys
 		env.putObject("server_public_jwks", publicJwksWithDecoys);
 
-		logSuccess("Augmented JWKS with decoy keys.", Map.of("existingJwks", publicJWKSet, "jwksWithDecoys", publicJwksWithDecoys));
+		logSuccess("Augmented JWKS with decoy keys.", Map.of("existingJwks", existingPublicJwks, "jwksWithDecoys", publicJwksWithDecoys));
 
 		return env;
 	}
 
-	JsonObject generateDecoyPublicKeysAroundGivenPublicKey(Environment env, JWK publicKey) {
+	private static int indexOfKey(JsonArray keys, JWK key) {
+		String kid = key.getKeyID();
+		String alg = key.getAlgorithm().getName();
+		for (int i = 0; i < keys.size(); i++) {
+			if (!keys.get(i).isJsonObject()) {
+				continue;
+			}
+			JsonObject candidate = keys.get(i).getAsJsonObject();
+			if (isStringEqual(candidate.get("kid"), kid) && isStringEqual(candidate.get("alg"), alg)) {
+				return i;
+			}
+		}
+		return -1;
+	}
+
+	private static boolean isStringEqual(JsonElement element, String value) {
+		return element != null && element.isJsonPrimitive() && element.getAsJsonPrimitive().isString()
+			&& OIDFJSON.getString(element).equals(value);
+	}
+
+	private static JsonObject toJsonObject(JWK jwk) {
+		return JsonParser.parseString(jwk.toJSONString()).getAsJsonObject();
+	}
+
+	/**
+	 * Generates two decoy public keys with the same kid as the given key but different algorithms. The first decoy is published
+	 * before the real key and the second after it.
+	 */
+	List<JWK> generateDecoyPublicKeys(Environment env, JWK publicKey) {
 
 		String keyID = publicKey.getKeyID();
 		Algorithm alg = publicKey.getAlgorithm();
@@ -120,33 +188,20 @@ public class AugmentRealJwksWithDecoys extends AbstractCondition {
 			}
 		};
 
-		List<JWK> keysWithDecoys = new ArrayList<>();
-		// generate decoy keys
-		switch (alg.getName()) {
-			case "ES256":
-				// generate decoys with same kid for the "other" algorithms
-				keysWithDecoys.add(keyGenerator.createJwkForAlg(env, "EdDSA")); // decoy jwk
-				keysWithDecoys.add(publicKey); // real jwk
-				keysWithDecoys.add(keyGenerator.createJwkForAlg(env, "PS256")); // decoy jwk
-				break;
-			case "EdDSA":
-			case "Ed25519":
-				// EdDSA and Ed25519 are the same curve/kty, so they're treated as the same "family" here
-				keysWithDecoys.add(keyGenerator.createJwkForAlg(env, "ES256"));
-				keysWithDecoys.add(publicKey); // real jwk
-				keysWithDecoys.add(keyGenerator.createJwkForAlg(env, "PS256"));
-				break;
-			case "PS256":
-				keysWithDecoys.add(keyGenerator.createJwkForAlg(env, "EdDSA"));
-				keysWithDecoys.add(publicKey); // real jwk
-				keysWithDecoys.add(keyGenerator.createJwkForAlg(env, "ES256"));
-				break;
-			default:
-				throw error("Invalid FAPI alg detected in JWK", Map.of("alg", alg.getName()));
-		}
+		// generate decoys with same kid for the "other" algorithms
+		List<String> decoyAlgs = switch (alg.getName()) {
+			case "ES256" -> List.of("EdDSA", "PS256");
+			// EdDSA and Ed25519 are the same curve/kty, so they're treated as the same "family" here
+			case "EdDSA", "Ed25519" -> List.of("ES256", "PS256");
+			case "PS256" -> List.of("EdDSA", "ES256");
+			default -> throw error("Invalid FAPI alg detected in JWK", Map.of("alg", alg.getName()));
+		};
 
-		// generate a new JWKS with the real key and the decoys
-		return JWKUtil.getPublicJwksAsJsonObject(new JWKSet(keysWithDecoys));
+		List<JWK> decoys = new ArrayList<>();
+		for (String decoyAlg : decoyAlgs) {
+			decoys.add(keyGenerator.createJwkForAlg(env, decoyAlg).toPublicJWK());
+		}
+		return decoys;
 	}
 
 	/**

```

### `src/rp/jwks.ts#setRsaAltServerJwks`

[condition/as/SetRsaAltServerJwks.java](https://gitlab.com/openid/Conformance-suite/-/blob/845ce4562d1c483edd7c5cc2390f5e910c5f94da/src/main/java/net/openid/conformance/condition/as/SetRsaAltServerJwks.java)

```diff
diff --git a/src/main/java/net/openid/conformance/condition/as/SetRsaAltServerJwks.java b/src/main/java/net/openid/conformance/condition/as/SetRsaAltServerJwks.java
index d45fb7a72..ec443c5d4 100644
--- a/src/main/java/net/openid/conformance/condition/as/SetRsaAltServerJwks.java
+++ b/src/main/java/net/openid/conformance/condition/as/SetRsaAltServerJwks.java
@@ -1,6 +1,7 @@
 package net.openid.conformance.condition.as;
 
 import com.google.gson.JsonObject;
+import com.google.gson.JsonParser;
 import com.nimbusds.jose.jwk.JWK;
 import com.nimbusds.jose.jwk.JWKSet;
 import net.openid.conformance.condition.AbstractCondition;
@@ -10,12 +11,11 @@ import net.openid.conformance.testmodule.Environment;
 import net.openid.conformance.util.JWKUtil;
 
 import java.text.ParseException;
-import java.util.ArrayList;
-import java.util.List;
 
 /**
  * Set an RSA key with no specified alg as the alt signing JWK.
- * The new public key is also added to the server's list of public keys in the jwks_uri
+ * The new public key is also appended to the server's list of public keys in the jwks_uri ({@code server_public_jwks},
+ * derived from {@code server_jwks} if not yet present); keys already published there are kept.
  */
 public class SetRsaAltServerJwks extends AbstractCondition {
 
@@ -52,10 +52,15 @@ public class SetRsaAltServerJwks extends AbstractCondition {
 			// Alt RSA signing key with alg NONE.
 			JWK altPrivateKey = JWK.parse(altRsaKey);
 
-			List<JWK> newJwksList = new ArrayList<>(jwks.getKeys());
-			newJwksList.add(altPrivateKey);
-			JWKSet newJwkSet = new JWKSet(newJwksList);
-			JsonObject publicJwks = JWKUtil.getPublicJwksAsJsonObject(newJwkSet);
+			// edited as JSON rather than via JWKSet so already-published keys Nimbus cannot parse are kept
+			JsonObject existingPublicJwks = env.getObject("server_public_jwks");
+			JsonObject publicJwks = existingPublicJwks != null
+				? existingPublicJwks.deepCopy()
+				: JWKUtil.getPublicJwksAsJsonObject(jwks);
+			if (!JWKUtil.hasKeysArray(publicJwks)) {
+				throw error("server_public_jwks does not contain a 'keys' array", args("server_public_jwks", publicJwks));
+			}
+			publicJwks.getAsJsonArray("keys").add(JsonParser.parseString(altPrivateKey.toPublicJWK().toJSONString()));
 
 			env.putObject("server_public_jwks", publicJwks);
 			log("generated new alt RSA key configuration");

```

### `tests/rp/3rdparty-init-login.spec.ts#oidcc-client-test-3rd-party-init-login`

[openid/client/OIDCCClient3rdPartyInitiatedLoginTest.java](https://gitlab.com/openid/Conformance-suite/-/blob/845ce4562d1c483edd7c5cc2390f5e910c5f94da/src/main/java/net/openid/conformance/openid/client/OIDCCClient3rdPartyInitiatedLoginTest.java)

```diff
diff --git a/src/main/java/net/openid/conformance/openid/client/OIDCCClient3rdPartyInitiatedLoginTest.java b/src/main/java/net/openid/conformance/openid/client/OIDCCClient3rdPartyInitiatedLoginTest.java
index 26c8fc141..5a9b66a7c 100644
--- a/src/main/java/net/openid/conformance/openid/client/OIDCCClient3rdPartyInitiatedLoginTest.java
+++ b/src/main/java/net/openid/conformance/openid/client/OIDCCClient3rdPartyInitiatedLoginTest.java
@@ -3,6 +3,8 @@ package net.openid.conformance.openid.client;
 import net.openid.conformance.condition.as.dynregistration.ValidateClientInitiateLoginUri;
 import net.openid.conformance.testmodule.PublishTestModule;
 import net.openid.conformance.testmodule.TestFailureException;
+import net.openid.conformance.variant.ClientRegistration;
+import net.openid.conformance.variant.VariantConfigurationFields;
 import org.springframework.web.util.UriComponentsBuilder;
 
 @PublishTestModule(
@@ -13,34 +15,57 @@ import org.springframework.web.util.UriComponentsBuilder;
 	configurationFields = {
 	}
 )
+@VariantConfigurationFields(parameter = ClientRegistration.class, value = "static_client", configurationFields = {
+	"client.initiate_login_uri"
+})
 public class OIDCCClient3rdPartyInitiatedLoginTest extends AbstractOIDCCClientTest {
 
 	@Override
 	protected void validateClientMetadata() {
-		callAndStopOnFailure(ValidateClientInitiateLoginUri.class,"OIDCR-2");
+		callAndStopOnFailure(ValidateClientInitiateLoginUri.class, "OIDCR-2");
 
-		// run in background so it gets recorded in the log after the response is sent to the client
-		getTestExecutionManager().runInBackground(() -> {
-			setStatus(Status.RUNNING);
-			String initiateLoginUri = env.getString("client", "initiate_login_uri");
-			String issuer = env.getString("issuer");
+		if (clientRegistrationType == ClientRegistration.DYNAMIC_CLIENT) {
+			// run in background so it gets recorded in the log after the response is sent to the client
+			getTestExecutionManager().runInBackground(() -> {
+				setStatus(Status.RUNNING);
+				redirectToInitiateLoginUri();
+				return "done";
+			});
+		}
+	}
+
+	@Override
+	public void start() {
+		setStatus(Status.RUNNING);
+		if (clientRegistrationType == ClientRegistration.STATIC_CLIENT) {
+			// for a static client the metadata is validated during configure(), before the test can
+			// change status, so the redirect happens here instead
+			redirectToInitiateLoginUri();
+		} else {
+			setStatus(Status.WAITING);
+		}
+	}
 
-			UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(initiateLoginUri);
+	/**
+	 * Sends the user to the client's initiate_login_uri; must be called with status RUNNING, leaves it WAITING.
+	 */
+	private void redirectToInitiateLoginUri() {
+		String initiateLoginUri = env.getString("client", "initiate_login_uri");
+		String issuer = env.getString("issuer");
 
-			builder.queryParam("iss", issuer);
+		UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(initiateLoginUri);
 
-			String redirectTo = builder.toUriString();
+		builder.queryParam("iss", issuer);
 
-			eventLog.log(getName(), args("msg", "Redirecting user to initiate_login_uri - press 'Proceed with test' to continue",
-				"redirect_to", redirectTo,
-				"http", "redirect"));
+		String redirectTo = builder.toUriString();
 
-			setStatus(Status.WAITING);
+		eventLog.log(getName(), args("msg", "Redirecting user to initiate_login_uri - press 'Proceed with test' to continue",
+			"redirect_to", redirectTo,
+			"http", "redirect"));
 
-			browser.goToUrl(redirectTo);
+		setStatus(Status.WAITING);
 
-			return "done";
-		});
+		browser.goToUrl(redirectTo);
 	}
 
 	@Override

```

### `tests/rp/fapi2-message-signing.spec.ts#fapi2-security-profile-final-client-test-happy-path-no-mtls-endpoint-aliases`

[fapi2spfinal/FAPI2SPFinalClientTestHappyPathNoMtlsEndpointAliases.java](https://gitlab.com/openid/Conformance-suite/-/blob/845ce4562d1c483edd7c5cc2390f5e910c5f94da/src/main/java/net/openid/conformance/fapi2spfinal/FAPI2SPFinalClientTestHappyPathNoMtlsEndpointAliases.java)

```diff
diff --git a/src/main/java/net/openid/conformance/fapi2spfinal/FAPI2SPFinalClientTestHappyPathNoMtlsEndpointAliases.java b/src/main/java/net/openid/conformance/fapi2spfinal/FAPI2SPFinalClientTestHappyPathNoMtlsEndpointAliases.java
index 733a2c587..8e110319e 100644
--- a/src/main/java/net/openid/conformance/fapi2spfinal/FAPI2SPFinalClientTestHappyPathNoMtlsEndpointAliases.java
+++ b/src/main/java/net/openid/conformance/fapi2spfinal/FAPI2SPFinalClientTestHappyPathNoMtlsEndpointAliases.java
@@ -5,6 +5,8 @@ import net.openid.conformance.condition.as.SetParEndpointToMtlsParEndpoint;
 import net.openid.conformance.condition.as.SetTokenEndpointToMtlsTokenEndpoint;
 import net.openid.conformance.condition.as.SetUserinfoEndpointToMtlsUserinfoEndpoint;
 import net.openid.conformance.testmodule.PublishTestModule;
+import net.openid.conformance.variant.FAPI2FinalOPProfile;
+import net.openid.conformance.variant.VariantNotApplicable;
 
 @PublishTestModule(
 	testName = "fapi2-security-profile-final-client-test-happy-path-no-mtls-endpoint-aliases",
@@ -20,6 +22,7 @@ import net.openid.conformance.testmodule.PublishTestModule;
 		"waitTimeoutSeconds"
 	}
 )
+@VariantNotApplicable(parameter = FAPI2FinalOPProfile.class, values = { "connectid_au" })
 public class FAPI2SPFinalClientTestHappyPathNoMtlsEndpointAliases extends FAPI2SPFinalClientTestHappyPath {
 
 	@Override

```
