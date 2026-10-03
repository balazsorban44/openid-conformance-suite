/**
 * The Java exceptions upstream's checks catch and log (`java.text.ParseException`, Nimbus' `JOSEException`, ...), so
 * the emulation throws them with upstream's names and messages.
 */
import { errors } from "jose";

/**
 * An error whose `name` is its class name: what `errorFields()` (src/suite/conditions.ts) logs as error_class, so
 * the emulated Java exceptions log like upstream's.
 */
export class NamedError extends Error {
	override get name(): string {
		return this.constructor.name;
	}
}

/**
 * Port of `java.text.ParseException`, thrown where the Nimbus parse methods (`JWKSet.parse`, `JWK.parse`,
 * `JWTParser.parse`, `SignedJWT.parse`, `JWTClaimsSet.parse`, `JSONObjectUtils.parse`, ...) throw it.
 */
export class ParseException extends NamedError {
	readonly errorOffset: number;

	constructor(message: string, errorOffset = 0, options?: ErrorOptions) {
		super(message, options);
		this.errorOffset = errorOffset;
	}

	getErrorOffset(): number {
		return this.errorOffset;
	}
}

/** Port of `com.nimbusds.jose.JOSEException`. */
export class JOSEException extends NamedError {}

/** Port of `com.nimbusds.jose.KeyLengthException`. */
export class KeyLengthException extends JOSEException {}

/**
 * True for the errors Nimbus would report as a `JOSEException`: the {@link JOSEException} port (and its subclasses)
 * and jose's own errors (`errors.JOSEError`), which jose throws where Nimbus' signers, verifiers, encrypters and
 * decrypters throw a JOSEException.
 *
 * Unified from the copies in AbstractSignJWT (exactly this) and AbstractJWEEncryptString (which also counted
 * `TypeError`). jose reports invalid key material for an operation as a `TypeError`, which Nimbus would mostly
 * report as an IllegalArgumentException from a signer/verifier constructor (not a JOSEException), so the
 * TypeError is not part of this predicate; the one condition that needs it (AbstractJWEEncryptString, where
 * Nimbus' encrypters throw a JOSEException for the same key problems) adds it at its catch site.
 */
export function isJOSEException(e: unknown): e is Error {
	return e instanceof JOSEException || e instanceof errors.JOSEError;
}

/** Nimbus `JWKException.expectedClass(cls)`: the JOSEException a factory throws for a JWK of the wrong class. */
export function expectedClass(cls: string): JOSEException {
	return new JOSEException("Invalid JWK: Must be an instance of class com.nimbusds.jose.jwk." + cls);
}
