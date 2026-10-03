import { OIDCCGenerateServerJWKs } from "./OIDCCGenerateServerJWKs.ts";

export class OIDCCGenerateServerJWKsSingleSigningKeyWithNoKeyId extends OIDCCGenerateServerJWKs {
	protected override setupParameters(): void {
		this.setGenerateSigKids(false);
		this.setNumberOfRSASigningKeysWithNoAlg(1);
		this.setNumberOfECCurveP256SigningKeysWithNoAlg(1);
		this.setNumberOfECCurveSECP256KSigningKeysWithNoAlg(1);
		this.setNumberOfOKPSigningKeysWithNoAlg(1);
	}
}
