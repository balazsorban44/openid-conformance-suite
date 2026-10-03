import { OIDCCGenerateServerJWKs } from "./OIDCCGenerateServerJWKs.ts";

export class OIDCCGenerateServerJWKsMultipleSigningsKeyWithNoKeyIds extends OIDCCGenerateServerJWKs {
	protected override setupParameters(): void {
		this.setGenerateSigKids(false);
		this.setNumberOfRSASigningKeysWithNoAlg(3);
		this.setNumberOfECCurveP256SigningKeysWithNoAlg(3);
		this.setNumberOfECCurveSECP256KSigningKeysWithNoAlg(3);
		this.setNumberOfOKPSigningKeysWithNoAlg(3);
	}
}
