// oidc-provider ships no type declarations; the CI target only needs it untyped.
declare module "oidc-provider" {
	// oxlint-disable-next-line typescript/no-explicit-any
	const Provider: any;
	// oxlint-disable-next-line typescript/no-explicit-any
	export const errors: any;
	export default Provider;
}

declare module "oidc-provider/lib/helpers/defaults.js" {
	// oxlint-disable-next-line typescript/no-explicit-any
	export const defaults: any;
}

declare module "oidc-provider/lib/consts/jwa.js" {
	export const clientAuthSigningAlgValues: string[];
	export const idTokenSigningAlgValues: string[];
	export const requestObjectSigningAlgValues: string[];
	export const userinfoSigningAlgValues: string[];
	export const introspectionSigningAlgValues: string[];
	export const authorizationSigningAlgValues: string[];
	export const idTokenEncryptionAlgValues: string[];
	export const requestObjectEncryptionAlgValues: string[];
	export const userinfoEncryptionAlgValues: string[];
	export const introspectionEncryptionAlgValues: string[];
	export const authorizationEncryptionAlgValues: string[];
	export const idTokenEncryptionEncValues: string[];
	export const requestObjectEncryptionEncValues: string[];
	export const userinfoEncryptionEncValues: string[];
	export const introspectionEncryptionEncValues: string[];
	export const authorizationEncryptionEncValues: string[];
}
