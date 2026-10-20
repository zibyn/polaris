// Passkeys: adding one goes through the browser's WebAuthn API and the
// Account API. base64url lives in /login/passkey.js, which the Go server
// serves and the hosted login page's own Passkey flow shares; loadB64url
// waits for it rather than a library
// (docs/spec/consoles.md#账号中心单页长滚动).

declare global {
	interface Window {
		polaris: {
			b64url: {
				encode(buf: ArrayBuffer | Uint8Array): string;
				decode(s: string): Uint8Array<ArrayBuffer>;
			};
		};
	}
}

export type Passkey = {
	id: string;
	name: string;
	createdAt: string;
	lastUsedAt?: string;
};

// Creation options as the API sends them: the WebAuthn JSON shape, byte
// fields in base64url.
export type CreationOptions = {
	publicKey: {
		rp: { id?: string; name: string };
		user: { id: string; name: string; displayName: string };
		challenge: string;
		pubKeyCredParams: { type: "public-key"; alg: number }[];
		timeout?: number;
		excludeCredentials?: { type: "public-key"; id: string }[];
		authenticatorSelection?: Record<string, unknown>;
		attestation?: "none";
	};
};

export type RegistrationResponse = {
	id: string;
	rawId: string;
	type: string;
	response: {
		clientDataJSON: string;
		attestationObject: string;
		transports?: string[];
	};
};

// Assertion options as the API sends them: which Passkeys the User may pick
// from, in allowCredentials.
export type AssertionOptions = {
	publicKey: {
		challenge: string;
		rpId?: string;
		timeout?: number;
		userVerification?: UserVerificationRequirement;
		allowCredentials?: { type: "public-key"; id: string }[];
	};
};

export type AssertionResponse = {
	id: string;
	rawId: string;
	type: string;
	response: {
		clientDataJSON: string;
		authenticatorData: string;
		signature: string;
		userHandle?: string;
	};
};

// passkeySupported is whether this browser can make one at all.
export const passkeySupported = typeof PublicKeyCredential !== "undefined";

let b64urlModule: Promise<Window["polaris"]["b64url"]> | null = null;

function loadB64url(): Promise<Window["polaris"]["b64url"]> {
	b64urlModule ??= new Promise((resolve, reject) => {
		const s = document.createElement("script");
		s.src = "/login/passkey.js";
		s.onload = () => resolve(window.polaris.b64url);
		s.onerror = () => {
			b64urlModule = null; // a retry gets another chance
			reject(new Error("base64url 模块加载失败"));
		};
		document.head.append(s);
	});
	return b64urlModule;
}

// createPasskey walks the browser through adding a Passkey: the system
// dialog, then the registration response the API takes.
export async function createPasskey(
	options: CreationOptions,
): Promise<RegistrationResponse> {
	const b64url = await loadB64url();
	const cred = (await navigator.credentials.create({
		publicKey: {
			...options.publicKey,
			challenge: b64url.decode(options.publicKey.challenge),
			user: {
				...options.publicKey.user,
				id: b64url.decode(options.publicKey.user.id),
			},
			excludeCredentials: (options.publicKey.excludeCredentials ?? []).map(
				(c) => ({ ...c, id: b64url.decode(c.id) }),
			),
		},
	})) as PublicKeyCredential;
	const response = cred.response as AuthenticatorAttestationResponse;
	return {
		id: cred.id,
		rawId: b64url.encode(cred.rawId),
		type: cred.type,
		response: {
			clientDataJSON: b64url.encode(response.clientDataJSON),
			attestationObject: b64url.encode(response.attestationObject),
			transports: response.getTransports?.() ?? ["internal"],
		},
	};
}

// getPasskey runs the browser's Passkey prompt for an assertion and returns
// the response the API takes, the way createPasskey does for adding one.
export async function getPasskey(
	options: AssertionOptions,
): Promise<AssertionResponse> {
	const b64url = await loadB64url();
	const cred = (await navigator.credentials.get({
		publicKey: {
			...options.publicKey,
			challenge: b64url.decode(options.publicKey.challenge),
			allowCredentials: (options.publicKey.allowCredentials ?? []).map((c) => ({
				...c,
				id: b64url.decode(c.id),
			})),
		},
	})) as PublicKeyCredential;
	const response = cred.response as AuthenticatorAssertionResponse;
	return {
		id: cred.id,
		rawId: b64url.encode(cred.rawId),
		type: cred.type,
		response: {
			clientDataJSON: b64url.encode(response.clientDataJSON),
			authenticatorData: b64url.encode(response.authenticatorData),
			signature: b64url.encode(response.signature),
			userHandle: response.userHandle
				? b64url.encode(response.userHandle)
				: undefined,
		},
	};
}
