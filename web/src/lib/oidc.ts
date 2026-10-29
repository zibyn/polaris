// The console and the account center each sign in as their built-in public
// Application with code + PKCE and keep the access token for this tab only.
// When it expires they run the flow again; the browser Session makes that a
// silent round trip.
// ponytail: full-page redirect on expiry; switch to refresh tokens if the
// round trips get noticed.

function base64url(bytes: Uint8Array) {
	return btoa(String.fromCharCode(...bytes))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/, "");
}

const random = () => base64url(crypto.getRandomValues(new Uint8Array(32)));

// here is where the browser is, fragment included: a section anchor such as
// #passkeys, where /.well-known/change-password sends a User, survives the
// sign-in round trip.
const here = () => location.pathname + location.search + location.hash;

export class APIError extends Error {
	readonly status: number;
	readonly code?: string; // what kind, when the API names it
	constructor(status: number, message: string, code?: string) {
		super(message);
		this.status = status;
		this.code = code;
	}
}

// oidcClient signs in as clientID, whose callback is home + "/callback",
// and calls the API under apiPrefix.
export function oidcClient({
	clientID,
	home,
	apiPrefix,
}: {
	clientID: string;
	home: string;
	apiPrefix: string;
}) {
	const tokenKey = `${clientID}.token`;
	const flowKey = `${clientID}.flow`;
	const redirectURI = () => `${location.origin}${home}/callback`;

	// login sends the browser to the hosted login page; it never resolves.
	async function login(returnTo: string): Promise<never> {
		const verifier = random();
		const state = random();
		const challenge = base64url(
			new Uint8Array(
				await crypto.subtle.digest(
					"SHA-256",
					new TextEncoder().encode(verifier),
				),
			),
		);
		sessionStorage.setItem(
			flowKey,
			JSON.stringify({ state, verifier, returnTo }),
		);
		location.assign(
			`/authorize?${new URLSearchParams({
				client_id: clientID,
				response_type: "code",
				scope: "openid",
				redirect_uri: redirectURI(),
				state,
				code_challenge: challenge,
				code_challenge_method: "S256",
			})}`,
		);
		return new Promise<never>(() => {});
	}

	// finishLogin redeems the callback's code and returns where to go next.
	async function finishLogin(params: URLSearchParams): Promise<string> {
		const flow = JSON.parse(sessionStorage.getItem(flowKey) ?? "null");
		sessionStorage.removeItem(flowKey);
		if (!flow || params.get("state") !== flow.state) {
			throw new Error("登录已过期,请重试");
		}
		const error = params.get("error");
		if (error) {
			throw new Error(params.get("error_description") || error);
		}
		const res = await fetch("/token", {
			method: "POST",
			body: new URLSearchParams({
				grant_type: "authorization_code",
				code: params.get("code") ?? "",
				redirect_uri: redirectURI(),
				client_id: clientID,
				code_verifier: flow.verifier,
			}),
		});
		if (!res.ok) {
			throw new Error("登录失败,请重试");
		}
		const tok = await res.json();
		sessionStorage.setItem(
			tokenKey,
			JSON.stringify({
				accessToken: tok.access_token,
				idToken: tok.id_token,
				expiresAt: Date.now() + tok.expires_in * 1000,
			}),
		);
		return typeof flow.returnTo === "string" && flow.returnTo.startsWith(home)
			? flow.returnTo
			: home;
	}

	function stored(): {
		accessToken: string;
		idToken: string;
		expiresAt: number;
	} | null {
		return JSON.parse(sessionStorage.getItem(tokenKey) ?? "null");
	}

	function accessToken(): string | null {
		const tok = stored();
		return tok && tok.expiresAt - 30_000 > Date.now() ? tok.accessToken : null;
	}

	// api calls an API path, signing in first when needed; body goes as JSON,
	// a Blob (an uploaded file) as it is.
	async function api<T>(
		path: string,
		init?: { method: "POST" | "PUT" | "PATCH" | "DELETE"; body?: unknown },
	): Promise<T> {
		const token = accessToken();
		if (!token) {
			return login(here());
		}
		const raw = init?.body instanceof Blob ? init.body : undefined;
		const res = await fetch(`${apiPrefix}${path}`, {
			method: init?.method,
			headers: {
				Authorization: `Bearer ${token}`,
				...(init?.body !== undefined && {
					"Content-Type": raw
						? raw.type || "application/octet-stream"
						: "application/json",
				}),
			},
			body:
				raw ??
				(init?.body === undefined ? undefined : JSON.stringify(init.body)),
		});
		if (res.status === 401) {
			sessionStorage.removeItem(tokenKey);
			return login(here());
		}
		if (!res.ok) {
			const body = await res.json().catch(() => ({}));
			throw new APIError(res.status, body.detail ?? res.statusText, body.code);
		}
		return res.status === 204 ? (undefined as T) : res.json();
	}

	// forget drops the access token, as after the account is deleted.
	const forget = () => sessionStorage.removeItem(tokenKey);

	// logout ends the browser Session, which signs out every Application
	// that signed in with it, and comes back home to sign in again. The
	// id_token_hint, expired or not, skips the confirmation page.
	function logout() {
		const idToken = stored()?.idToken;
		forget();
		location.assign(
			`/logout?${new URLSearchParams({
				client_id: clientID,
				post_logout_redirect_uri: location.origin + home,
				...(idToken && { id_token_hint: idToken }),
			})}`,
		);
	}

	return { login, finishLogin, api, forget, logout };
}
