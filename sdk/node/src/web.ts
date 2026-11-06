// Web Application login (ADR 0035): a confidential client on the
// authorization code flow, its tokens kept in the SDK's session cookie.
import * as oidc from "openid-client";
import {
	applyToJar,
	type CookieOptions,
	deriveKey,
	parseCookies,
	readChunked,
	seal,
	serialize,
	unseal,
	writeChunked,
} from "./cookies.ts";

export type PolarisConfig = {
	/** The Polaris instance, e.g. https://auth.example.com */
	issuer: string;
	clientId: string;
	clientSecret: string;
	/** Where this app is served; the handler answers under {baseURL}/auth/. */
	baseURL: string;
	/** Encrypts the session cookie: at least 32 random characters, kept server side. */
	secret: string;
	/** Defaults to "openid profile email phone". */
	scope?: string;
};

/** The ID token's claims about the User: sub, name, email, … */
export type User = { sub: string; [claim: string]: unknown };

export type Session = { user: User; accessToken: string };

export type GetSessionOptions = {
	/**
	 * Never refresh: for callers that cannot write cookies, like a Next
	 * Server Component. An expired access token then reads as signed out,
	 * since a consumed refresh token must make it back to the cookie.
	 */
	readOnly?: boolean;
};

type Stored = { at: string; rt: string; expiresAt: number; user: User };
type Tx = { state: string; nonce: string; verifier: string; returnTo: string };

const sessionCookie = "polaris.session";
const txCookie = "polaris.tx";
// shortcut: the default browser Session idle time, not the Application's own; a
// longer one at Polaris still ends here, take it from config when someone asks.
const sessionMaxAge = 30 * 24 * 3600;
const txMaxAge = 600;
// Refresh this long before the access token expires, so that it still holds
// for the calls made with it in this request.
const refreshMargin = 60;
// Claims about the token itself, not the User.
const protocolClaims = [
	"iss",
	"aud",
	"exp",
	"iat",
	"nbf",
	"nonce",
	"at_hash",
	"c_hash",
	"azp",
	"jti",
];

const now = () => Math.floor(Date.now() / 1000);

export function createPolaris(config: PolarisConfig) {
	const base = new URL(config.baseURL);
	const prefix = `${base.pathname.replace(/\/$/, "")}/auth`;
	const redirectURI = new URL(`${prefix}/callback`, base).href;
	const cookieOpts: CookieOptions = {
		secure: base.protocol === "https:",
		path: "/",
	};
	const key = deriveKey(config.secret);
	const issuer = new URL(config.issuer);
	// Like redirect URIs (ADR 0034): https, except on localhost.
	const insecure =
		issuer.protocol === "http:" &&
		["localhost", "127.0.0.1", "[::1]"].includes(issuer.hostname);
	let discovered: Promise<oidc.Configuration> | undefined;
	const configuration = () => {
		discovered ??= oidc
			.discovery(
				issuer,
				config.clientId,
				undefined,
				oidc.ClientSecretBasic(config.clientSecret),
				{
					execute: insecure ? [oidc.allowInsecureRequests] : [],
				},
			)
			.catch((err) => {
				discovered = undefined; // try again on the next request
				throw err;
			});
		return discovered;
	};
	// Concurrent requests of one browser carry the same refresh token: send it once.
	// shortcut: one process only; several instances lean on the 60 s grace (ADR 0019), add a shared store if that shows in audits.
	const inflight = new Map<string, Promise<Stored | null>>();

	const userOf = (claims: oidc.IDToken | undefined): User | undefined => {
		if (!claims) return undefined;
		const user: Record<string, unknown> = { ...claims };
		for (const c of protocolClaims) delete user[c];
		return user as User;
	};

	const stored = (
		tokens: oidc.TokenEndpointResponse & oidc.TokenEndpointResponseHelpers,
		user: User,
	): Stored => {
		if (!tokens.refresh_token) {
			throw new Error(
				"polaris: no refresh token; turn on refresh tokens for this Application",
			);
		}
		return {
			at: tokens.access_token,
			rt: tokens.refresh_token,
			// Polaris always sends expires_in (600); without it every request would refresh.
			expiresAt: now() + (tokens.expiresIn() ?? 600),
			user,
		};
	};

	/** Appends to headers the Set-Cookie values that store s, or clear the session when null. */
	const writeSession = async (
		headers: Headers,
		jar: Map<string, string>,
		s: Stored | null,
	) => {
		const value = s && (await seal(s, await key, sessionMaxAge));
		for (const c of writeChunked(
			jar,
			sessionCookie,
			value,
			sessionMaxAge,
			cookieOpts,
		)) {
			headers.append("set-cookie", c);
		}
	};

	/** The refreshed session, or null when Polaris refused the refresh token. */
	const refresh = (s: Stored) => {
		let p = inflight.get(s.rt);
		if (!p) {
			p = (async () => {
				try {
					const tokens = await oidc.refreshTokenGrant(
						await configuration(),
						s.rt,
					);
					return stored(tokens, userOf(tokens.claims()) ?? s.user);
				} catch (err) {
					// Polaris said no (the Session ended): signed out. Anything else,
					// like the network, keeps the cookie for the next try.
					if (err instanceof oidc.ResponseBodyError) return null;
					throw err;
				}
			})().finally(() => inflight.delete(s.rt));
			inflight.set(s.rt, p);
		}
		return p;
	};

	/**
	 * Reads the session, refreshing it when due. The Set-Cookie headers in
	 * headers must reach the browser whenever there are any.
	 */
	async function getSession(
		request: Request | Headers,
		options: GetSessionOptions = {},
	): Promise<{ session: Session | null; headers: Headers }> {
		const headers = new Headers();
		const jar = parseCookies(
			(request instanceof Request ? request.headers : request).get("cookie"),
		);
		const raw = readChunked(jar, sessionCookie);
		let s = await unseal<Stored>(raw, await key);
		if (!s) {
			if (raw && !options.readOnly) await writeSession(headers, jar, null);
			return { session: null, headers };
		}
		if (options.readOnly) {
			return {
				session:
					s.expiresAt > now() ? { user: s.user, accessToken: s.at } : null,
				headers,
			};
		}
		if (s.expiresAt - refreshMargin <= now()) {
			s = await refresh(s);
			await writeSession(headers, jar, s);
		}
		return { session: s && { user: s.user, accessToken: s.at }, headers };
	}

	const login = async (request: Request) => {
		const returnTo = new URL(request.url).searchParams.get("returnTo") ?? "/";
		const tx: Tx = {
			state: oidc.randomState(),
			nonce: oidc.randomNonce(),
			verifier: oidc.randomPKCECodeVerifier(),
			returnTo: localPath(returnTo, base),
		};
		const url = oidc.buildAuthorizationUrl(await configuration(), {
			redirect_uri: redirectURI,
			scope: config.scope ?? "openid profile email phone",
			state: tx.state,
			nonce: tx.nonce,
			code_challenge: await oidc.calculatePKCECodeChallenge(tx.verifier),
			code_challenge_method: "S256",
		});
		const res = redirect(url.href);
		res.headers.append(
			"set-cookie",
			serialize(
				txCookie,
				await seal(tx, await key, txMaxAge),
				txMaxAge,
				cookieOpts,
			),
		);
		return res;
	};

	const callback = async (request: Request) => {
		const jar = parseCookies(request.headers.get("cookie"));
		const tx = await unseal<Tx>(jar.get(txCookie), await key);
		if (!tx)
			return text(400, "login expired or not started here; sign in again");
		let tokens: Awaited<ReturnType<typeof oidc.authorizationCodeGrant>>;
		try {
			// Rebuilt on baseURL: behind a proxy request.url names an internal host.
			tokens = await oidc.authorizationCodeGrant(
				await configuration(),
				new URL(new URL(request.url).search, redirectURI),
				{
					pkceCodeVerifier: tx.verifier,
					expectedState: tx.state,
					expectedNonce: tx.nonce,
					idTokenExpected: true,
				},
			);
		} catch (err) {
			if (
				err instanceof oidc.AuthorizationResponseError ||
				err instanceof oidc.ResponseBodyError
			) {
				return text(
					400,
					`login failed: ${err.error}${err.error_description ? `: ${err.error_description}` : ""}`,
				);
			}
			throw err;
		}
		const user = userOf(tokens.claims());
		if (!user) throw new Error("polaris: no ID token in the token response");
		const res = redirect(tx.returnTo);
		await writeSession(res.headers, jar, stored(tokens, user));
		res.headers.append("set-cookie", serialize(txCookie, "", 0, cookieOpts));
		return res;
	};

	// RP-Initiated Logout without id_token_hint, which is not kept: Polaris asks
	// the User to confirm, then sends them back to baseURL.
	const logout = async (request: Request) => {
		const url = oidc.buildEndSessionUrl(await configuration(), {
			client_id: config.clientId,
			post_logout_redirect_uri: config.baseURL,
		});
		const res = redirect(url.href);
		await writeSession(
			res.headers,
			parseCookies(request.headers.get("cookie")),
			null,
		);
		return res;
	};

	const sessionRoute = async (request: Request) => {
		const { session, headers } = await getSession(request);
		headers.set("content-type", "application/json");
		headers.set("cache-control", "no-store");
		// The access token stays server side, out of reach of page scripts.
		return new Response(JSON.stringify(session && { user: session.user }), {
			headers,
		});
	};

	const routes: Record<string, (r: Request) => Promise<Response>> = {
		"GET /login": login,
		"GET /callback": callback,
		"POST /logout": logout,
		"GET /session": sessionRoute,
	};

	/** The login, callback, logout and session routes, as a web-standard handler. */
	const handle = async (request: Request): Promise<Response> => {
		const path = new URL(request.url).pathname;
		const route =
			path.startsWith(`${prefix}/`) &&
			routes[`${request.method} ${path.slice(prefix.length)}`];
		return route ? route(request) : text(404, "not found");
	};
	const handler = Object.assign(handle, { GET: handle, POST: handle });

	/**
	 * For a Next.js proxy.ts (formerly middleware.ts): refreshes the session
	 * when due, putting the new cookie both on the response and on the request
	 * the app goes on to handle, so that Server Components read the new tokens.
	 */
	async function middleware(request: Request): Promise<Response> {
		const { NextResponse } = await import("next/server.js");
		const { headers } = await getSession(request);
		const setCookies = headers.getSetCookie();
		if (!setCookies.length) return NextResponse.next();
		const forwarded = new Headers(request.headers);
		forwarded.set(
			"cookie",
			applyToJar(parseCookies(request.headers.get("cookie")), setCookies),
		);
		const res = NextResponse.next({ request: { headers: forwarded } });
		for (const c of setCookies) res.headers.append("set-cookie", c);
		return res;
	}

	/** The account center link, branded for this Application (ADR 0034). */
	const accountUrl = () => {
		const url = new URL("account", `${config.issuer.replace(/\/$/, "")}/`);
		url.searchParams.set("client_id", config.clientId);
		return url.href;
	};

	return { handler, getSession, middleware, accountUrl };
}

export type Polaris = ReturnType<typeof createPolaris>;

/**
 * returnTo as a path on base's origin, else "/": no open redirect. Resolving
 * it as the browser will catches "//x", "/\\x" and "/\t/x" alike.
 */
function localPath(returnTo: string, base: URL) {
	const url = new URL(returnTo, base);
	return url.origin === base.origin
		? url.pathname + url.search + url.hash
		: "/";
}

const redirect = (location: string) =>
	new Response(null, { status: 302, headers: { location } });
const text = (status: number, body: string) =>
	new Response(body, {
		status,
		headers: { "content-type": "text/plain; charset=utf-8" },
	});
