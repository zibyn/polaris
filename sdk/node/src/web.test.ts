import assert from "node:assert/strict";
import { after, before, beforeEach, test } from "node:test";
import { createPolaris } from "./index.ts";
import { appURL, Browser } from "./testing/browser.ts";
import {
	clientId,
	clientSecret,
	type FakeOP,
	startFakeOP,
} from "./testing/fake-op.ts";

let op: FakeOP;
before(async () => {
	op = await startFakeOP();
});
after(() => op.close());
beforeEach(() => {
	op.accessTTL = 600;
	op.issueRefreshTokens = true;
	op.profile = { name: "Ada" };
	op.refreshRequests = 0;
});

const setup = () => {
	const polaris = createPolaris({
		issuer: op.issuer,
		clientId,
		clientSecret,
		baseURL: appURL,
		secret: "a-secret-of-at-least-thirty-two-characters",
	});
	return { polaris, browser: new Browser(polaris.handler) };
};

const signIn = async (browser: Browser, returnTo = "/dashboard") => {
	const res = await browser.go(
		`${appURL}/auth/login?returnTo=${encodeURIComponent(returnTo)}`,
	);
	assert.equal(res.status, 302);
	return res.headers.get("location");
};

test("signing in leaves a session with the user and access token", async () => {
	const { polaris, browser } = setup();
	assert.equal(await signIn(browser), "/dashboard");

	const q = op.authorizeParams;
	assert.equal(q.get("client_id"), clientId);
	assert.equal(q.get("redirect_uri"), `${appURL}/auth/callback`);
	assert.equal(q.get("code_challenge_method"), "S256");
	assert.ok(q.get("state") && q.get("nonce"));

	const { session, headers } = await polaris.getSession(browser.request("/"));
	assert.equal(session?.user.sub, "user-1");
	assert.equal(session?.user.name, "Ada");
	assert.equal(
		session?.user.nonce,
		undefined,
		"protocol claims are not the user's",
	);
	assert.ok(session?.accessToken);
	assert.deepEqual(headers.getSetCookie(), []);
});

test("an access token due to expire is refreshed and the rotated cookie comes back in headers", async () => {
	const { polaris, browser } = setup();
	op.accessTTL = 30; // inside the refresh margin
	await signIn(browser);
	const before = browser.cookieHeader();
	op.profile = { name: "Ada Lovelace" };

	const { session, headers } = await polaris.getSession(browser.request("/"));
	assert.equal(op.refreshRequests, 1);
	assert.equal(
		session?.user.name,
		"Ada Lovelace",
		"user follows the refreshed ID token",
	);
	assert.ok(headers.getSetCookie().length > 0);
	browser.store(headers);
	assert.notEqual(browser.cookieHeader(), before);

	// The new cookie carries the rotated refresh token: refreshing again works.
	const again = await polaris.getSession(browser.request("/"));
	assert.ok(again.session);
	assert.equal(op.refreshRequests, 2);
});

test("concurrent requests with one cookie refresh once", async () => {
	const { polaris, browser } = setup();
	op.accessTTL = 30;
	await signIn(browser);
	const results = await Promise.all(
		[1, 2, 3].map(() => polaris.getSession(browser.request("/"))),
	);
	assert.equal(op.refreshRequests, 1);
	for (const r of results) assert.ok(r.session);
});

test("a refused refresh signs the user out and clears the cookie", async () => {
	const { polaris, browser } = setup();
	op.accessTTL = 30;
	await signIn(browser);
	op.endSessions();

	const { session, headers } = await polaris.getSession(browser.request("/"));
	assert.equal(session, null);
	browser.store(headers);
	assert.equal(browser.cookies.has("polaris.session"), false);
});

test("read-only, an expired access token reads as signed out without refreshing", async () => {
	const { polaris, browser } = setup();
	op.accessTTL = 0;
	await signIn(browser);

	const { session, headers } = await polaris.getSession(
		browser.request("/").headers,
		{ readOnly: true },
	);
	assert.equal(session, null);
	assert.equal(op.refreshRequests, 0);
	assert.deepEqual(headers.getSetCookie(), []);
});

test("read-only, a live access token is read", async () => {
	const { polaris, browser } = setup();
	await signIn(browser);
	const { session } = await polaris.getSession(browser.request("/").headers, {
		readOnly: true,
	});
	assert.equal(session?.user.sub, "user-1");
});

test("an Application without refresh tokens is a configuration error", async () => {
	const { browser } = setup();
	op.issueRefreshTokens = false;
	await assert.rejects(signIn(browser), /refresh token/);
});

test("logout clears the cookie and goes to RP-Initiated Logout without an ID token hint", async () => {
	const { polaris, browser } = setup();
	await signIn(browser);
	const res = await polaris.handler(
		browser.request("/auth/logout", { method: "POST" }),
	);
	browser.store(res.headers);
	assert.equal(browser.cookies.has("polaris.session"), false);

	const loc = new URL(res.headers.get("location") ?? "");
	assert.equal(loc.origin + loc.pathname, `${op.issuer}/logout`);
	assert.equal(loc.searchParams.get("client_id"), clientId);
	assert.equal(loc.searchParams.get("post_logout_redirect_uri"), appURL);
	assert.equal(loc.searchParams.has("id_token_hint"), false);
	assert.equal((await polaris.getSession(browser.request("/"))).session, null);
});

test("returnTo only goes to a path on this site", async () => {
	const { browser } = setup();
	for (const evil of [
		"//evil.example.com",
		"https://evil.example.com",
		"/\t/evil.example.com",
		"/\\evil.example.com",
	]) {
		assert.equal(
			await signIn(new Browser(browser.app), evil),
			"/",
			JSON.stringify(evil),
		);
	}
	assert.equal(
		await signIn(new Browser(browser.app), "/a/b?c=1#d"),
		"/a/b?c=1#d",
	);
});

test("logout only takes POST, so another site cannot sign the user out with a link", async () => {
	const { polaris, browser } = setup();
	await signIn(browser);
	const res = await polaris.handler(browser.request("/auth/logout"));
	assert.equal(res.status, 404);
	assert.deepEqual(res.headers.getSetCookie(), []);
});

test("a callback without the login's cookie is refused", async () => {
	const { polaris, browser } = setup();
	const res = await polaris.handler(
		browser.request("/auth/callback?code=x&state=y"),
	);
	assert.equal(res.status, 400);
});

test("the session route gives the front end the user, not the token", async () => {
	const { polaris, browser } = setup();
	assert.equal(
		await (await polaris.handler(browser.request("/auth/session"))).json(),
		null,
	);
	await signIn(browser);
	const body = await (
		await polaris.handler(browser.request("/auth/session"))
	).json();
	assert.deepEqual(Object.keys(body), ["user"]);
	assert.equal(body.user.sub, "user-1");
});

test("a session too big for one cookie is split and read back", async () => {
	const { polaris, browser } = setup();
	op.profile = { name: "Ada", bio: "x".repeat(6000) };
	await signIn(browser);
	assert.ok(
		browser.cookies.has("polaris.session.0") &&
			browser.cookies.has("polaris.session.1"),
	);
	assert.equal(browser.cookies.has("polaris.session"), false);
	for (const c of browser.cookies.values()) assert.ok(c.length < 4000);
	const { session } = await polaris.getSession(browser.request("/"));
	assert.equal((session?.user.bio as string).length, 6000);

	// Shrinking back to one cookie clears the chunks.
	op.profile = { name: "Ada" };
	op.accessTTL = 30;
	await signIn(browser);
	assert.deepEqual(
		[...browser.cookies.keys()].filter((k) => k.startsWith("polaris.session")),
		["polaris.session"],
	);
});

test("a tampered cookie reads as signed out and is cleared", async () => {
	const { polaris, browser } = setup();
	await signIn(browser);
	browser.cookies.set(
		"polaris.session",
		`${browser.cookies.get("polaris.session")}x`,
	);
	const { session, headers } = await polaris.getSession(browser.request("/"));
	assert.equal(session, null);
	browser.store(headers);
	assert.equal(browser.cookies.has("polaris.session"), false);
});

test("the account link names the Application", () => {
	const { polaris } = setup();
	assert.equal(
		polaris.accountUrl(),
		`${op.issuer}/account?client_id=${clientId}`,
	);
});

test("middleware puts the refreshed cookie on the response and on the forwarded request", async () => {
	const { polaris, browser } = setup();
	op.accessTTL = 30;
	await signIn(browser);
	const res = await polaris.middleware(browser.request("/dashboard"));
	assert.equal(op.refreshRequests, 1);
	assert.equal(res.headers.get("x-middleware-next"), "1");

	const setCookies = res.headers.getSetCookie();
	assert.ok(setCookies.some((c) => c.startsWith("polaris.session=")));
	browser.store(res.headers);
	// Next hands the app the request with this Cookie header.
	assert.match(
		res.headers.get("x-middleware-override-headers") ?? "",
		/cookie/,
	);
	const forwarded = res.headers.get("x-middleware-request-cookie") ?? "";
	assert.equal(forwarded, browser.cookieHeader());

	// The app reads the new tokens even read-only, as a Server Component would.
	const { session } = await polaris.getSession(
		new Headers({ cookie: forwarded }),
		{ readOnly: true },
	);
	assert.ok(session);
});

test("middleware passes a fresh session through untouched", async () => {
	const { polaris, browser } = setup();
	await signIn(browser);
	const res = await polaris.middleware(browser.request("/dashboard"));
	assert.equal(res.headers.get("x-middleware-next"), "1");
	assert.deepEqual(res.headers.getSetCookie(), []);
	assert.equal(res.headers.get("x-middleware-request-cookie"), null);
});
