import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { Hono } from "hono";
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

test("on Hono: sign in, then read the session in a route", async () => {
	const polaris = createPolaris({
		issuer: op.issuer,
		clientId,
		clientSecret,
		baseURL: appURL,
		secret: "x".repeat(32),
	});
	const app = new Hono();
	app.on(["GET", "POST"], "/auth/*", (c) => polaris.handler(c.req.raw));
	app.get("/me", async (c) => {
		const { session, headers } = await polaris.getSession(c.req.raw);
		for (const cookie of headers.getSetCookie())
			c.header("set-cookie", cookie, { append: true });
		return session
			? c.json({ sub: session.user.sub })
			: c.text("signed out", 401);
	});
	const browser = new Browser(async (req) => app.fetch(req));

	assert.equal((await app.fetch(browser.request("/me"))).status, 401);
	op.accessTTL = 30; // due for refresh at once
	await browser.go(`${appURL}/auth/login?returnTo=/me`);
	const res = await app.fetch(browser.request("/me"));
	assert.deepEqual(await res.json(), { sub: "user-1" });
	assert.ok(
		res.headers.getSetCookie().some((c) => c.startsWith("polaris.session=")),
	);
});
