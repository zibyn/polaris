// Smoke test of an example app: node examples/smoke.ts http://localhost:3000
// Starts a fake Polaris on 127.0.0.1:4999 (the examples' default issuer),
// signs in through the app, reads the session on its home page after a
// refresh, and signs out.
import assert from "node:assert/strict";
import { Browser } from "../src/testing/browser.ts";
import { startFakeOP } from "../src/testing/fake-op.ts";

const base = process.argv[2] ?? "http://localhost:3000";
const op = await startFakeOP(4999);
const browser = new Browser((req) => fetch(req, { redirect: "manual" }), base);
try {
	op.accessTTL = 30; // the first page view is due for a refresh
	const back = await browser.go(`${base}/auth/login`);
	assert.equal(back.headers.get("location"), "/", "signed in and sent home");
	op.accessTTL = 600; // what the refresh hands out

	const home = await browser.go(`${base}/`);
	const html = await home.text();
	assert.match(html, /Signed in as.*user-1/s, html.slice(0, 500));
	assert.equal(op.refreshRequests, 1, "refreshed once");
	browser.store(home.headers);
	assert.ok(
		home.headers.getSetCookie().some((c) => c.startsWith("polaris.session=")),
		"rotated cookie written back",
	);

	const again = await (await browser.go(`${base}/`)).text();
	assert.match(again, /Signed in as.*user-1/s, "the rotated cookie works");
	assert.equal(op.refreshRequests, 1);

	const out = await browser.app(
		browser.request("/auth/logout", { method: "POST" }),
	);
	browser.store(out.headers);
	assert.match(out.headers.get("location") ?? "", /\/logout\?/);
	assert.match(await (await browser.go(`${base}/`)).text(), /Sign in/);
	console.log(`ok: ${base}`);
} finally {
	await op.close();
}
