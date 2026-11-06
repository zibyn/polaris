import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, test } from "node:test";
import { createPolaris, toNodeHandler } from "./index.ts";
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

test("toNodeHandler serves the routes on node:http, as Express would mount them", async () => {
	const polaris = createPolaris({
		issuer: op.issuer,
		clientId,
		clientSecret,
		baseURL: appURL,
		secret: "x".repeat(32),
	});
	const node = toNodeHandler(polaris.handler);
	// Express strips the mount path from req.url and keeps it in originalUrl.
	const server = createServer((req, res) => {
		Object.assign(req, {
			originalUrl: req.url,
			url: req.url?.replace(/^\/auth/, ""),
		});
		node(req, res);
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
	try {
		const browser = new Browser((req) => {
			const u = new URL(req.url);
			return fetch(base + u.pathname + u.search, {
				method: req.method,
				headers: req.headers,
				redirect: "manual",
			});
		});
		const res = await browser.go(`${appURL}/auth/login`);
		assert.equal(res.headers.get("location"), "/");
		const body = await (
			await browser.app(browser.request("/auth/session"))
		).json();
		assert.equal(body.user.sub, "user-1");

		const out = await browser.app(
			browser.request("/auth/logout", { method: "POST", body: "x=1" }),
		);
		assert.equal(out.status, 302);
		assert.ok(out.headers.getSetCookie().length >= 1);
	} finally {
		server.close();
	}
});
