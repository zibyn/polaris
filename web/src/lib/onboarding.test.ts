import assert from "node:assert/strict";
import { test } from "node:test";
import { checklist, type Platform, platforms, snippet } from "./onboarding.ts";

test("each platform card maps to its type and callback requirement", () => {
	const got = Object.fromEntries(
		Object.entries(platforms).map(([k, p]) => [k, [p.type, p.redirect]]),
	);
	assert.deepEqual(got, {
		app: ["public", false],
		mini: ["public", false],
		spa: ["public", true],
		web: ["confidential", true],
		m2m: ["m2m", false],
	});
});

const done = (items: { key: string; done?: boolean }[]) =>
	Object.fromEntries(items.map((i) => [i.key, i.done]));

test("a confidential app's checklist waits on the secret and default API", () => {
	const app = { type: "confidential" as const, defaultApi: undefined };
	assert.deepEqual(done(checklist(app, false)), {
		clientId: true,
		secret: false,
		api: false,
		code: undefined,
	});
	assert.deepEqual(
		done(checklist({ ...app, defaultApi: "https://api.shop" }, true)),
		{ clientId: true, secret: true, api: true, code: undefined },
	);
});

test("a public app has no secret to save", () => {
	const items = checklist({ type: "public", defaultApi: undefined }, false);
	assert.deepEqual(
		items.map((i) => i.key),
		["clientId", "api", "code"],
	);
});

test("an m2m app's default API is settled at creation", () => {
	assert.deepEqual(
		done(checklist({ type: "m2m", defaultApi: "https://api.shop" }, false)),
		{
			clientId: true,
			secret: false,
			api: true,
			code: undefined,
		},
	);
});

test("each platform gets its own integration code", () => {
	const at = {
		issuer: "https://auth.example.com",
		clientId: "app_1",
		redirectUri: "https://shop.example.com/callback",
	};
	const code = (p: Platform) => snippet(p, at).code;
	assert.match(code("app"), /PolarisConfig\(/);
	assert.match(
		code("mini"),
		/POST https:\/\/auth\.example\.com\/v1\/auth\/challenge/,
	);
	assert.match(code("spa"), /new UserManager\(/);
	assert.match(
		code("spa"),
		/redirect_uri: "https:\/\/shop\.example\.com\/callback"/,
	);
	assert.match(code("web"), /client_secret/);
	assert.match(code("m2m"), /grant_type=client_credentials/);
	assert.match(code("m2m"), /-u "app_1:\$POLARIS_CLIENT_SECRET"/);
	for (const p of ["app", "mini", "spa", "web", "m2m"] as const) {
		assert.match(code(p), /app_1/);
	}
});
