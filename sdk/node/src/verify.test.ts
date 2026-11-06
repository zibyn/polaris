import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { generateKeyPair } from "jose";
import {
	accessTokenVerifier,
	PolarisAuthError,
	requireEntitlements,
} from "./index.ts";
import { api, clientId, type FakeOP, startFakeOP } from "./testing/fake-op.ts";

let op: FakeOP;
let verifyAccessToken: ReturnType<typeof accessTokenVerifier>;
before(async () => {
	op = await startFakeOP();
	verifyAccessToken = accessTokenVerifier({ issuer: op.issuer, audience: api });
});
after(() => op.close());

const rejected = (status: number) => (err: unknown) =>
	err instanceof PolarisAuthError && err.status === status;

test("a User's access token gives its claims", async () => {
	const claims = await verifyAccessToken(
		await op.accessToken({ sub: "user-1", entitlements: ["read", "write"] }),
	);
	assert.equal(claims.sub, "user-1");
	assert.equal(claims.client_id, clientId);
	assert.deepEqual(claims.entitlements, ["read", "write"]);
});

test("an M2M token passes, without entitlements it reads as none", async () => {
	const claims = await verifyAccessToken(
		await op.accessToken({ sub: "m2m-app", client_id: "m2m-app" }),
	);
	assert.equal(claims.sub, "m2m-app");
	assert.deepEqual(claims.entitlements, []);
});

test("wrong audience, type, signature or an expired token are 401", async () => {
	const { privateKey } = await generateKeyPair("RS256");
	const bad = [
		await op.accessToken({ sub: "u" }, { aud: "https://other.example.com" }),
		await op.accessToken({ sub: "u" }, { typ: "JWT" }),
		await op.accessToken({ sub: "u" }, { key: privateKey }),
		"not-a-jwt",
		"",
		undefined,
	];
	op.accessTTL = -60;
	bad.push(await op.accessToken({ sub: "u" }));
	op.accessTTL = 600;
	for (const token of bad)
		await assert.rejects(
			verifyAccessToken(token),
			rejected(401),
			String(token),
		);
});

test("requireEntitlements wants every one listed, else 403", async () => {
	const claims = await verifyAccessToken(
		await op.accessToken({ sub: "u", entitlements: ["read", "write"] }),
	);
	requireEntitlements(claims, "read", "write");
	assert.throws(
		() => requireEntitlements(claims, "read", "admin"),
		rejected(403),
	);
});
