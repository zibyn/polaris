import assert from "node:assert/strict";
import { test } from "node:test";
import { navGroups, needsTwoFactor } from "./nav.ts";
import { APIError } from "./oidc.ts";

test("only the 403 for want of 两步验证 sends the admin to set it up", () => {
	assert.equal(
		needsTwoFactor(
			new APIError(403, "需要先开启两步验证", "two_factor_required"),
		),
		true,
	);
	assert.equal(needsTwoFactor(new APIError(403, "not an admin")), false);
	assert.equal(needsTwoFactor(new Error("two_factor_required")), false);
	assert.equal(needsTwoFactor(undefined), false);
});

const labels = (permissions: string[]) =>
	navGroups(permissions).map((g) => g.label);

test("an owner sees all seven groups in order", () => {
	assert.deepEqual(
		labels(["users:read", "applications:read", "config:read", "audit:read"]),
		["概览", "用户", "应用", "API 资源", "认证源", "审计", "设置"],
	);
});

test("each group needs the Permission consoles.md lists", () => {
	assert.deepEqual(labels(["users:read"]), ["概览", "用户"]);
	assert.deepEqual(labels(["applications:read"]), ["应用", "API 资源"]);
	assert.deepEqual(labels(["config:read"]), ["认证源", "设置"]);
	assert.deepEqual(labels(["audit:read"]), ["审计"]);
	assert.deepEqual(labels([]), []);
});
