import assert from "node:assert/strict";
import { test } from "node:test";
import { navItems, navSections, needsTwoFactor } from "./nav.ts";
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
	navItems(permissions).map((g) => g.label);

const all = ["users:read", "applications:read", "config:read", "audit:read"];

test("an owner sees every item in sidebar order", () => {
	assert.deepEqual(labels(all), [
		"概览",
		"应用",
		"API 资源",
		"登录体验",
		"认证源",
		"验证码通道",
		"用户",
		"审计日志",
		"安全",
	]);
	assert.deepEqual(
		navSections(all).map((s) => s.title),
		["", "身份认证", "用户管理", "系统"],
	);
});

test("each item needs the Permission consoles.md lists", () => {
	assert.deepEqual(labels(["users:read"]), ["概览", "用户"]);
	assert.deepEqual(labels(["applications:read"]), ["应用", "API 资源"]);
	assert.deepEqual(labels(["config:read"]), [
		"登录体验",
		"认证源",
		"验证码通道",
		"安全",
	]);
	assert.deepEqual(labels(["audit:read"]), ["审计日志"]);
	assert.deepEqual(labels([]), []);
});

test("a section with nothing visible is dropped with its title", () => {
	assert.deepEqual(
		navSections(["audit:read"]).map((s) => s.title),
		["系统"],
	);
});
