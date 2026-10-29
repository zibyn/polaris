import assert from "node:assert/strict";
import { test } from "node:test";
import type { Login } from "./account-api.ts";
import { loginLine } from "./logins.ts";

const chrome =
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";
const at = "2026-10-29T06:00:00Z";

test("a sign-in shows its first factor, and 两步验证 after it", () => {
	const cases: [Partial<Login>, string][] = [
		[{ method: "password", twoFactor: true }, "密码 + 两步验证"],
		[{ method: "code" }, "验证码"],
		[{ method: "passkey" }, "Passkey"],
		[{ method: "provider" }, "外部登录"],
	];
	for (const [l, what] of cases) {
		const line = loginLine({
			at,
			result: "succeeded",
			application: "Polaris 账号中心",
			...l,
		});
		assert.equal(line.result, "成功");
		assert.equal(line.what, what);
	}
});

test("a failure shows the step that went wrong", () => {
	const cases: [Login["method"], string][] = [
		["password", "密码错误"],
		["code", "验证码错误"],
		["totp", "两步验证码错误"],
		["recovery_code", "恢复码错误"],
	];
	for (const [method, what] of cases) {
		const line = loginLine({ at, result: "failed", method, application: "a" });
		assert.equal(line.result, "失败");
		assert.equal(line.what, what);
	}
});

test("a lockout shows until when", () => {
	const until = new Date(2026, 9, 29, 14, 30).toISOString();
	const line = loginLine({
		at,
		result: "locked",
		application: "a",
		lockedUntil: until,
	});
	assert.equal(line.result, "已锁定");
	assert.equal(line.what, "多次失败后已锁定到 14:30");
});

test("the device is the UA's label and the IP", () => {
	const base = { at, result: "succeeded", application: "a" } as const;
	assert.equal(
		loginLine({ ...base, userAgent: chrome, ip: "203.0.113.5" }).device,
		"Chrome · macOS · 203.0.113.5",
	);
	assert.equal(loginLine(base).device, "未知设备");
});
