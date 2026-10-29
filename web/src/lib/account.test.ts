import assert from "node:assert/strict";
import { test } from "node:test";
import {
	avatarProblem,
	bindSchema,
	deleteSchema,
	nicknameSchema,
	passwordSchema,
	providerReturn,
	reauthChoices,
	reauthSchema,
	recoveryCodesText,
	totpSchema,
} from "./account.ts";

// fieldErrors is what a form shows under each field.
const fieldErrors = (r: {
	error?: { issues: { path: PropertyKey[]; message: string }[] };
}) =>
	Object.fromEntries(
		(r.error?.issues ?? []).map((i) => [i.path.join("."), i.message]),
	);

test("a new phone number is a mainland mobile, +86 optional", () => {
	for (const value of ["13800000001", "+86 138-0000-0001", "8613800000001"]) {
		assert.equal(
			bindSchema("phone", false).safeParse({ value, code: "" }).success,
			true,
			value,
		);
	}
	for (const value of ["", "12800000001", "+447700900123"]) {
		assert.deepEqual(
			fieldErrors(bindSchema("phone", false).safeParse({ value, code: "" })),
			{ value: "请输入 +86 手机号" },
		);
	}
});

test("a new email looks like one", () => {
	assert.equal(
		bindSchema("email", false).safeParse({ value: "a@x.com", code: "" })
			.success,
		true,
	);
	assert.deepEqual(
		fieldErrors(
			bindSchema("email", false).safeParse({ value: "a@x", code: "" }),
		),
		{ value: "请输入邮箱" },
	);
});

test("binding asks for the 6-digit code only once it is sent", () => {
	const value = "a@x.com";
	assert.deepEqual(
		fieldErrors(bindSchema("email", true).safeParse({ value, code: "12345" })),
		{ code: "请输入 6 位验证码" },
	);
	assert.equal(
		bindSchema("email", true).safeParse({ value, code: "123456" }).success,
		true,
	);
});

test("a password has at least 8 characters", () => {
	assert.deepEqual(
		fieldErrors(passwordSchema.safeParse({ password: "密码1234567" })),
		{},
	);
	assert.deepEqual(
		fieldErrors(passwordSchema.safeParse({ password: "1234567" })),
		{
			password: "密码至少 8 位",
		},
	);
});

test("reauthentication needs the password, or the code once sent", () => {
	assert.deepEqual(
		fieldErrors(reauthSchema("password", false).safeParse({ secret: "" })),
		{ secret: "请输入密码" },
	);
	assert.equal(
		reauthSchema("email", false).safeParse({ secret: "" }).success,
		true,
	);
	assert.deepEqual(
		fieldErrors(reauthSchema("email", true).safeParse({ secret: "12" })),
		{ secret: "请输入 6 位验证码" },
	);
});

test("with 两步验证 on, reauthentication takes a TOTP or a recovery code", () => {
	assert.deepEqual(
		fieldErrors(reauthSchema("totp", false).safeParse({ secret: "12345" })),
		{ secret: "请输入验证器中的 6 位数字" },
	);
	for (const ok of ["abcd-2345", "ABCD2345", " abcd 2345 "]) {
		assert.equal(
			reauthSchema("recovery", false).safeParse({ secret: ok }).success,
			true,
			ok,
		);
	}
	assert.deepEqual(
		fieldErrors(
			reauthSchema("recovery", false).safeParse({ secret: "abcd-234" }),
		),
		{ secret: "请输入恢复码,形如 xxxx-xxxx" },
	);
});

test("deleting the account takes typing 注销", () => {
	assert.equal(deleteSchema.safeParse({ confirm: "注销" }).success, true);
	assert.deepEqual(fieldErrors(deleteSchema.safeParse({ confirm: "删除" })), {
		confirm: "请输入「注销」确认",
	});
});

test("confirming the TOTP takes the authenticator's 6 digits", () => {
	assert.equal(totpSchema.safeParse({ code: " 123456 " }).success, true);
	assert.deepEqual(fieldErrors(totpSchema.safeParse({ code: "12345" })), {
		code: "请输入验证器中的 6 位数字",
	});
});

test("coming back from a Provider says how it went", () => {
	const name = (id: string) => ({ google: "Google" })[id] ?? id;
	assert.deepEqual(providerReturn("?bound=google", name), {
		success: "已绑定 Google",
	});
	assert.deepEqual(providerReturn("?reauthenticated=google", name), {
		success: "已验证身份,请继续操作",
	});
	assert.deepEqual(providerReturn("?error=%E5%87%BA%E9%94%99", name), {
		error: "出错",
	});
	assert.equal(providerReturn("", name), null);
});

test("recovery codes download as a text file, one per line", () => {
	assert.equal(
		recoveryCodesText("auth.example.com", ["abcd-efgh", "ijkl-mnop"]),
		"auth.example.com 两步验证恢复码\n每个只能用一次。\n\nabcd-efgh\nijkl-mnop\n",
	);
});

// meUser is the part of the Account API's /me the reauthentication choices
// come from.
const meUser = (over: Partial<Parameters<typeof reauthChoices>[0]> = {}) => ({
	identifiers: [{ kind: "phone" }],
	hasPassword: false,
	passwordAllowed: false,
	passkeyLogin: true,
	twoFactor: { enabled: false },
	...over,
});

test("reauthentication offers a Passkey only to a User who has one", () => {
	assert.deepEqual(reauthChoices(meUser(), false, true), ["phone"]);
	assert.deepEqual(reauthChoices(meUser(), true, true), ["passkey", "phone"]);
	// A browser that cannot run the ceremony is offered no Passkey.
	assert.deepEqual(reauthChoices(meUser(), true, false), ["phone"]);
	// Nor is anyone while the instance has Passkey login off.
	assert.deepEqual(reauthChoices(meUser({ passkeyLogin: false }), true, true), [
		"phone",
	]);
});

test("with 两步验证 on, a Passkey joins the TOTP as a way to reauthenticate", () => {
	const twoFactor = { twoFactor: { enabled: true } };
	assert.deepEqual(reauthChoices(meUser(twoFactor), false, true), ["totp"]);
	assert.deepEqual(reauthChoices(meUser(twoFactor), true, true), [
		"passkey",
		"totp",
	]);
});

test("a nickname is at most 32 characters with no control characters; empty clears it", () => {
	for (const nickname of ["", "  ", "小明", "字".repeat(32), "👨‍👩‍👧 一家"]) {
		assert.equal(
			nicknameSchema.safeParse({ nickname }).success,
			true,
			nickname,
		);
	}
	assert.deepEqual(
		fieldErrors(nicknameSchema.safeParse({ nickname: "字".repeat(33) })),
		{
			nickname: "昵称最多 32 个字符",
		},
	);
	assert.deepEqual(
		fieldErrors(nicknameSchema.safeParse({ nickname: "a\nb" })),
		{
			nickname: "昵称不能含控制字符",
		},
	);
});

test("an avatar is a JPEG, PNG or WebP of at most 5 MB", () => {
	assert.equal(avatarProblem({ type: "image/png", size: 5 << 20 }), undefined);
	assert.equal(avatarProblem({ type: "image/webp", size: 10 }), undefined);
	assert.equal(
		avatarProblem({ type: "image/gif", size: 10 }),
		"头像须为 JPEG、PNG 或 WebP 图片",
	);
	assert.equal(
		avatarProblem({ type: "image/jpeg", size: (5 << 20) + 1 }),
		"头像不能超过 5 MB",
	);
});
