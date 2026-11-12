import assert from "node:assert/strict";
import { test } from "node:test";
import {
	avatarInitial,
	createUserSchema,
	primaryIdentifier,
	searchSchema,
} from "./users.ts";

test("the primary identifier is the phone, then email, then username", () => {
	const phone = { kind: "phone", value: "+8613800000001" } as const;
	const email = { kind: "email", value: "a@x.com" } as const;
	const username = { kind: "username", value: "alice" } as const;
	assert.equal(primaryIdentifier([email, username, phone]), phone.value);
	assert.equal(primaryIdentifier([username, email]), email.value);
	assert.equal(primaryIdentifier([username]), username.value);
	assert.equal(primaryIdentifier([]), undefined);
});

test("the avatar shows the identifier's first letter, past +86", () => {
	assert.equal(avatarInitial("+8613800001111"), "1");
	assert.equal(avatarInitial("+447700900123"), "+");
	assert.equal(avatarInitial("alice@example.com"), "A");
	assert.equal(avatarInitial("张三"), "张");
});

test("the user search takes up to 100 characters", () => {
	assert.equal(searchSchema.safeParse({ q: "" }).success, true);
	assert.equal(searchSchema.safeParse({ q: "a".repeat(100) }).success, true);
	assert.deepEqual(
		searchSchema.safeParse({ q: "a".repeat(101) }).error?.issues[0].message,
		"最多输入 100 个字。",
	);
});

test("creating a User takes an Identifier and a password of 8 or more", () => {
	const ok = createUserSchema.safeParse({
		identifier: "alice@example.com",
		way: "password",
		password: "password1",
	});
	assert.equal(ok.success, true);
	// A password is handed over as typed, not trimmed: the spaces count.
	assert.equal(
		createUserSchema.safeParse({
			identifier: "13800001111",
			way: "password",
			password: " passwd1 ",
		}).success,
		true,
	);
});

test("an invite needs no password at all", () => {
	// 二选一: 选了邀请, 表单上就没有密码这一项。
	assert.equal(
		createUserSchema.safeParse({
			identifier: "alice@example.com",
			way: "invite",
			password: "",
		}).success,
		true,
	);
	// 邀请只走邮箱, 但"这是不是邮箱"是服务端的判断: 这里只要求填了标识符。
	assert.deepEqual(
		createUserSchema.safeParse({ identifier: " ", way: "invite", password: "" })
			.error?.issues[0].message,
		"请输入登录标识。",
	);
});

test("creating a User needs an Identifier", () => {
	// Whitespace is not an Identifier; the kind is the server's call.
	assert.deepEqual(
		createUserSchema.safeParse({
			identifier: "  ",
			way: "password",
			password: "password1",
		}).error?.issues[0].message,
		"请输入登录标识。",
	);
});

test("creating a User needs 8 characters of password", () => {
	assert.deepEqual(
		createUserSchema.safeParse({
			identifier: "bob",
			way: "password",
			password: "passwd1",
		}).error?.issues[0].message,
		"密码至少 8 位。",
	);
});
