import assert from "node:assert/strict";
import { test } from "node:test";
import {
	asksRequirePhone,
	asksShorterRetention,
	asksTermsVersion,
	channelSchema,
	disableImpact,
	hasChannel,
	lastRotation,
	numberSchema,
	passwordLocksOut,
	providerSchema,
	rotatedRecently,
	sendsNothing,
	smsLocked,
	termsSchema,
	testSchema,
} from "./login.ts";

const sms = { kind: "phone" as const };

test("a kind with an enabled channel can send codes", () => {
	// 必须绑定手机号 can be turned on; phone code login works.
	assert.equal(hasChannel([sms], "phone"), true);
});

test("a kind without an enabled channel can't send codes", () => {
	// 必须绑定手机号 is disabled; email code login gets 去设置通道.
	assert.equal(hasChannel([sms], "email"), false);
	assert.equal(hasChannel([], "phone"), false);
});

const terms = "https://shop.example.com/terms";
const privacy = "https://shop.example.com/privacy";

// fieldErrors is what a form shows under each field.
const fieldErrors = (r: {
	error?: { issues: { path: PropertyKey[]; message: string }[] };
}) =>
	Object.fromEntries(
		(r.error?.issues ?? []).map((i) => [i.path.join("."), i.message]),
	);

test("a terms version needs both URLs", () => {
	assert.deepEqual(
		fieldErrors(
			termsSchema.safeParse({
				termsUrl: terms,
				privacyUrl: "",
				termsVersion: "2026-10",
			}),
		),
		{
			privacyUrl:
				"请填写地址。设了协议版本，用户登录时要打开用户协议和隐私政策才能同意。",
		},
	);
});

test("a terms URL must be https", () => {
	assert.deepEqual(
		fieldErrors(
			termsSchema.safeParse({
				termsUrl: "http://shop.example.com/terms",
				privacyUrl: privacy,
				termsVersion: "",
			}),
		),
		{ termsUrl: "请填写 https 开头的地址。认证服务只接受 https 链接。" },
	);
});

test("https URLs with a version, or no version and no URLs, save", () => {
	assert.equal(
		termsSchema.safeParse({
			termsUrl: terms,
			privacyUrl: privacy,
			termsVersion: "2026-10",
		}).success,
		true,
	);
	assert.equal(
		termsSchema.safeParse({ termsUrl: "", privacyUrl: "", termsVersion: "" })
			.success,
		true,
	);
});

test("a policy number is a whole number from its minimum up", () => {
	assert.equal(numberSchema(0).safeParse({ value: "0" }).success, true);
	assert.equal(numberSchema(1).safeParse({ value: "30" }).success, true);
	for (const value of ["", "0", "1.5", "-3", "abc"]) {
		assert.deepEqual(fieldErrors(numberSchema(1).safeParse({ value })), {
			value: "请填写不小于 1 的整数。",
		});
	}
});

const fields = [
	{ key: "region", label: "地域", type: "text", secret: false, optional: true },
	{
		key: "endpoint",
		label: "接口地址",
		type: "url",
		secret: false,
		optional: false,
	},
	{
		key: "port",
		label: "端口",
		type: "number",
		secret: false,
		optional: false,
	},
	{
		key: "secret",
		label: "密钥",
		type: "text",
		secret: true,
		optional: false,
	},
] as const;

test("a channel needs its required fields, in their format", () => {
	assert.deepEqual(
		fieldErrors(
			channelSchema(fields, {}).safeParse({
				region: "",
				endpoint: "sms.example",
				port: "abc",
				secret: "",
			}),
		),
		{
			endpoint: "请填写有效的地址。",
			port: "请填写数字。",
			secret: "请填写密钥。",
		},
	);
	assert.deepEqual(
		fieldErrors(
			channelSchema(fields, {}).safeParse({
				region: "",
				endpoint: "",
				port: "",
				secret: "s",
			}),
		),
		{ endpoint: "请填写接口地址。", port: "请填写端口。" },
	);
});

test("a secret already set may stay empty", () => {
	assert.equal(
		channelSchema(fields, { secret: "2026-10-01T00:00:00Z" }).safeParse({
			region: "",
			endpoint: "https://sms.example.com",
			port: "443",
			secret: "",
		}).success,
		true,
	);
});

test("a test code goes to an email or a phone number", () => {
	assert.equal(
		testSchema("email").safeParse({ to: "you@example.com" }).success,
		true,
	);
	assert.deepEqual(fieldErrors(testSchema("email").safeParse({ to: "you" })), {
		to: "请填写有效的邮箱。",
	});
	assert.equal(
		testSchema("phone").safeParse({ to: "+8613800001111" }).success,
		true,
	);
	assert.deepEqual(fieldErrors(testSchema("phone").safeParse({ to: "" })), {
		to: "请填写手机号，如 +8613800001111。",
	});
});

test("turning 必须绑定手机号 on asks first", () => {
	assert.equal(asksRequirePhone(false, true), true);
});

test("leaving 必须绑定手机号 as it was or turning it off doesn't ask", () => {
	assert.equal(asksRequirePhone(true, true), false);
	assert.equal(asksRequirePhone(true, false), false);
	assert.equal(asksRequirePhone(false, false), false);
});

test("a new terms version asks first, the first one too", () => {
	// All users agree again on their next login.
	assert.equal(asksTermsVersion("2026-01", "2026-10"), true);
	assert.equal(asksTermsVersion("", "2026-10"), true);
});

test("the same terms version, or none, doesn't ask", () => {
	assert.equal(asksTermsVersion("2026-10", "2026-10"), false);
	assert.equal(asksTermsVersion("2026-10", ""), false);
});

test("a shorter audit retention asks first", () => {
	// Older events are deleted within the hour.
	assert.equal(asksShorterRetention(180, 30), true);
});

test("the same or a longer audit retention doesn't ask", () => {
	assert.equal(asksShorterRetention(180, 180), false);
	assert.equal(asksShorterRetention(30, 180), false);
});

test("password login off warns", () => {
	// Username-only users can't sign in; the account center can't set one.
	assert.equal(passwordLocksOut("off"), true);
});

test("password login on doesn't warn", () => {
	assert.equal(passwordLocksOut("on"), false);
});

test("a daily send limit of 0 warns", () => {
	assert.equal(sendsNothing(0), true);
});

test("a daily send limit above 0 doesn't warn", () => {
	assert.equal(sendsNothing(1), false);
});

const rotatedAt = "2026-10-07T08:00:00Z";

test("rotating within a day of the last rotation warns harder", () => {
	// Tokens from the key before last stop working at once.
	assert.equal(
		rotatedRecently(rotatedAt, new Date("2026-10-08T07:59:00Z")),
		true,
	);
});

test("rotating a day or more after the last rotation doesn't", () => {
	assert.equal(
		rotatedRecently(rotatedAt, new Date("2026-10-08T08:00:00Z")),
		false,
	);
});

test("SMS can't be stopped while 必须绑定手机号 is on", () => {
	assert.equal(smsLocked("phone", true), true);
});

test("SMS can be stopped with 必须绑定手机号 off, and email always", () => {
	assert.equal(smsLocked("phone", false), false);
	assert.equal(smsLocked("email", true), false);
});

const first = { createdAt: "2026-09-01T08:00:00Z", current: false };
const second = { createdAt: "2026-10-07T08:00:00Z", current: true };

test("the current key's creation is the last rotation once a key retired", () => {
	assert.equal(lastRotation([second, first]), "2026-10-07T08:00:00Z");
});

test("a lone key was never rotated", () => {
	assert.equal(lastRotation([{ ...first, current: true }]), "");
	assert.equal(lastRotation([]), "");
});

const oidcFields = [
	{
		key: "issuer",
		label: "Issuer",
		type: "url",
		secret: false,
		optional: false,
	},
	{
		key: "client_secret",
		label: "Client secret",
		type: "text",
		secret: true,
		optional: false,
	},
] as const;

test("a new Provider needs an ID in the callback URL's form, a name and its fields", () => {
	assert.deepEqual(
		fieldErrors(
			providerSchema(oidcFields, {}, true).safeParse({
				id: "Google!",
				name: " ",
				config: { issuer: "accounts.google.com", client_secret: "" },
			}),
		),
		{
			id: "Provider ID 只能用小写字母、数字和 -，以字母或数字开头，最多 32 位。",
			name: "请填写名称。",
			"config.issuer": "请填写有效的地址。",
			"config.client_secret": "请填写Client secret。",
		},
	);
	assert.deepEqual(
		fieldErrors(
			providerSchema(oidcFields, {}, true).safeParse({
				id: "google",
				name: "Google",
				config: { issuer: "https://accounts.google.com", client_secret: "s" },
			}),
		),
		{},
	);
});

test("editing a Provider keeps its ID and a secret already set", () => {
	assert.deepEqual(
		fieldErrors(
			providerSchema(
				oidcFields,
				{ client_secret: "2026-10-01T00:00:00Z" },
				false,
			).safeParse({
				id: "",
				name: "Google",
				config: { issuer: "https://accounts.google.com", client_secret: "" },
			}),
		),
		{},
	);
});

test("disabling a Provider says whom it locks out", () => {
	assert.equal(
		disableImpact({ bound: 12, onlyLoginPath: 3 }),
		"12 个用户已绑定，其中 3 个没有其他登录方式，停用后他们无法登录。",
	);
	assert.equal(
		disableImpact({ bound: 0, onlyLoginPath: 0 }),
		"还没有用户绑定。停用后登录页不再显示这个按钮。",
	);
});
