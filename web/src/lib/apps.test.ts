import assert from "node:assert/strict";
import { test } from "node:test";
import {
	accountAPI,
	androidApps,
	androidLines,
	backchannelSchema,
	createSchema,
	loginSchema,
	m2mAPIs,
	nativeSchema,
	onlyBuiltin,
	ownCount,
	webhookSchema,
} from "./apps.ts";
import { managementAPI } from "./users.ts";

const consoleApp = { builtin: true };
const shop = { builtin: false };

test("only built-in while every Application is built in", () => {
	assert.equal(onlyBuiltin([consoleApp]), true);
});

test("not only built-in once the first own Application exists", () => {
	assert.equal(onlyBuiltin([consoleApp, shop]), false);
});

test("the overview counts only your own Applications", () => {
	assert.equal(ownCount([consoleApp, shop, shop]), 2);
	assert.equal(ownCount([consoleApp]), 0);
});

// fieldErrors is what a form shows under each field.
const fieldErrors = (r: {
	error?: { issues: { path: PropertyKey[]; message: string }[] };
}) =>
	Object.fromEntries(
		(r.error?.issues ?? []).map((i) => [i.path.join("."), i.message]),
	);

test("creating an Application needs a name and, on the web, callback URLs", () => {
	assert.deepEqual(
		fieldErrors(
			createSchema(true).safeParse({
				name: " ",
				redirectUris: "",
				defaultApi: "",
			}),
		),
		{ name: "请填写名称。", redirectUris: "请填写回调地址。" },
	);
	assert.deepEqual(
		fieldErrors(
			createSchema(true).safeParse({
				name: "星选商城",
				redirectUris: "https://shop.example.com/callback\nshop/callback",
				defaultApi: "",
			}),
		),
		{ redirectUris: "「shop/callback」不是有效的地址。" },
	);
	assert.equal(
		createSchema(false).safeParse({
			name: "星选商城",
			redirectUris: "",
			defaultApi: "",
		}).success,
		true,
	);
});

test("a 后端服务 must pick its default API", () => {
	assert.deepEqual(
		fieldErrors(
			createSchema(false, true).safeParse({
				name: "对账单任务",
				redirectUris: "",
				defaultApi: "",
			}),
		),
		{ defaultApi: "请选择默认 API 资源。" },
	);
	assert.equal(
		createSchema(false, true).safeParse({
			name: "对账单任务",
			redirectUris: "",
			defaultApi: "https://api.shop",
		}).success,
		true,
	);
});

test("an M2M Application may call any API but the Account API", () => {
	const apis = [
		{ identifier: "https://api.shop" },
		{ identifier: managementAPI },
		{ identifier: accountAPI },
	];
	assert.deepEqual(
		m2mAPIs(apis).map((a) => a.identifier),
		["https://api.shop", managementAPI],
	);
});

test("a webhook URL needs a key, new or already set", () => {
	const webhookUrl = "https://shop.example.com/hooks";
	assert.deepEqual(
		fieldErrors(
			webhookSchema(false).safeParse({ webhookUrl, webhookSecret: "" }),
		),
		{
			webhookSecret: "请设置 Webhook 密钥。填写通知地址后，必须同时设置密钥。",
		},
	);
	assert.equal(
		webhookSchema(false).safeParse({ webhookUrl, webhookSecret: "whsec_1" })
			.success,
		true,
	);
	assert.equal(
		webhookSchema(true).safeParse({ webhookUrl, webhookSecret: "" }).success,
		true,
	);
	assert.equal(
		webhookSchema(false).safeParse({ webhookUrl: "", webhookSecret: "" })
			.success,
		true,
	);
});

test("the webhook goes to an http(s) URL", () => {
	assert.deepEqual(
		fieldErrors(
			webhookSchema(true).safeParse({
				webhookUrl: "shop.example.com",
				webhookSecret: "",
			}),
		),
		{ webhookUrl: "请填写 http 或 https 开头的地址。" },
	);
});

test("the back-channel logout URI is an http(s) URL without #, or empty", () => {
	const check = (backchannelLogoutUri: string) =>
		fieldErrors(backchannelSchema.safeParse({ backchannelLogoutUri }));
	assert.deepEqual(check(""), {});
	assert.deepEqual(check("https://shop.example.com/logout"), {});
	assert.deepEqual(check("shop.example.com/logout"), {
		backchannelLogoutUri: "请填写 http 或 https 开头的地址。",
	});
	assert.deepEqual(check("https://shop.example.com/logout#x"), {
		backchannelLogoutUri: "地址不能带 #。",
	});
});

test("sign-in redirects are URLs and idle days a whole number up to a year", () => {
	const ok = {
		redirectUris: "com.example.shop://callback",
		postLogoutRedirectUris: "",
		idleDays: "",
		maxDays: "",
		refreshTokens: true,
	};
	assert.equal(loginSchema.safeParse(ok).success, true);
	assert.equal(loginSchema.safeParse({ ...ok, idleDays: "30" }).success, true);
	assert.equal(loginSchema.safeParse({ ...ok, idleDays: "0" }).success, true);
	for (const idleDays of ["1.5", "366", "abc"]) {
		assert.deepEqual(fieldErrors(loginSchema.safeParse({ ...ok, idleDays })), {
			idleDays: "请填写 0 到 365 之间的整数，0 表示默认值。",
		});
	}
	assert.equal(loginSchema.safeParse({ ...ok, maxDays: "180" }).success, true);
	for (const maxDays of ["1.5", "366", "abc"]) {
		assert.deepEqual(fieldErrors(loginSchema.safeParse({ ...ok, maxDays })), {
			maxDays: "请填写 0 到 365 之间的整数，0 表示默认值。",
		});
	}
	assert.deepEqual(
		fieldErrors(
			loginSchema.safeParse({ ...ok, postLogoutRedirectUris: "/home" }),
		),
		{ postLogoutRedirectUris: "「/home」不是有效的地址。" },
	);
});

test("the Android textarea and its entries round-trip", () => {
	const fp =
		"14:6D:E9:83:C5:73:06:50:D8:EE:B9:95:2F:34:FC:64:16:A0:83:42:E6:1D:BE:A8:8A:04:96:B2:3F:CF:44:E5";
	const text = `com.example.app ${fp}\ncom.example.app.dev ${fp} ${fp}`;
	assert.equal(androidLines(androidApps(text)), text);
	assert.deepEqual(androidLines([]), "");
	assert.deepEqual(androidApps(`  \ncom.example.app  ${fp}\n\n`), [
		{ packageName: "com.example.app", sha256CertFingerprints: [fp] },
	]);
});

test("native App association lines are Team ID.Bundle ID, package + fingerprints", () => {
	const fp =
		"14:6D:E9:83:C5:73:06:50:D8:EE:B9:95:2F:34:FC:64:16:A0:83:42:E6:1D:BE:A8:8A:04:96:B2:3F:CF:44:E5";
	const ok = {
		apple: "ABCDE12345.com.example.app",
		android: `com.example.app ${fp} ${fp}`,
	};
	assert.equal(nativeSchema.safeParse(ok).success, true);
	assert.equal(
		nativeSchema.safeParse({ apple: "", android: "" }).success,
		true,
	);
	assert.deepEqual(
		fieldErrors(nativeSchema.safeParse({ ...ok, apple: "com.example.app" })),
		{
			apple:
				"「com.example.app」须为 Team ID.Bundle ID，如 ABCDE12345.com.example.app。",
		},
	);
	for (const android of [
		"com.example.app",
		`app ${fp}`,
		`com.example.app ab:cd`,
	]) {
		assert.deepEqual(fieldErrors(nativeSchema.safeParse({ ...ok, android })), {
			android:
				"「" +
				android +
				"」须为包名加签名指纹，指纹形如 AB:CD:…（十六进制，32 字节），可多个、空格分隔。",
		});
	}
});
