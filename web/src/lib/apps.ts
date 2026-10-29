// Application list and detail logic. Pure TypeScript: tested with node --test.
import { z } from "zod";
import type { AndroidApp, Application } from "./console-api.ts";
import { lines } from "./onboarding.ts";

// onlyBuiltin reports whether the list holds nothing but built-in
// Applications, which counts as empty (docs/spec/consoles.md「空状态」).
export const onlyBuiltin = (apps: Pick<Application, "builtin">[]) =>
	apps.every((a) => a.builtin);

// ownCount is the overview's 应用 figure: built-in ones don't count.
export const ownCount = (apps: Pick<Application, "builtin">[]) =>
	apps.filter((a) => !a.builtin).length;

// typeName and typeWhy say what each type of Application is for.
export const typeName: Record<Application["type"], string> = {
	public: "无后端应用",
	confidential: "有后端应用",
	m2m: "后端服务",
};

export const typeWhy: Record<Application["type"], string> = {
	public:
		"适合 App、小程序和纯前端网页。没有 client secret，登录时靠 PKCE 防止授权码被截走。类型创建后不能更改。",
	confidential:
		"适合有自己服务器的网站。后端用 client secret 证明自己的身份。类型创建后不能更改。",
	m2m: "没有用户登录，以自己的身份调用 API。用自己的 client secret 换令牌，令牌只对它选定的那个 API 有效。类型和默认 API 创建后都不能更改。",
};

// accountAPI is the built-in API the account center calls; no Application
// may use it as its default API.
export const accountAPI = "urn:polaris:account-api";

// m2mAPIs are the APIs an M2M Application may choose as its default API: any
// registered one, the Management API included (ADR 0015), but not the
// Account API.
export const m2mAPIs = <T extends { identifier: string }>(apis: T[]): T[] =>
	apis.filter((a) => a.identifier !== accountAPI);

export const appName = z
	.string()
	.trim()
	.min(1, "请填写名称。")
	.max(64, "名称最多 64 个字。");

// basicSchema checks the 基本信息 section.
export const basicSchema = z.object({ name: appName });

// uriLines is a textarea of addresses, one per line; App callbacks use
// their own scheme, so any absolute URL goes.
export const uriLines = z.string().superRefine((v, ctx) => {
	const bad = lines(v).find((l) => !URL.canParse(l));
	if (bad) {
		ctx.addIssue({ code: "custom", message: `「${bad}」不是有效的地址。` });
	}
});

// createSchema checks the create page: a name, at least one callback URL for
// the web, and the one API a 后端服务 calls.
export const createSchema = (redirect: boolean, needsAPI = false) =>
	z.object({
		name: appName,
		redirectUris: redirect
			? uriLines.refine((v) => lines(v).length > 0, "请填写回调地址。")
			: z.string(),
		defaultApi: z
			.string()
			.refine((v) => !needsAPI || v.length > 0, "请选择默认 API 资源。"),
	});

// httpURL is an optional address the server calls out to.
export const httpURL = z
	.string()
	.trim()
	.refine(
		(v) => !v || /^https?:$/.test(URL.parse(v)?.protocol ?? ""),
		"请填写 http 或 https 开头的地址。",
	);

// backchannelSchema checks the 退出通知 section; a URI with # is refused
// by the server too (OIDC Back-Channel Logout §2.2).
export const backchannelSchema = z.object({
	backchannelLogoutUri: httpURL.refine(
		(v) => !v.includes("#"),
		"地址不能带 #。",
	),
});

// loginSchema checks the 登录 tab; 0 or an empty idleDays means the default.
export const loginSchema = z.object({
	redirectUris: uriLines,
	postLogoutRedirectUris: uriLines,
	idleDays: z
		.string()
		.trim()
		.refine(
			(v) => !v || (/^\d+$/.test(v) && +v >= 0 && +v <= 365),
			"请填写 0 到 365 之间的整数，0 表示默认值。",
		),
	refreshTokens: z.boolean(),
});

// webhookSchema stops a save with a webhook URL but no key, new or
// already set; the backend rejects that too.
export const webhookSchema = (secretSet: boolean) =>
	z
		.object({ webhookUrl: httpURL, webhookSecret: z.string() })
		.refine((w) => !w.webhookUrl || w.webhookSecret || secretSet, {
			path: ["webhookSecret"],
			message: "请设置 Webhook 密钥。填写通知地址后，必须同时设置密钥。",
		});

// The 原生 App 关联 formats, as the server's validate() checks them too.
const appleAppId = /^[A-Z0-9]{10}\.[A-Za-z0-9.-]+$/;
const packageName = /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$/;
const certSHA256 = /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/;

// androidLines is the Android App textarea: one per line, the package name
// then its fingerprints, space-separated. androidApps parses it back.
export const androidLines = (apps: AndroidApp[]): string =>
	apps
		.map((a) => [a.packageName, ...a.sha256CertFingerprints].join(" "))
		.join("\n");

export const androidApps = (v: string): AndroidApp[] =>
	lines(v).map((l) => {
		const [p, ...sha256CertFingerprints] = l.split(/\s+/);
		return { packageName: p, sha256CertFingerprints };
	});

// nativeSchema checks the 原生 App 关联 section: Apple app IDs and Android
// package + fingerprint lines, each as the server wants them.
export const nativeSchema = z.object({
	apple: z.string().superRefine((v, ctx) => {
		const bad = lines(v).find((l) => !appleAppId.test(l));
		if (bad) {
			ctx.addIssue({
				code: "custom",
				message: `「${bad}」须为 Team ID.Bundle ID，如 ABCDE12345.com.example.app。`,
			});
		}
	}),
	android: z.string().superRefine((v, ctx) => {
		const bad = lines(v).find((l) => {
			const [p, ...fps] = l.split(/\s+/);
			return (
				!packageName.test(p) ||
				fps.length === 0 ||
				fps.some((f) => !certSHA256.test(f))
			);
		});
		if (bad) {
			ctx.addIssue({
				code: "custom",
				message: `「${bad}」须为包名加签名指纹，指纹形如 AB:CD:…（十六进制，32 字节），可多个、空格分隔。`,
			});
		}
	}),
});
