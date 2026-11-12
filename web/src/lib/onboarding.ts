// Create-Application onboarding (docs/spec/consoles.md「创建应用与接入清单」).
// Pure TypeScript: tested with node --test. The platform only guides; it
// isn't stored, and the create request stays {type, settings}.
import type { Application } from "./console-api.ts";

// redirect platforms sign in through the browser and need a callback
// address; App and 小程序 use the direct auth API and don't.
export const platforms = {
	app: {
		name: "手机 App",
		desc: "iOS、Android 原生或跨平台 App，在 App 内登录。",
		type: "public",
		redirect: false,
	},
	mini: {
		name: "小程序",
		desc: "微信等小程序，在小程序内登录。",
		type: "public",
		redirect: false,
	},
	spa: {
		name: "纯前端网页",
		desc: "React、Vue 等单页应用，无服务器，跳转到登录页登录。",
		type: "public",
		redirect: true,
	},
	web: {
		name: "有后端的网站",
		desc: "服务端渲染或带后端的网站，由服务器完成登录。",
		type: "confidential",
		redirect: true,
	},
	m2m: {
		name: "后端服务（M2M）",
		desc: "定时任务、内部服务等，无用户登录，以自身身份调用一个 API。",
		type: "m2m",
		redirect: false,
	},
} satisfies Record<
	string,
	{ name: string; desc: string; type: Application["type"]; redirect: boolean }
>;

export type Platform = keyof typeof platforms;

export const platformKeys = Object.keys(platforms) as [Platform, ...Platform[]];

// newSecrets hands a new Application's client secret from the create page
// to the 接入清单, in memory only: it never goes in the URL.
export const newSecrets = new Map<string, string>();

// lines splits a textarea into one trimmed entry per non-empty line.
export const lines = (v: FormDataEntryValue | null) =>
	`${v ?? ""}`
		.split("\n")
		.map((l) => l.trim())
		.filter(Boolean);

// checklist is the 接入清单's steps, ticked from the Application: client_id
// is there once it exists, the secret once the admin says it's saved, the
// default API once one is set. The code step has nothing to tick it.
export const checklist = (
	app: Pick<Application, "type" | "defaultApi">,
	secretSaved: boolean,
): { key: "clientId" | "secret" | "api" | "code"; done?: boolean }[] => [
	{ key: "clientId", done: true },
	...(app.type !== "public"
		? [{ key: "secret" as const, done: secretSaved }]
		: []),
	{ key: "api", done: !!app.defaultApi },
	{ key: "code" },
];

// snippet is the 接入代码 for a platform: a sentence on how, then code
// filled in with this Application.
export function snippet(
	platform: Platform,
	{
		issuer,
		clientId,
		redirectUri,
	}: { issuer: string; clientId: string; redirectUri?: string },
): { help: string; code: string } {
	switch (platform) {
		case "app":
			return {
				help: "接入 KMP SDK。登录界面由 App 实现，SDK 负责发送验证码、校验和换取令牌。",
				code: `Polaris(
  PolarisConfig(
    issuer = "${issuer}",
    clientId = "${clientId}",
  ),
  store,
)`,
			};
		case "mini":
			return {
				help: "小程序 SDK 开发中，可按接口文档直接调用直连认证 API，登录界面由小程序实现。",
				code: `POST ${issuer}/v1/auth/challenge
client_id=${clientId}

接口文档：${issuer}/v1/auth/openapi.json`,
			};
		case "spa":
			return {
				help: "推荐使用 oidc-client-ts。用户跳转到登录页，登录后返回回调地址。",
				code: `new UserManager({
  authority: "${issuer}",
  client_id: "${clientId}",
  redirect_uri: "${redirectUri ?? "https://…/callback"}",
})`,
			};
		case "web":
			return {
				help: "使用后端语言的 OIDC 客户端库，填入以下三项。client secret 只能存放在服务器上。",
				code: `issuer        = ${issuer}
client_id     = ${clientId}
client_secret = （创建时保存的值）`,
			};
		case "m2m":
			return {
				help: "使用 client_credentials 换取令牌，client_id 和 client_secret 通过 HTTP Basic 认证。令牌 10 分钟后过期，无 refresh token，过期后重新换取。",
				code: `curl -u "${clientId}:$POLARIS_CLIENT_SECRET" \\
  -d grant_type=client_credentials \\
  ${issuer}/token`,
			};
	}
}

// platformOf guesses a platform back from an Application, for the 接入指南
// beside its detail page: the platform itself isn't stored. A public one
// with a callback signs in through the browser; without, it's an App.
export const platformOf = (
	app: Pick<Application, "type" | "redirectUris">,
): Platform =>
	app.type === "m2m"
		? "m2m"
		: app.type === "confidential"
			? "web"
			: app.redirectUris.length > 0
				? "spa"
				: "app";
