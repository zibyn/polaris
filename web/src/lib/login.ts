// Login and settings dependency hints (docs/spec/consoles.md「依赖提示」).
// Pure TypeScript: tested with node --test.
import { z } from "zod";
import type {
	ChannelField,
	ChannelSettings,
	Policy,
	SigningKey,
} from "./console-api.ts";

// hasChannel reports whether codes can go out to a phone or an email:
// 必须绑定手机号 needs SMS, and code login needs its kind's channel.
export const hasChannel = (
	channels: Pick<ChannelSettings, "kind">[],
	kind: ChannelSettings["kind"],
) => channels.some((c) => c.kind === kind);

const isHTTPS = (u: string) => {
	try {
		const url = new URL(u);
		return url.protocol === "https:" && url.host !== "";
	} catch {
		return false;
	}
};

// termsSchema stops a terms save the backend would reject: a version
// needs both URLs, and every URL must be https. The English ones are
// optional: English login pages fall back to the Chinese.
export const termsSchema = z
	.object({
		termsUrl: z.string().trim(),
		privacyUrl: z.string().trim(),
		termsUrlEn: z.string().trim(),
		privacyUrlEn: z.string().trim(),
		termsVersion: z.string().trim().max(64, "协议版本不能超过 64 个字符。"),
	})
	.superRefine((t, ctx) => {
		for (const k of [
			"termsUrl",
			"privacyUrl",
			"termsUrlEn",
			"privacyUrlEn",
		] as const) {
			if (t[k] && !isHTTPS(t[k])) {
				ctx.addIssue({
					code: "custom",
					path: [k],
					message: "请输入以 https 开头的地址。",
				});
			} else if (!t[k] && t.termsVersion && !k.endsWith("En")) {
				ctx.addIssue({
					code: "custom",
					path: [k],
					message: "设置协议版本时需填写此地址。",
				});
			}
		}
	});

// numberSchema checks a numeric policy setting typed into a text box.
export const numberSchema = (min: number) =>
	z.object({
		value: z
			.string()
			.trim()
			.refine(
				(v) => /^\d+$/.test(v) && +v >= min,
				`请输入不小于 ${min} 的整数。`,
			),
	});

// channelSchema checks a channel plugin's settings: every field is
// required unless optional or a secret already set (left empty keeps it).
export const channelSchema = (
	fields: readonly ChannelField[],
	secrets: Record<string, string>,
) =>
	z.object(
		Object.fromEntries(
			fields.map((f) => [
				f.key,
				z
					.string()
					.trim()
					.superRefine((v, ctx) => {
						const fail = (message: string) =>
							ctx.addIssue({ code: "custom", message });
						if (!v) {
							if (!f.optional && !(f.secret && secrets[f.key])) {
								fail(`请输入${f.label}。`);
							}
						} else if (f.type === "url" && !URL.canParse(v)) {
							fail("请输入有效的地址。");
						} else if (f.type === "number" && Number.isNaN(Number(v))) {
							fail("请输入数字。");
						}
					}),
			]),
		),
	);

// testSchema checks where a test code goes.
export const testSchema = (kind: ChannelSettings["kind"]) =>
	z.object({
		to:
			kind === "email"
				? z.email("请输入有效的邮箱。")
				: z
						.string()
						.trim()
						.regex(/^\+?\d{5,15}$/, "请输入有效的手机号，如 +8613800001111。"),
	});

// smsLocked: SMS stays on while 必须绑定手机号 needs it; stopping it would
// leave users without a phone unable to bind one and so to sign in.
export const smsLocked = (
	kind: ChannelSettings["kind"],
	requirePhone: boolean,
) => kind === "phone" && requirePhone;

// asksRequirePhone: turning 必须绑定手机号 on makes users without a phone
// bind one before their next login goes through.
export const asksRequirePhone = (before: boolean, after: boolean) =>
	!before && after;

// asksTermsVersion: any new version, the first included, makes every user
// agree again; clearing it asks nothing of them.
export const asksTermsVersion = (before: string, after: string) =>
	after !== "" && after !== before;

// asksShorterRetention: the hourly cleanup deletes what falls outside the
// new period, for good.
export const asksShorterRetention = (before: number, after: number) =>
	after < before;

// passwordLocksOut: with password login off, users who only have a username
// can't sign in, and the account center can't set one.
export const passwordLocksOut = (mode: Policy["passwordLogin"]) =>
	mode === "off";

// sendsNothing: a daily limit of 0 stops every code, login and binding alike.
export const sendsNothing = (dailySendLimit: number) => dailySendLimit === 0;

// rotatedRecently: rotating again this soon retires the key before last,
// and tokens it signed stop working at once.
// consoles.md marks 1 day as a placeholder (占位值).
export const rotatedRecently = (lastRotatedAt: string, now = new Date()) =>
	now.getTime() - new Date(lastRotatedAt).getTime() < 86_400_000;

// lastRotation is when the current key took over, or "" if it is the
// first: a rotation always leaves the previous key behind.
export const lastRotation = (
	keys: Pick<SigningKey, "createdAt" | "current">[],
) => (keys.length > 1 ? (keys.find((k) => k.current)?.createdAt ?? "") : "");

// providerSchema checks a Provider's form: its ID only when adding (it is
// in the callback URL and never changes), its name, and its type's fields
// as a channel's.
export const providerSchema = (
	fields: readonly ChannelField[],
	secrets: Record<string, string>,
	adding: boolean,
) =>
	z.object({
		id: adding
			? z
					.string()
					.trim()
					.regex(
						/^[a-z0-9][a-z0-9-]{0,31}$/,
						"Provider ID 只能用小写字母、数字和 -，以字母或数字开头，最多 32 位。",
					)
			: z.string(),
		name: z
			.string()
			.trim()
			.min(1, "请输入名称。")
			.max(64, "名称不能超过 64 个字符。"),
		config: channelSchema(fields, secrets),
	});

// disableImpact is what disabling a Provider does to the Users bound to it.
export const disableImpact = (p: { bound: number; onlyLoginPath: number }) =>
	p.bound
		? `已有 ${p.bound} 个用户绑定，其中 ${p.onlyLoginPath} 个没有其他登录方式，停用后将无法登录。`
		: "暂无用户绑定。";
