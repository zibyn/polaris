// Account center form rules, copies of the Account API's simple ones
// (internal/identity). Pure TypeScript: tested with node --test.
import { z } from "zod";

const phone = z
	.string()
	.refine(
		(v) => /^(?:\+?86)?1[3-9]\d{9}$/.test(v.replace(/[\s-]/g, "")),
		"请输入 +86 手机号",
	);

const email = z
	.string()
	.trim()
	.max(254, "请输入邮箱")
	.regex(/^[^@\s]+@[^@\s]+\.[^@\s]+$/, "请输入邮箱");

const code = z
	.string()
	.trim()
	.regex(/^\d{6}$/, "请输入 6 位验证码");

// bindSchema checks a new phone number or email, and its code once sent.
export const bindSchema = (kind: "phone" | "email", sent: boolean) =>
	z.object({
		value: kind === "phone" ? phone : email,
		code: sent ? code : z.string(),
	});

export const passwordSchema = z.object({
	password: z.string().refine((v) => [...v].length >= 8, "密码至少 8 位"),
});

const totp = z
	.string()
	.trim()
	.regex(/^\d{6}$/, "请输入验证器中的 6 位数字");

// A recovery code, xxxx-xxxx, in any case with or without the dash.
const recoveryCode = z
	.string()
	.refine(
		(v) => /^[a-z2-7]{8}$/i.test(v.replace(/[\s-]/g, "")),
		"请输入恢复码,形如 xxxx-xxxx",
	);

// reauthMethods is, per way of reauthenticating, how its secret is checked,
// sent to POST /reauth and typed in.
const codeMethod = (kind: "phone" | "email") =>
	({
		schema: code,
		body: (secret: string) => ({ kind, code: secret }),
		label: "验证码",
		input: {
			inputMode: "numeric",
			autoComplete: "one-time-code",
			placeholder: "6 位验证码",
		},
	}) as const;
export const reauthMethods = {
	phone: codeMethod("phone"),
	email: codeMethod("email"),
	password: {
		schema: z.string().min(1, "请输入密码"),
		body: (secret: string) => ({ password: secret }),
		label: "密码",
		input: { type: "password", autoComplete: "current-password" },
	},
	totp: {
		schema: totp,
		body: (secret: string) => ({ totp: secret.trim() }),
		label: "验证器中的验证码",
		input: {
			inputMode: "numeric",
			autoComplete: "one-time-code",
			placeholder: "6 位数字",
		},
	},
	recovery: {
		schema: recoveryCode,
		body: (secret: string) => ({ recoveryCode: secret }),
		label: "恢复码",
		input: { autoComplete: "off", placeholder: "xxxx-xxxx" },
	},
} as const;

export type ReauthMethod = keyof typeof reauthMethods;

// reauthChoices is the ways of reauthenticating to offer a User: a Passkey
// when the instance offers Passkey login, they have one and the browser can
// run the ceremony, then — with 两步验证 on — their TOTP, or otherwise the
// codes to their Identifiers and their password. A Passkey itself passes
// 两步验证.
export const reauthChoices = (
	me: {
		identifiers: { kind: string }[];
		hasPassword: boolean;
		passwordAllowed: boolean;
		passkeyLogin: boolean;
		twoFactor: { enabled: boolean };
	},
	hasPasskey: boolean,
	supported: boolean,
): ReauthChoice[] => {
	const passkey: ReauthChoice[] =
		hasPasskey && me.passkeyLogin && supported ? ["passkey"] : [];
	if (me.twoFactor.enabled) return [...passkey, "totp"];
	const codes = me.identifiers
		.map((i) => i.kind)
		.filter((k): k is "phone" | "email" => k !== "username");
	const password: ReauthChoice[] =
		me.hasPassword && me.passwordAllowed ? ["password"] : [];
	return [...passkey, ...codes, ...password];
};

// ReauthChoice is a way of reauthenticating: one reauthMethods knows the
// secret of, or the Passkey ceremony.
export type ReauthChoice = ReauthMethod | "passkey";

// reauthSchema checks the secret of method; a code only once it is sent.
export const reauthSchema = (method: ReauthMethod, sent: boolean) =>
	z.object({
		secret:
			(method === "phone" || method === "email") && !sent
				? z.string()
				: reauthMethods[method].schema,
	});

// totpSchema checks a code from the authenticator, confirming the TOTP.
export const totpSchema = z.object({ code: totp });

// nicknameSchema checks a nickname as the server does: trimmed, at most 32
// characters, no control characters; empty clears it.
export const nicknameSchema = z.object({
	nickname: z
		.string()
		.trim()
		.refine((v) => [...v].length <= 32, "昵称最多 32 个字符")
		.refine(
			// biome-ignore lint/suspicious/noControlCharactersInRegex: control characters are what it refuses
			(v) => !/[\u0000-\u001f\u007f-\u009f]/.test(v),
			"昵称不能含控制字符",
		),
});

// avatarProblem is why a picked file cannot be an avatar, or undefined; the
// server sniffs the content, this only spares an upload doomed by its type
// or size.
export function avatarProblem(file: {
	size: number;
	type: string;
}): string | undefined {
	if (!["image/jpeg", "image/png", "image/webp"].includes(file.type)) {
		return "头像须为 JPEG、PNG 或 WebP 图片";
	}
	if (file.size > 5 << 20) return "头像不能超过 5 MB";
}

// passkeyNameSchema checks a Passkey's new name.
export const passkeyNameSchema = z.object({
	name: z
		.string()
		.trim()
		.refine(
			(v) => [...v].length >= 1 && [...v].length <= 64,
			"名称须为 1–64 个字符",
		),
});

// providerReturn is what to tell the User on coming back from a Provider
// the account center sent them to (internal/login/provider.go), or null.
export const providerReturn = (
	search: string,
	name: (id: string) => string,
): { success: string } | { error: string } | null => {
	const q = new URLSearchParams(search);
	const error = q.get("error");
	const bound = q.get("bound");
	if (error !== null) return { error };
	if (bound !== null) return { success: `已绑定 ${name(bound)}` };
	if (q.has("reauthenticated")) return { success: "已验证身份,请继续操作" };
	return null;
};

// recoveryCodesText is the file the recovery codes download as.
export const recoveryCodesText = (host: string, codes: string[]) =>
	`${host} 两步验证恢复码\n每个只能用一次。\n\n${codes.join("\n")}\n`;

export const deleteSchema = z.object({
	confirm: z.string().refine((v) => v.trim() === "注销", "请输入「注销」确认"),
});
