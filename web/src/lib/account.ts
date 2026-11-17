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
	.max(254, "请输入有效的邮箱")
	.regex(/^[^@\s]+@[^@\s]+\.[^@\s]+$/, "请输入有效的邮箱");

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
		"请输入恢复码，格式为 xxxx-xxxx",
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
// run the ceremony, then — with 两步验证 on — their TOTP, the codes to the
// phone number and email they added as factors, and a recovery code when
// they have no TOTP; or otherwise the codes to their Identifiers and their
// password. A Passkey itself passes 两步验证.
export const reauthChoices = (
	me: {
		identifiers: { kind: string }[];
		hasPassword: boolean;
		passwordAllowed: boolean;
		passkeyLogin: boolean;
		twoFactor: {
			enabled: boolean;
			totp: boolean;
			sms: boolean;
			email: boolean;
		};
	},
	hasPasskey: boolean,
	supported: boolean,
): ReauthChoice[] => {
	const passkey: ReauthChoice[] =
		hasPasskey && me.passkeyLogin && supported ? ["passkey"] : [];
	const codes = me.identifiers
		.map((i) => i.kind)
		.filter((k): k is "phone" | "email" => k !== "username");
	const tf = me.twoFactor;
	if (tf.enabled)
		return [
			...passkey,
			...(tf.totp ? ["totp" as const] : []),
			...codes.filter((k) => (k === "phone" ? tf.sms : tf.email)),
			...(tf.totp ? [] : ["recovery" as const]),
		];
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
	if (q.has("reauthenticated")) return { success: "已验证身份，请继续操作" };
	return null;
};

type TwoFactorState = {
	passkeyLogin: boolean;
	twoFactor: { enabled: boolean; totp: boolean; sms: boolean; email: boolean };
};

// otherFactors names the factors besides the TOTP that 两步验证 can be on
// by (twofactor.Factors.Usable): a Passkey while the instance offers Passkey
// login, the phone number and email added.
export const otherFactors = (me: TwoFactorState, passkeys: number) =>
	[
		passkeys > 0 && me.passkeyLogin && "Passkey",
		me.twoFactor.sms && "短信",
		me.twoFactor.email && "邮箱",
	].filter((f): f is string => !!f);

// TwoFactorAction is a button of the account center's 两步验证 row.
export type TwoFactorAction =
	| "enable"
	| "enable-totp"
	| "add-totp"
	| "remove-totp"
	| "regenerate"
	| "disable";

// twoFactorActions is what the 两步验证 row offers. Off: turning it on by
// the other factors (otherFactors), while there are any, or with a TOTP. On:
// adding a TOTP, or removing it while another factor is left to pass
// 两步验证 with; new recovery codes; turning it off.
export const twoFactorActions = (
	me: TwoFactorState,
	passkeys: number,
): TwoFactorAction[] => {
	const other = otherFactors(me, passkeys).length > 0;
	if (!me.twoFactor.enabled)
		return other ? ["enable", "enable-totp"] : ["enable-totp"];
	const totp: TwoFactorAction[] = !me.twoFactor.totp
		? ["add-totp"]
		: other
			? ["remove-totp"]
			: [];
	return [...totp, "regenerate", "disable"];
};

// lastCodeFactorNote is why the User's phone number or email can't be
// removed as a factor, or undefined: 两步验证 is on and it is all it has.
// Same words as the server's 409 (twofactor.ErrLastFactor).
export const lastCodeFactorNote = (
	me: TwoFactorState,
	passkeys: number,
): string | undefined => {
	if (
		me.twoFactor.enabled &&
		!me.twoFactor.totp &&
		otherFactors(me, passkeys).length === 1
	)
		return "这是你唯一的两步验证方式,请先添加其他方式或关闭两步验证";
};

// lastPasskeyNote is why the User's Passkey can't be deleted, or undefined:
// it is their last, and 两步验证 is on with no TOTP, phone number or email.
// Same words as the server's 409 (passkey.ErrLastPasskey).
export const lastPasskeyNote = (
	me: TwoFactorState,
	passkeys: number,
): string | undefined => {
	if (
		me.twoFactor.enabled &&
		!me.twoFactor.totp &&
		!me.twoFactor.sms &&
		!me.twoFactor.email &&
		passkeys === 1
	)
		return "这是你唯一的两步验证方式，请先添加验证器或关闭两步验证";
};

// recoveryCodesText is the file the recovery codes download as.
export const recoveryCodesText = (host: string, codes: string[]) =>
	`${host} 两步验证恢复码\n每个只能用一次。\n\n${codes.join("\n")}\n`;

export const deleteSchema = z.object({
	confirm: z.string().refine((v) => v.trim() === "注销", "请输入「注销」确认"),
});
