// A 最近登录 row in words (docs/spec/consoles.md「账号中心」). The server
// normalizes method; this only translates it.
import type { Login } from "./account-api.ts";
import { deviceLabel } from "./device.ts";

const signedInWith: Record<string, string> = {
	password: "密码",
	code: "验证码",
	passkey: "Passkey",
	provider: "外部登录",
};

const failedAt: Record<string, string> = {
	password: "密码错误",
	code: "验证码错误",
	totp: "两步验证码错误",
	recovery_code: "恢复码错误",
};

const time = (s: string) =>
	new Date(s).toLocaleTimeString("zh-CN", {
		hour: "2-digit",
		minute: "2-digit",
		hour12: false,
	});

export function loginLine(l: Login): {
	result: string;
	what: string;
	device: string;
} {
	const device = [deviceLabel(l.userAgent), l.ip].filter(Boolean).join(" · ");
	const method = l.method ?? "";
	switch (l.result) {
		case "succeeded":
			return {
				result: "成功",
				what:
					(signedInWith[method] ?? method) + (l.twoFactor ? " + 两步验证" : ""),
				device,
			};
		case "failed":
			return { result: "失败", what: failedAt[method] ?? method, device };
		case "locked":
			return {
				result: "已锁定",
				what: l.lockedUntil
					? `多次失败后已锁定到 ${time(l.lockedUntil)}`
					: "多次失败后已锁定",
				device,
			};
	}
}
