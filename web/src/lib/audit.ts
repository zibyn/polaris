// Audit events as sentences (docs/spec/consoles.md「审计」). Pure
// TypeScript: tested with node --test.

import { z } from "zod";
import type { AuditEvent, Identifier } from "./console-api.ts";
import { kindName, query } from "./users.ts";

// Part is a piece of a sentence: plain text, or a User or Application
// that links to its page, or a raw ID in monospace when there is no name.
export type Ref = { text: string; user?: string; app?: string; mono?: boolean };
export type Part = string | Ref;

// Names are what IDs are shown as. apps is absent without
// applications:read; a missing entry means the object was deleted.
export type Names = {
	apps?: { clientId: string; name: string }[];
	apis?: {
		identifier: string;
		name: string;
		permissions: { key: string; name: string }[];
		roles: { key: string; name: string }[];
	}[];
};

// eventGroups names the events, grouped for the filter.
export const eventGroups: [string, [string, string][]][] = [
	[
		"用户",
		[
			["user.disabled", "禁用用户"],
			["user.enabled", "恢复用户"],
			["user.deleted", "删除用户"],
			["identifier.replaced", "更换登录标识"],
			["identifier.removed", "移除登录标识"],
			["password.changed", "设置密码"],
			["password.removed", "移除密码"],
			["mfa.enabled", "开启两步验证"],
			["mfa.disabled", "关闭两步验证"],
			["mfa.reset", "重置两步验证"],
			["recovery_codes.regenerated", "重新生成恢复码"],
			["recovery_code.used", "使用恢复码"],
			["session.ended", "下线会话"],
			["roles.assigned", "设置角色"],
			["external_identity.added", "绑定外部账号"],
			["external_identity.removed", "解绑外部账号"],
			["passkey.added", "添加 Passkey"],
			["passkey.removed", "删除 Passkey"],
			["passkey.renamed", "重命名 Passkey"],
		],
	],
	[
		"应用",
		[
			["application.created", "创建应用"],
			["application.updated", "修改应用"],
			["application.deleted", "删除应用"],
			["application.secret_regenerated", "重新生成 client secret"],
			["application.auth_method_changed", "切换客户端认证方式"],
			["application_roles.assigned", "设置角色"],
			["webhook.failed", "用户删除通知发送失败"],
		],
	],
	[
		"API 资源",
		[
			["api.saved", "保存 API 资源"],
			["api.deleted", "删除 API 资源"],
			["permission.saved", "保存权限"],
			["permission.deleted", "删除权限"],
			["role.saved", "保存角色"],
			["role.deleted", "删除角色"],
		],
	],
	[
		"登录与通道",
		[
			["settings.updated", "修改登录设置"],
			["channel.saved", "配置验证码通道"],
			["channel.deleted", "停用验证码通道"],
			["channel.tested", "发送测试验证码"],
			["send.daily_cap_reached", "验证码达到每日发送上限"],
			["provider.created", "添加认证源"],
			["provider.updated", "修改认证源"],
			["provider.enabled", "启用认证源"],
			["provider.disabled", "停用认证源"],
			["provider.deleted", "删除认证源"],
			["provider.unlink_failed", "外部账号吊销授权失败"],
		],
	],
	["设置", [["keys.rotated", "轮换令牌签名密钥"]]],
	[
		"安全",
		[
			["login.succeeded", "登录成功"],
			["login.failed", "登录失败"],
			["login.password_locked", "密码输错次数过多，暂时锁定"],
			["login.ip_locked", "同一 IP 登录失败过多，暂时锁定"],
			["refresh_token.reused", "疑似登录凭据被盗用，已下线会话"],
			["passkey.counter_regressed", "Passkey 计数器回退，拒绝登录"],
		],
	],
];

const names = new Map(eventGroups.flatMap(([, events]) => events));

// eventName names an event; one missing from the table keeps its own name
// so it can still be traced.
export const eventName = (event: string) =>
	names.get(event) ?? `其他操作（${event}）`;

const raw = (id: string): Ref => ({ text: id, mono: true });

// someone names a User by their primary Identifier, or by the start of
// their ID once they are deleted.
const someone = (sub: string, identifier?: string): Part[] =>
	identifier
		? ["用户 ", { text: identifier, user: sub }]
		: ["已删除的用户 ", raw(sub.slice(0, 8))];

// doneBy is the sub of whoever did it; undefined when the system did.
export const doneBy = (ev: AuditEvent) =>
	typeof ev.detail.by === "string" && ev.detail.by ? ev.detail.by : undefined;

// app names an Application by its client_id: its name, or the raw ID once
// it is deleted or applications:read is absent.
const app = (names: Names, clientId: string): Part => {
	const name = names.apps?.find((a) => a.clientId === clientId)?.name;
	return name ? { text: name, app: clientId } : raw(clientId);
};

// actor is who did it: a User, an M2M Application calling as itself, or the
// system. byType is absent on events older than it, which were Users.
export function actor(ev: AuditEvent, names: Names): Part[] {
	const by = doneBy(ev);
	if (!by) {
		return ["系统"];
	}
	if (ev.detail.byType === "application") {
		return [app(names, by)];
	}
	if (by === ev.sub) {
		return ["用户本人"];
	}
	return ev.byUser ? [{ text: ev.byUser, user: by }] : someone(by);
}

// amrName is how a login proved the User, by its first amr value.
const amrName: Record<string, string> = {
	pwd: "密码",
	sms: "验证码",
	otp: "验证码",
	hwk: " Passkey ",
	swk: " Passkey ",
	fed: "外部账号",
};

// failedName is what a login.failed got wrong, by its method.
const failedName: Record<string, string> = {
	password: "密码错误",
	code: "验证码错误",
	totp: "两步验证码错误",
	recovery_code: "恢复码错误",
};

// describe is the event as one sentence, with the doer left out (they
// have their own column). title holds what only belongs in a hover.
export function describe(
	ev: AuditEvent,
	names: Names,
): { parts: Part[]; title?: string } {
	const d = ev.detail;
	const str = (k: string) => (typeof d[k] === "string" ? (d[k] as string) : "");
	const user = someone(ev.sub ?? "", ev.user);
	const kind = kindName[str("kind") as Identifier["kind"]] ?? str("kind");
	const apiDef = names.apis?.find((a) => a.identifier === str("api"));
	const apiName: Part = apiDef?.name ?? raw(str("api"));
	const named = (list: { key: string; name: string }[] = [], key: string) =>
		list.find((x) => x.key === key)?.name ?? raw(key);
	// roleSentence is who's Roles on this API set to what: the list, or
	// 清空了 when empty. Shared by a User's and an Application's assignment.
	const roleSentence = (who: Part[], roles: string[]): Part[] =>
		roles.length === 0
			? ["清空了", ...who, " 在 ", apiName, " 上的角色"]
			: [
					"把",
					...who,
					" 在 ",
					apiName,
					" 上的角色设为 ",
					...roles.flatMap((r, i) => [
						...(i ? ["、"] : []),
						named(apiDef?.roles, r),
					]),
				];
	// inAPI is a Permission or Role of the event's API resource.
	const inAPI = (verb: string, what: "permissions" | "roles"): Part[] => [
		`${verb} `,
		apiName,
		what === "roles" ? " 的角色 " : " 的权限 ",
		named(apiDef?.[what], str("key")),
	];
	// whereFrom is a login's IP and User-Agent, for the hover.
	const whereFrom = () =>
		[str("ip") && `IP：${str("ip")}`, str("ua") && `UA：${str("ua")}`]
			.filter(Boolean)
			.join("\n") || undefined;
	switch (ev.event) {
		case "user.disabled":
			return { parts: ["禁用了", ...user] };
		case "user.enabled":
			return { parts: ["恢复了", ...user] };
		case "user.deleted":
			return {
				parts: ["删除了", ...user],
			};
		case "identifier.replaced":
			return { parts: ["更换了", ...user, ` 的${kind}`] };
		case "identifier.removed":
			return { parts: ["移除了", ...user, ` 的${kind}`] };
		case "password.changed":
			return { parts: ["设置了", ...user, " 的密码"] };
		case "password.removed":
			return { parts: ["移除了", ...user, " 的密码"] };
		case "mfa.enabled":
			return { parts: ["开启了", ...user, " 的两步验证"] };
		case "mfa.disabled":
			return { parts: ["关闭了", ...user, " 的两步验证"] };
		case "mfa.reset":
			return { parts: ["重置了", ...user, " 的两步验证"] };
		case "recovery_codes.regenerated":
			return { parts: ["重新生成了", ...user, " 的恢复码"] };
		case "recovery_code.used":
			return { parts: [...user, " 用了一个恢复码"] };
		case "session.ended":
			return { parts: ["下线了", ...user, " 的一个会话"] };
		case "roles.assigned": {
			const roles = Array.isArray(d.roles) ? (d.roles as string[]) : [];
			return { parts: roleSentence(user, roles) };
		}
		case "application.created":
			return { parts: ["创建了一个应用"] };
		case "application.updated":
			return { parts: ["修改了应用 ", app(names, str("clientId"))] };
		case "application.deleted":
			return { parts: ["删除了应用 ", app(names, str("clientId"))] };
		case "application.secret_regenerated":
			return {
				parts: [
					"重新生成了应用 ",
					app(names, str("clientId")),
					" 的 client secret",
				],
			};
		case "application.auth_method_changed":
			return {
				parts: [
					"切换了应用 ",
					app(names, str("clientId")),
					" 的客户端认证方式",
				],
			};
		case "application_roles.assigned": {
			const roles = Array.isArray(d.roles) ? (d.roles as string[]) : [];
			const target: Part[] = ["应用 ", app(names, str("clientId"))];
			return { parts: roleSentence(target, roles) };
		}
		case "webhook.failed":
			return {
				parts: [
					"没能把",
					...user,
					" 的删除通知发给应用 ",
					app(names, str("application")),
				],
				title: str("id") ? `投递 ID：${str("id")}` : undefined,
			};
		case "api.saved":
			return { parts: ["保存了 API 资源 ", apiName] };
		case "api.deleted":
			return { parts: ["删除了 API 资源 ", apiName] };
		case "permission.saved":
			return { parts: inAPI("保存了", "permissions") };
		case "permission.deleted":
			return { parts: inAPI("删除了", "permissions") };
		case "role.saved":
			return { parts: inAPI("保存了", "roles") };
		case "role.deleted":
			return { parts: inAPI("删除了", "roles") };
		case "settings.updated":
			return { parts: ["修改了登录设置"] };
		case "channel.saved":
			return { parts: [`配置了${kind}验证码通道`] };
		case "channel.deleted":
			return { parts: [`停用了${kind}验证码通道`] };
		case "channel.tested":
			return { parts: [`发送了一条${kind}测试验证码`] };
		case "send.daily_cap_reached":
			return {
				parts: [
					typeof d.limit === "number"
						? `验证码达到每日上限 ${d.limit} 条，今天不再发送`
						: "验证码达到每日发送上限，今天不再发送",
				],
			};
		case "external_identity.added":
			return {
				parts: ["给", ...user, " 绑定了外部账号 ", raw(str("provider"))],
			};
		case "external_identity.removed":
			return {
				parts: ["解绑了", ...user, " 的外部账号 ", raw(str("provider"))],
			};
		case "passkey.added":
			return { parts: ["给", ...user, " 添加了 Passkey ", str("name")] };
		case "passkey.removed":
			return { parts: ["删除了", ...user, " 的 Passkey ", str("name")] };
		case "passkey.renamed":
			return { parts: ["把", ...user, " 的 Passkey 重命名为 ", str("name")] };
		case "passkey.counter_regressed":
			return {
				parts: [
					"拒绝了",
					...user,
					" 的 Passkey ",
					str("name"),
					" 登录：计数器回退，疑似被克隆",
				],
				title: typeof d.count === "number" ? `计数器：${d.count}` : undefined,
			};
		case "provider.created":
			return { parts: ["添加了认证源 ", raw(str("id"))] };
		case "provider.updated":
			return { parts: ["修改了认证源 ", raw(str("id"))] };
		case "provider.enabled":
			return { parts: ["启用了认证源 ", raw(str("id"))] };
		case "provider.disabled":
			return { parts: ["停用了认证源 ", raw(str("id"))] };
		case "provider.deleted":
			return { parts: ["删除了认证源 ", raw(str("id"))] };
		case "provider.unlink_failed":
			return {
				parts: [
					"没能让认证源 ",
					raw(str("provider")),
					" 吊销",
					...user,
					" 的授权",
				],
				title: str("error") || undefined,
			};
		case "keys.rotated":
			return { parts: ["轮换了令牌签名密钥"] };
		case "login.succeeded": {
			const amr = Array.isArray(d.amr) ? (d.amr as string[]) : [];
			const how = amrName[amr[0]] ?? "";
			return {
				parts: [...user, ` 用${how}登录了 `, app(names, str("client_id"))],
				title: whereFrom(),
			};
		}
		case "login.failed":
			return {
				parts: [
					...user,
					" 登录 ",
					app(names, str("client_id")),
					` 失败：${failedName[str("method")] ?? str("method")}`,
				],
				title: whereFrom(),
			};
		case "login.password_locked": {
			const until = str("until")
				? new Date(str("until")).toLocaleTimeString("zh-CN", {
						hour: "2-digit",
						minute: "2-digit",
					})
				: "";
			return {
				parts: [
					...user,
					until
						? ` 密码输错次数过多，已锁定到 ${until}`
						: " 密码输错次数过多，暂时锁定",
				],
				title: whereFrom(),
			};
		}
		case "login.ip_locked":
			return { parts: [`IP ${str("ip")} 登录失败过多，暂时锁定`] };
		case "refresh_token.reused":
			return { parts: [...user, " 的登录凭据疑似被盗用，已下线会话"] };
		default:
			return { parts: [eventName(ev.event)] };
	}
}

// findUser turns the search box into the User to filter by, using the
// Users GET /users?q= found (it matches parts of values): one, or one
// whose Identifier or ID is exactly what was typed, is it; several are for
// picking; none means the box held a deleted User's ID (they can only be
// found that way).
export function findUser<
	U extends { sub: string; identifiers: { value: string }[] },
>(q: string, users: U[]): { sub: string } | { choices: U[] } {
	const typed = q.trim().toLowerCase();
	const exact = users.filter(
		(u) =>
			u.sub.toLowerCase() === typed ||
			u.identifiers.some((i) => i.value.toLowerCase() === typed),
	);
	const found = exact.length === 1 ? exact : users;
	if (found.length === 1) {
		return { sub: found[0].sub };
	}
	return found.length ? { choices: found } : { sub: q.trim().toUpperCase() };
}

// findSchema checks the user box; without users:read it can only be a
// user ID, 26 base32 characters.
export const findSchema = (canReadUsers: boolean) =>
	z.object({
		q: canReadUsers
			? query
			: query.regex(
					/^$|^[A-Z2-7]{26}$/i,
					"请填写 26 位用户 ID。没有读取用户的权限，只能按 ID 查找。",
				),
	});
