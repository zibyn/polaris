import assert from "node:assert/strict";
import { test } from "node:test";
import {
	actor,
	describe,
	eventGroups,
	eventName,
	findSchema,
	findUser,
	type Names,
	type Part,
} from "./audit.ts";
import type { AuditEvent } from "./console-api.ts";

// docs/spec/consoles.md「事件名与分组」
const spec: Record<string, [string, string][]> = {
	用户: [
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
	应用: [
		["create-application", "创建应用"],
		["update-application", "修改应用"],
		["delete-application", "删除应用"],
		["new-application-secret", "重新生成 client secret"],
		["application_roles.assigned", "设置角色"],
		["webhook.failed", "用户删除通知发送失败"],
	],
	"API 资源": [
		["put-api", "保存 API 资源"],
		["delete-api", "删除 API 资源"],
		["put-permission", "保存权限"],
		["delete-permission", "删除权限"],
		["put-role", "保存角色"],
		["delete-role", "删除角色"],
	],
	登录与通道: [
		["settings.updated", "修改登录设置"],
		["put-channel", "配置验证码通道"],
		["delete-channel", "停用验证码通道"],
		["test-channel", "发送测试验证码"],
		["send.daily_cap_reached", "验证码达到每日发送上限"],
		["create-provider", "添加认证源"],
		["update-provider", "修改认证源"],
		["enable-provider", "启用认证源"],
		["disable-provider", "停用认证源"],
		["delete-provider", "删除认证源"],
		["provider.unlink_failed", "外部账号吊销授权失败"],
	],
	设置: [["keys.rotated", "轮换令牌签名密钥"]],
	安全: [
		["login.succeeded", "登录成功"],
		["login.failed", "登录失败"],
		["login.password_locked", "密码输错次数过多，暂时锁定"],
		["login.ip_locked", "同一 IP 登录失败过多，暂时锁定"],
		["refresh_token.reused", "疑似登录凭据被盗用，已下线会话"],
		["passkey.counter_regressed", "Passkey 计数器回退，拒绝登录"],
	],
};

test("every event has its name, in its group, in the spec's order", () => {
	assert.deepEqual(
		eventGroups.map(([group, events]) => [group, events]),
		Object.entries(spec),
	);
	for (const events of Object.values(spec)) {
		for (const [event, name] of events) {
			assert.equal(eventName(event), name);
		}
	}
});

test("an event not in the table still names itself", () => {
	assert.equal(eventName("set-foo"), "其他操作（set-foo）");
});

const ev = (over: Partial<AuditEvent> = {}): AuditEvent => ({
	id: 1,
	at: "2026-10-07T00:00:00Z",
	event: "user.disabled",
	detail: {},
	...over,
});

test("who did it: an admin by their primary Identifier, linked", () => {
	assert.deepEqual(
		actor(
			ev({ sub: "ALICE", detail: { by: "ADMIN01X" }, byUser: "admin" }),
			names,
		),
		[{ text: "admin", user: "ADMIN01X" }],
	);
});

test("who did it: nobody is the system", () => {
	assert.deepEqual(actor(ev({ sub: "ALICE", user: "a@x.com" }), names), [
		"系统",
	]);
});

test("who did it: the User themselves", () => {
	assert.deepEqual(
		actor(
			ev({ sub: "ALICE", detail: { by: "ALICE" }, byUser: "a@x.com" }),
			names,
		),
		["用户本人"],
	);
});

test("who did it: a deleted admin by the start of their ID", () => {
	assert.deepEqual(actor(ev({ detail: { by: "GONE1234ABCDEFGH" } }), names), [
		"已删除的用户 ",
		{ text: "GONE1234", mono: true },
	]);
});

test("who did it: an M2M Application by its name, its client_id once gone", () => {
	const app = actor(
		ev({ detail: { by: "SHOP", byType: "application" } }),
		names,
	);
	assert.deepEqual(app, [{ text: "星选商城", app: "SHOP" }]);
	// Deleted, or without applications:read, its client_id shows as it is.
	assert.deepEqual(
		actor(ev({ detail: { by: "GONE", byType: "application" } }), names),
		[{ text: "GONE", mono: true }],
	);
	assert.deepEqual(
		actor(ev({ detail: { by: "SHOP", byType: "application" } }), {
			...names,
			apps: undefined,
		}),
		[{ text: "SHOP", mono: true }],
	);
});

const names: Names = {
	apps: [{ clientId: "SHOP", name: "星选商城" }],
	apis: [
		{
			identifier: "https://api.shop",
			name: "订单 API",
			permissions: [{ key: "orders:read", name: "读订单" }],
			roles: [
				{ key: "editor", name: "编辑" },
				{ key: "viewer", name: "只读" },
			],
		},
	],
};
const alice = { sub: "ALICE", user: "a@x.com" };
const api = "https://api.shop";
const say = (parts: Part[]) =>
	parts.map((p) => (typeof p === "string" ? p : p.text)).join("");

test("every event reads as a sentence", () => {
	const cases: [Partial<AuditEvent>, string][] = [
		[{ event: "user.disabled", ...alice }, "禁用了用户 a@x.com"],
		[{ event: "user.enabled", ...alice }, "恢复了用户 a@x.com"],
		[
			{ event: "user.deleted", sub: "ALICE123XYZ" },
			"删除了已删除的用户 ALICE123",
		],
		[
			{ event: "identifier.replaced", ...alice, detail: { kind: "phone" } },
			"更换了用户 a@x.com 的手机号",
		],
		[
			{ event: "identifier.removed", ...alice, detail: { kind: "email" } },
			"移除了用户 a@x.com 的邮箱",
		],
		[{ event: "password.changed", ...alice }, "设置了用户 a@x.com 的密码"],
		[{ event: "password.removed", ...alice }, "移除了用户 a@x.com 的密码"],
		[{ event: "mfa.enabled", ...alice }, "开启了用户 a@x.com 的两步验证"],
		[{ event: "mfa.disabled", ...alice }, "关闭了用户 a@x.com 的两步验证"],
		[{ event: "mfa.reset", ...alice }, "重置了用户 a@x.com 的两步验证"],
		[
			{ event: "recovery_codes.regenerated", ...alice },
			"重新生成了用户 a@x.com 的恢复码",
		],
		[{ event: "recovery_code.used", ...alice }, "用户 a@x.com 用了一个恢复码"],
		[
			{ event: "session.ended", ...alice, detail: { session: "S1" } },
			"下线了用户 a@x.com 的一个会话",
		],
		[
			{
				event: "roles.assigned",
				...alice,
				detail: { api, roles: ["editor", "viewer"] },
			},
			"把用户 a@x.com 在 订单 API 上的角色设为 编辑、只读",
		],
		[
			{ event: "roles.assigned", ...alice, detail: { api, roles: [] } },
			"清空了用户 a@x.com 在 订单 API 上的角色",
		],
		[{ event: "create-application" }, "创建了一个应用"],
		[
			{ event: "update-application", detail: { clientId: "SHOP" } },
			"修改了应用 星选商城",
		],
		[
			{ event: "delete-application", detail: { clientId: "SHOP" } },
			"删除了应用 星选商城",
		],
		[
			{ event: "new-application-secret", detail: { clientId: "SHOP" } },
			"重新生成了应用 星选商城 的 client secret",
		],
		[
			{
				event: "application_roles.assigned",
				detail: { clientId: "SHOP", api, roles: ["editor", "viewer"] },
			},
			"把应用 星选商城 在 订单 API 上的角色设为 编辑、只读",
		],
		[
			{
				event: "application_roles.assigned",
				detail: { clientId: "SHOP", api, roles: [] },
			},
			"清空了应用 星选商城 在 订单 API 上的角色",
		],
		[
			{
				event: "webhook.failed",
				sub: "ALICE123XYZ",
				detail: { application: "SHOP", id: "D1" },
			},
			"没能把已删除的用户 ALICE123 的删除通知发给应用 星选商城",
		],
		[{ event: "put-api", detail: { api } }, "保存了 API 资源 订单 API"],
		[{ event: "delete-api", detail: { api } }, "删除了 API 资源 订单 API"],
		[
			{ event: "put-permission", detail: { api, key: "orders:read" } },
			"保存了 订单 API 的权限 读订单",
		],
		[
			{ event: "delete-permission", detail: { api, key: "orders:read" } },
			"删除了 订单 API 的权限 读订单",
		],
		[
			{ event: "put-role", detail: { api, key: "editor" } },
			"保存了 订单 API 的角色 编辑",
		],
		[
			{ event: "delete-role", detail: { api, key: "editor" } },
			"删除了 订单 API 的角色 编辑",
		],
		[{ event: "settings.updated" }, "修改了登录设置"],
		[
			{ event: "put-channel", detail: { kind: "phone" } },
			"配置了手机号验证码通道",
		],
		[
			{ event: "delete-channel", detail: { kind: "email" } },
			"停用了邮箱验证码通道",
		],
		[
			{ event: "test-channel", detail: { kind: "phone" } },
			"发送了一条手机号测试验证码",
		],
		[
			{ event: "send.daily_cap_reached", detail: { limit: 1000 } },
			"验证码达到每日上限 1000 条，今天不再发送",
		],
		[{ event: "keys.rotated" }, "轮换了令牌签名密钥"],
		[
			{
				event: "external_identity.added",
				...alice,
				detail: { provider: "google" },
			},
			"给用户 a@x.com 绑定了外部账号 google",
		],
		[
			{
				event: "external_identity.removed",
				...alice,
				detail: { provider: "google" },
			},
			"解绑了用户 a@x.com 的外部账号 google",
		],
		[
			{
				event: "passkey.added",
				...alice,
				detail: { by: "ALICE", name: "工作电脑" },
			},
			"给用户 a@x.com 添加了 Passkey 工作电脑",
		],
		[
			{
				event: "passkey.removed",
				...alice,
				detail: { by: "ADMIN01X", name: "工作电脑" },
			},
			"删除了用户 a@x.com 的 Passkey 工作电脑",
		],
		[
			{
				event: "passkey.renamed",
				...alice,
				detail: { by: "ALICE", name: "新电脑" },
			},
			"把用户 a@x.com 的 Passkey 重命名为 新电脑",
		],
		[
			{
				event: "passkey.counter_regressed",
				...alice,
				detail: { name: "工作电脑", count: 7 },
			},
			"拒绝了用户 a@x.com 的 Passkey 工作电脑 登录：计数器回退，疑似被克隆",
		],
		[
			{ event: "create-provider", detail: { id: "google" } },
			"添加了认证源 google",
		],
		[
			{ event: "update-provider", detail: { id: "google" } },
			"修改了认证源 google",
		],
		[
			{ event: "enable-provider", detail: { id: "google" } },
			"启用了认证源 google",
		],
		[
			{ event: "disable-provider", detail: { id: "google" } },
			"停用了认证源 google",
		],
		[
			{ event: "delete-provider", detail: { id: "google" } },
			"删除了认证源 google",
		],
		[
			{
				event: "provider.unlink_failed",
				...alice,
				detail: { provider: "apple", error: "timeout" },
			},
			"没能让认证源 apple 吊销用户 a@x.com 的授权",
		],
		[
			{
				event: "login.succeeded",
				...alice,
				detail: {
					client_id: "SHOP",
					amr: ["sms", "otp", "mfa"],
					ip: "203.0.113.7",
				},
			},
			"用户 a@x.com 用验证码登录了 星选商城",
		],
		[
			{
				event: "login.succeeded",
				...alice,
				detail: { client_id: "SHOP", amr: ["pwd"] },
			},
			"用户 a@x.com 用密码登录了 星选商城",
		],
		[
			{
				event: "login.succeeded",
				...alice,
				detail: { client_id: "SHOP", amr: ["swk", "mfa"] },
			},
			"用户 a@x.com 用 Passkey 登录了 星选商城",
		],
		[
			{
				event: "login.succeeded",
				...alice,
				detail: { client_id: "SHOP", amr: ["fed"] },
			},
			"用户 a@x.com 用外部账号登录了 星选商城",
		],
		[
			{
				event: "login.failed",
				...alice,
				detail: { client_id: "SHOP", method: "password" },
			},
			"用户 a@x.com 登录 星选商城 失败：密码错误",
		],
		[
			{
				event: "login.failed",
				...alice,
				detail: { client_id: "SHOP", method: "code" },
			},
			"用户 a@x.com 登录 星选商城 失败：验证码错误",
		],
		[
			{
				event: "login.failed",
				...alice,
				detail: { client_id: "SHOP", method: "totp" },
			},
			"用户 a@x.com 登录 星选商城 失败：两步验证码错误",
		],
		[
			{
				event: "login.failed",
				...alice,
				detail: { client_id: "SHOP", method: "recovery_code" },
			},
			"用户 a@x.com 登录 星选商城 失败：恢复码错误",
		],
		[
			{ event: "login.password_locked", ...alice },
			"用户 a@x.com 密码输错次数过多，暂时锁定",
		],
		[
			{
				event: "login.password_locked",
				...alice,
				detail: {
					until: new Date(2026, 9, 7, 14, 30).toISOString(),
					client_id: "SHOP",
				},
			},
			"用户 a@x.com 密码输错次数过多，已锁定到 14:30",
		],
		[
			{ event: "login.ip_locked", detail: { ip: "203.0.113.7" } },
			"IP 203.0.113.7 登录失败过多，暂时锁定",
		],
		[
			{ event: "refresh_token.reused", ...alice, detail: { session: "S1" } },
			"用户 a@x.com 的登录凭据疑似被盗用，已下线会话",
		],
		[
			{ event: "set-foo", detail: { x: "1", by: "ADMIN" } },
			"其他操作（set-foo）",
		],
	];
	for (const [over, want] of cases) {
		assert.equal(say(describe(ev(over), names).parts), want, over.event);
	}
});

test("Users and Applications link to their pages", () => {
	const { parts } = describe(
		ev({ event: "webhook.failed", ...alice, detail: { application: "SHOP" } }),
		names,
	);
	assert.deepEqual(
		parts.filter((p) => typeof p !== "string"),
		[
			{ text: "a@x.com", user: "ALICE" },
			{ text: "星选商城", app: "SHOP" },
		],
	);
});

test("a login's IP and User-Agent go only in the hover", () => {
	const s = describe(
		ev({
			event: "login.failed",
			...alice,
			detail: {
				client_id: "SHOP",
				method: "code",
				ip: "203.0.113.7",
				ua: "Safari",
			},
		}),
		names,
	);
	assert.equal(s.title, "IP：203.0.113.7\nUA：Safari");
});

test("a delivery ID goes only in the hover", () => {
	const s = describe(
		ev({
			event: "webhook.failed",
			...alice,
			detail: { application: "SHOP", id: "D1" },
		}),
		names,
	);
	assert.equal(s.title, "投递 ID：D1");
	assert.doesNotMatch(say(s.parts), /D1/);
});

test("a deleted User shows the start of their ID in monospace", () => {
	const { parts } = describe(
		ev({ event: "user.disabled", sub: "GONE1234ABC" }),
		names,
	);
	assert.deepEqual(parts, [
		"禁用了",
		"已删除的用户 ",
		{ text: "GONE1234", mono: true },
	]);
});

test("without a name, IDs show as they are, in monospace", () => {
	const mono = (over: Partial<AuditEvent>, n = names) =>
		describe(ev(over), n).parts.filter((p) => typeof p !== "string");
	// a deleted Application
	assert.deepEqual(
		mono({ event: "delete-application", detail: { clientId: "GONE" } }),
		[{ text: "GONE", mono: true }],
	);
	// no applications:read
	assert.deepEqual(
		mono(
			{ event: "update-application", detail: { clientId: "SHOP" } },
			{ ...names, apps: undefined },
		),
		[{ text: "SHOP", mono: true }],
	);
	// a deleted API resource, Role and Permission
	assert.deepEqual(
		mono({ event: "put-role", detail: { api: "https://old", key: "x" } }),
		[
			{ text: "https://old", mono: true },
			{ text: "x", mono: true },
		],
	);
	assert.deepEqual(
		mono({ event: "delete-permission", detail: { api, key: "orders:write" } }),
		[{ text: "orders:write", mono: true }],
	);
	assert.deepEqual(
		mono({
			event: "roles.assigned",
			...alice,
			detail: { api, roles: ["editor", "gone"] },
		}),
		[
			{ text: "a@x.com", user: "ALICE" },
			{ text: "gone", mono: true },
		],
	);
});

const user = (sub: string, value: string) => ({
	sub,
	identifiers: [{ kind: "email" as const, value }],
});

test("a search matching one User filters by them", () => {
	assert.deepEqual(findUser("a@x.com", [user("ALICE", "a@x.com")]), {
		sub: "ALICE",
	});
});

test("a search matching several Users lets you pick", () => {
	const users = [user("ALICE", "a@x.com"), user("ANNA", "a@y.com")];
	assert.deepEqual(findUser("a@", users), { choices: users });
});

test("a search matching nobody is taken as a deleted User's ID", () => {
	assert.deepEqual(findUser(" gone1234abc ", []), { sub: "GONE1234ABC" });
});

test("an exact Identifier picks its User among partial matches", () => {
	const users = [user("ALICE", "a@x.com"), user("AARON", "aa@x.com")];
	assert.deepEqual(findUser("A@x.com", users), { sub: "ALICE" });
});

test("without API resources to read, their IDs show as they are", () => {
	const { parts } = describe(
		ev({ event: "put-permission", detail: { api, key: "orders:read" } }),
		{ apps: undefined, apis: undefined },
	);
	assert.deepEqual(
		parts.filter((p) => typeof p !== "string"),
		[
			{ text: api, mono: true },
			{ text: "orders:read", mono: true },
		],
	);
});

test("a daily cap without its number still reads", () => {
	assert.equal(
		say(describe(ev({ event: "send.daily_cap_reached" }), names).parts),
		"验证码达到每日发送上限，今天不再发送",
	);
});

test("without users:read the user box only takes a user ID", () => {
	const id = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	assert.equal(findSchema(false).safeParse({ q: "" }).success, true);
	assert.equal(
		findSchema(false).safeParse({ q: ` ${id.toLowerCase()} ` }).success,
		true,
	);
	assert.equal(
		findSchema(false).safeParse({ q: "alice@example.com" }).error?.issues[0]
			.message,
		"请填写 26 位用户 ID。没有读取用户的权限，只能按 ID 查找。",
	);
	assert.equal(
		findSchema(true).safeParse({ q: "alice@example.com" }).success,
		true,
	);
	assert.equal(
		findSchema(true).safeParse({ q: "a".repeat(101) }).error?.issues[0].message,
		"最多输入 100 个字。",
	);
});
