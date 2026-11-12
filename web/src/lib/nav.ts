// The console's sidebar: 概览 and titled sections of items, each with the
// Permission it needs, per docs/spec/consoles.md「导航」. Pure TypeScript:
// tested with node --test.
import { APIError } from "./oidc.ts";

const sections = [
	{
		title: "",
		items: [{ label: "概览", permission: "users:read", to: "/console" }],
	},
	{
		title: "身份认证",
		items: [
			{ label: "应用", permission: "applications:read", to: "/console/apps" },
			{
				label: "API 资源",
				permission: "applications:read",
				to: "/console/apis",
			},
			{ label: "登录体验", permission: "config:read", to: "/console/sign-in" },
			{ label: "认证源", permission: "config:read", to: "/console/providers" },
			{
				label: "验证码通道",
				permission: "config:read",
				to: "/console/channels",
			},
		],
	},
	{
		title: "用户管理",
		items: [
			{ label: "用户", permission: "users:read", to: "/console/users" },
			{
				label: "角色与权限",
				permission: "applications:read",
				to: "/console/roles",
			},
		],
	},
	{
		title: "系统",
		items: [
			{ label: "审计日志", permission: "audit:read", to: "/console/audit" },
			{ label: "安全", permission: "config:read", to: "/console/security" },
		],
	},
] as const;

export type NavItem = (typeof sections)[number]["items"][number];

// needsTwoFactor: 管理员必须启用两步验证 is on and the admin hasn't, so the
// console gives way to a page sending them to the account center.
export const needsTwoFactor = (e: unknown) =>
	e instanceof APIError && e.code === "two_factor_required";

// navSections lists what an admin holding permissions can see; a section
// with nothing left is dropped, title and all.
export const navSections = (permissions: readonly string[]) =>
	sections
		.map((s) => ({
			title: s.title,
			items: s.items.filter((i): i is NavItem =>
				permissions.includes(i.permission),
			),
		}))
		.filter((s) => s.items.length > 0);

// navItems is every item an admin may open, in sidebar order.
export const navItems = (permissions: readonly string[]) =>
	navSections(permissions).flatMap((s) => s.items);
