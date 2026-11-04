// The console's top-level groups and the Permission each needs, per
// docs/spec/consoles.md「导航」. Pure TypeScript: tested with node --test.
import { APIError } from "./oidc.ts";

const groups = [
	{ label: "概览", permission: "users:read", to: "/console" },
	{ label: "用户", permission: "users:read", to: "/console/users" },
	{ label: "应用", permission: "applications:read", to: "/console/apps" },
	{ label: "API 资源", permission: "applications:read", to: "/console/apis" },
	{ label: "认证源", permission: "config:read", to: "/console/providers" },
	{ label: "审计", permission: "audit:read", to: "/console/audit" },
	{ label: "设置", permission: "config:read", to: "/console/settings" },
] as const;

// needsTwoFactor: 管理员必须启用两步验证 is on and the admin hasn't, so the
// console gives way to a page sending them to the account center.
export const needsTwoFactor = (e: unknown) =>
	e instanceof APIError && e.code === "two_factor_required";

// navGroups lists the groups an admin holding permissions can see.
export const navGroups = (permissions: readonly string[]) =>
	groups.filter((g) => permissions.includes(g.permission));
