// API resource list and detail logic. Pure TypeScript: tested with node --test.
import { z } from "zod";
import type { Application, RoleDef } from "./console-api.ts";

// defaultFor lists the Applications using an API resource as their
// default. While any do, it can't be deleted; while none do, its roles
// reach no token.
export const defaultFor = <A extends Pick<Application, "defaultApi">>(
	apps: A[],
	identifier: string,
) => apps.filter((a) => a.defaultApi === identifier);

// rolesWith counts the roles that lose a permission when it is deleted.
export const rolesWith = (
	roles: Pick<RoleDef, "permissions">[],
	permission: string,
) => roles.filter((r) => r.permissions.includes(permission)).length;

// The rules below mirror the Management API's (internal/management/rbac.go).
const name = z
	.string()
	.trim()
	.min(1, "请输入名称。")
	.max(64, "名称不能超过 64 个字符。");

// apiSchema checks 添加 API 资源.
export const apiSchema = z.object({
	identifier: z
		.string()
		.trim()
		.min(1, "请输入 API 资源标识符。")
		.max(200, "API 资源标识符不能超过 200 个字符。")
		.regex(/^\S*$/, "API 资源标识符不能包含空格。"),
	name,
});

const key = z
	.string()
	.trim()
	.regex(
		/^[A-Za-z0-9][A-Za-z0-9:._-]{0,63}$/,
		"key 以字母或数字开头，只能包含字母、数字和 : . _ -，最多 64 个字符。",
	);

// permissionSchema checks 添加权限.
export const permissionSchema = z.object({ key, name });

// roleSchema checks a Role being defined or edited.
export const roleSchema = z.object({
	key,
	name,
	permissions: z.array(z.string()),
});
