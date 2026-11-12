import assert from "node:assert/strict";
import { test } from "node:test";
import {
	apiSchema,
	defaultFor,
	granted,
	matching,
	permissionSchema,
	roleSchema,
	rolesWith,
	toggled,
} from "./apis.ts";

const orders = "api://orders";
const shop = { clientId: "shop", defaultApi: orders };
const blog = { clientId: "blog", defaultApi: "" };

test("an API resource used as a default lists those Applications", () => {
	// Deleting it is blocked and its roles reach tokens.
	assert.deepEqual(defaultFor([shop, blog], orders), [shop]);
});

test("an API resource no Application defaults to lists none", () => {
	// Deleting it is allowed and its roles reach no token.
	assert.deepEqual(defaultFor([blog], orders), []);
});

test("deleting a permission counts the roles that hold it", () => {
	const roles = [
		{ permissions: ["orders:read", "orders:export"] },
		{ permissions: ["orders:read"] },
	];
	assert.equal(rolesWith(roles, "orders:read"), 2);
	assert.equal(rolesWith(roles, "orders:export"), 1);
	assert.equal(rolesWith(roles, "orders:delete"), 0);
});

// fieldErrors is what a form shows under each field.
const fieldErrors = (r: {
	error?: { issues: { path: PropertyKey[]; message: string }[] };
}) =>
	Object.fromEntries(
		(r.error?.issues ?? []).map((i) => [i.path.join("."), i.message]),
	);

test("adding an API resource needs an identifier without spaces and a name", () => {
	assert.deepEqual(
		fieldErrors(apiSchema.safeParse({ identifier: "", name: "" })),
		{
			identifier: "请输入 API 资源标识符。",
			name: "请输入名称。",
		},
	);
	assert.deepEqual(
		fieldErrors(
			apiSchema.safeParse({ identifier: "orders api", name: "订单 API" }),
		),
		{ identifier: "API 资源标识符不能包含空格。" },
	);
	assert.equal(
		apiSchema.safeParse({ identifier: orders, name: "订单 API" }).success,
		true,
	);
});

test("a permission key is letters, digits and : . _ -, up to 64", () => {
	assert.equal(
		permissionSchema.safeParse({ key: "orders:export", name: "导出订单" })
			.success,
		true,
	);
	for (const key of ["", ":orders", "orders export", "订单", "a".repeat(65)]) {
		assert.deepEqual(
			fieldErrors(permissionSchema.safeParse({ key, name: "导出订单" })),
			{
				key: "key 以字母或数字开头，只能包含字母、数字和 : . _ -，最多 64 个字符。",
			},
		);
	}
	assert.deepEqual(
		fieldErrors(
			permissionSchema.safeParse({
				key: "orders:export",
				name: "x".repeat(65),
			}),
		),
		{ name: "名称不能超过 64 个字符。" },
	);
});

test("a role needs a key and a name; permissions may be empty", () => {
	assert.equal(
		roleSchema.safeParse({ key: "editor", name: "编辑", permissions: [] })
			.success,
		true,
	);
	assert.deepEqual(
		fieldErrors(
			roleSchema.safeParse({ key: "editor", name: " ", permissions: [] }),
		),
		{ name: "请输入名称。" },
	);
});

test("the Permission picker matches key or name, ignoring case", () => {
	const ps = [
		{ key: "orders:read", name: "查看订单" },
		{ key: "orders:export", name: "导出订单" },
		{ key: "users:read", name: "查看用户" },
	];
	assert.deepEqual(
		matching(ps, " ORDERS ").map((p) => p.key),
		["orders:read", "orders:export"],
	);
	assert.deepEqual(
		matching(ps, "查看").map((p) => p.key),
		["orders:read", "users:read"],
	);
	assert.equal(matching(ps, "").length, 3);
});

test("ticking keys keeps the others and never doubles one", () => {
	assert.deepEqual(toggled(["a", "b"], ["b", "c"], true), ["a", "b", "c"]);
	assert.deepEqual(toggled(["a", "b", "c"], ["b", "c"], false), ["a"]);
});

test("held Roles grant the union of their Permissions", () => {
	const roles = [
		{ key: "viewer", permissions: ["orders:read"] },
		{ key: "editor", permissions: ["orders:write", "orders:read"] },
		{ key: "admin", permissions: ["orders:delete"] },
	];
	assert.deepEqual(granted(roles, ["viewer", "editor"]), [
		"orders:read",
		"orders:write",
	]);
	assert.deepEqual(granted(roles, []), []);
});
