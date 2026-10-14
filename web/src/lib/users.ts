// User list and detail logic. Pure TypeScript: tested with node --test.
import { z } from "zod";
import type { Identifier, User } from "./console-api.ts";

export const managementAPI = "urn:stars-auth:management-api";

// identifierKinds lists the kinds of Identifier, primary first.
export const identifierKinds: Identifier["kind"][] = [
	"phone",
	"email",
	"username",
];

// kindName is what each kind of Identifier is called.
export const kindName: Record<Identifier["kind"], string> = {
	phone: "手机号",
	email: "邮箱",
	username: "用户名",
};

// primaryIdentifier is the Identifier a User is shown by.
export const primaryIdentifier = (identifiers: Identifier[]) =>
	identifierKinds
		.map((kind) => identifiers.find((i) => i.kind === kind))
		.find(Boolean)?.value;

// avatarInitial is the letter an avatar shows for a primary Identifier,
// skipping a mainland phone number's +86.
export const avatarInitial = (identifier: string) =>
	identifier.replace(/^\+86/, "").charAt(0).toUpperCase();

// onlyAdmins: nothing but admins have signed up yet, which is the Users
// list's empty state (docs/spec/consoles.md「空状态」). Only an unfiltered
// list that fits on one page can say it: with a filter on, an admin-only
// result speaks for the filter, and a page with more behind it hasn't seen
// everyone. No Users at all counts, too.
export const onlyAdmins = (
	users: Pick<User, "roles">[],
	hasMore: boolean,
	filtered: boolean,
) =>
	!filtered &&
	!hasMore &&
	users.every((u) => u.roles.some((r) => r.api === managementAPI));

// query is what a user search box takes.
export const query = z.string().trim().max(100, "最多输入 100 个字。");

export const searchSchema = z.object({ q: query });

// createUserSchema checks 创建用户 (ADR 0016): one Identifier and the initial
// password the admin hands over. Only the password's length is checked
// here: what an Identifier is (+86 phone, email, username) the server
// decides, in its own words, and its normaliser is the only one there is.
export const createUserSchema = z.object({
	identifier: z.string().trim().min(1, "请填写登录标识。"),
	password: z.string().min(8, "密码至少 8 位。"),
});
