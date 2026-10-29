// The console signs in as the built-in public Application with code + PKCE
// and keeps the access token for this tab only; see oidc.ts.

import { oidcClient } from "#/lib/oidc";

export { APIError } from "#/lib/oidc";

export const { login, finishLogin, api, logout } = oidcClient({
	clientID: "polaris-console",
	home: "/console",
	apiPrefix: "/v1/management",
});

export type Identifier = {
	kind: "phone" | "email" | "username";
	value: string;
};
export type Role = { api: string; key: string; name: string };
export type User = {
	sub: string;
	createdAt: string;
	disabledAt?: string;
	pending: boolean; // 待激活: created by an admin, no password of their own yet
	identifiers: Identifier[];
	roles: Role[];
};
// Invite is what a User's 注册邀请 has come to: none 没发出过（撤销了、过期了
// 也算）, sent 有一条还没被接受的链接（expiresAt 是它的期限）, accepted 上一
// 条已经被本人用掉.
export type Invite = {
	state: "none" | "sent" | "accepted";
	expiresAt?: string;
};
export type UserDetail = User & {
	nickname?: string;
	// The avatar's URL.
	picture?: string;
	hasPassword: boolean;
	twoFactor: boolean;
	twoFactorOrPasskey: boolean;
	invite: Invite;
};
export type RoleInfo = Role & { apiName: string; builtin: boolean };
export type Me = { sub: string; identifier: string; permissions: string[] };
export type Session = {
	id: string;
	kind: "browser" | "app";
	application: string;
	authTime: string;
	amr: string[];
	lastSeenAt: string;
	ip: string;
	userAgent: string;
	expiresAt: string;
	endedAt?: string;
	active: boolean;
};
export type AuditEvent = {
	id: number;
	at: string;
	event: string;
	sub?: string;
	user?: string; // sub's primary Identifier; absent once deleted
	byUser?: string; // detail.by's, likewise
	detail: Record<string, unknown>;
};
export type Overview = {
	users: number;
	loginsToday: number;
	liveSessions: number;
	applications: number;
	sendsLastDay: number;
	dailySendLimit: number;
};

export type ChannelField = {
	key: string;
	label: string;
	type: "text" | "number" | "url";
	secret: boolean;
	optional: boolean;
	help?: string;
};
export type ChannelPlugin = {
	key: string;
	name: string;
	kinds: ("phone" | "email")[];
	fields: ChannelField[];
};
// A Provider type's field; an immutable one is set only when adding.
export type ProviderField = ChannelField & { immutable: boolean };
export type ProviderType = {
	key: string;
	name: string;
	fields: ProviderField[];
};
export type ProviderInfo = {
	id: string;
	type: string;
	name: string;
	enabled: boolean;
	config: Record<string, string>;
	secrets: Record<string, string>; // field → when it was last set
	createdAt: string;
	bound: number;
	onlyLoginPath: number; // bound Users with no other way to sign in
	callbackUrl: string;
};
export type ExternalIdentity = {
	provider: string;
	name: string;
	createdAt: string;
};
export type ChannelSettings = {
	kind: "phone" | "email";
	plugin: string;
	config: Record<string, string>;
	secrets: Record<string, string>; // field → when it was last set
	updatedAt: string;
};

export type Policy = {
	passwordLogin: "off" | "on";
	requirePhone: boolean;
	dailySendLimit: number;
	termsUrl: string;
	privacyUrl: string;
	termsVersion: string;
	auditRetentionDays: number;
	adminsNeedTwoFactor: boolean;
	passkeyLogin: boolean;
};
export type SigningKey = { kid: string; createdAt: string; current: boolean };

export type AndroidApp = {
	packageName: string;
	sha256CertFingerprints: string[];
};
export type ApplicationSettings = {
	name: string;
	redirectUris: string[];
	postLogoutRedirectUris: string[];
	defaultApi?: string;
	sessionIdleTimeout?: number; // seconds; 0 or absent for the default
	refreshTokens: boolean;
	webhookUrl?: string;
	webhookSecret?: string; // write-only; empty keeps the stored one
	backchannelLogoutUri?: string; // confidential only; empty for none
	appleAppIds: string[];
	androidApps: AndroidApp[];
};
export type Application = ApplicationSettings & {
	clientId: string;
	type: "public" | "confidential" | "m2m";
	builtin: boolean;
	createdAt: string;
	webhookSecretUpdatedAt?: string;
};
export type PermissionInfo = { key: string; name: string; builtin: boolean };
export type RoleDef = {
	key: string;
	name: string;
	builtin: boolean;
	default: boolean; // given to every User created later; business APIs only
	permissions: string[];
	users: number;
	applications: number;
};
export type APIDef = {
	identifier: string;
	name: string;
	builtin: boolean;
	permissions: PermissionInfo[];
	roles: RoleDef[];
};
// The Roles an M2M Application holds on its API (its default API).
export type ApplicationRoles = { api: string; roles: string[] };

// apiPath names an API in a Management API path; identifiers are often URLs.
export const apiPath = (identifier: string) =>
	`/apis/${encodeURIComponent(identifier)}`;
