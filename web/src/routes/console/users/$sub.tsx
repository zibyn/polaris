import { useForm } from "@tanstack/react-form";
import {
	queryOptions,
	useIsMutating,
	useMutation,
	useQuery,
	useQueryClient,
	useSuspenseQuery,
} from "@tanstack/react-query";
import {
	createFileRoute,
	Link,
	notFound,
	useNavigate,
	useParams,
} from "@tanstack/react-router";
import { ChevronRight } from "lucide-react";
import { type ReactNode, useState } from "react";
import { FormError, failed, saved } from "#/components/form";
import { ItemList } from "#/components/item-list";
import { Badge } from "#/components/ui/badge";
import { Button } from "#/components/ui/button";
import { Checkbox } from "#/components/ui/checkbox";
import {
	Collapsible,
	CollapsibleContent,
	CollapsibleTrigger,
} from "#/components/ui/collapsible";
import {
	Empty,
	EmptyContent,
	EmptyDescription,
	EmptyHeader,
	EmptyTitle,
} from "#/components/ui/empty";
import { FieldLegend, FieldSet } from "#/components/ui/field";
import { Item, ItemActions, ItemContent } from "#/components/ui/item";
import { Label } from "#/components/ui/label";
import { UserAvatar } from "#/components/user-avatar";
import {
	APIError,
	type Application,
	api,
	type ExternalIdentity,
	type RoleInfo,
	type Session,
	type UserDetail,
} from "#/lib/console-api";
import type { Passkey } from "#/lib/passkey";
import {
	identifierKinds,
	kindName,
	managementAPI,
	primaryIdentifier,
} from "#/lib/users";
import { ConfirmDialog } from "#/routes/console/-components/confirm-dialog";
import { Section } from "#/routes/console/-components/section";
import { type Header, useCan } from "#/routes/console/route";
import { date, rolesQuery } from "#/routes/console/users/index";
import {
	PasswordLoginNotice,
	usePasswordLoginOff,
} from "./-components/password-login";

export const Route = createFileRoute("/console/users/$sub")({
	staticData: { crumb: UserName, useHeader },
	loader: ({ context: { queryClient }, params: { sub } }) =>
		Promise.all([
			queryClient.ensureQueryData(userQuery(sub)),
			queryClient.ensureQueryData(sessionsQuery(sub)),
			queryClient.ensureQueryData(passkeysQuery(sub)),
			queryClient.ensureQueryData(externalIdentitiesQuery(sub)),
			queryClient.ensureQueryData(rolesQuery),
		]).catch((e) => {
			throw e instanceof APIError && e.status === 404 ? notFound() : e;
		}),
	notFoundComponent: () => (
		<p className="text-sm">
			没有这个用户，可能已经被删除。
			<Link to="/console/users" className="underline">
				返回用户列表
			</Link>
		</p>
	),
	component: UserPage,
});

const userQuery = (sub: string) =>
	queryOptions({
		queryKey: ["user", sub],
		queryFn: () => api<UserDetail>(`/users/${encodeURIComponent(sub)}`),
	});

const sessionsQuery = (sub: string) =>
	queryOptions({
		queryKey: ["sessions", sub],
		queryFn: () =>
			api<{ sessions: Session[] }>(
				`/users/${encodeURIComponent(sub)}/sessions`,
			),
	});

const passkeysQuery = (sub: string) =>
	queryOptions({
		queryKey: ["passkeys", sub],
		queryFn: () =>
			api<{ passkeys: Passkey[] }>(
				`/users/${encodeURIComponent(sub)}/passkeys`,
			),
	});

const externalIdentitiesQuery = (sub: string) =>
	queryOptions({
		queryKey: ["external-identities", sub],
		queryFn: () =>
			api<{ externalIdentities: ExternalIdentity[] }>(
				`/users/${encodeURIComponent(sub)}/external-identities`,
			),
	});

// UserName is the User's crumb: their primary Identifier, kept current by
// the query.
function UserName(): ReactNode {
	const { sub } = useParams({ from: "/console/users/$sub" });
	const u = useQuery(userQuery(sub)).data;
	return u && (primaryIdentifier(u.identifiers) ?? "未绑定登录标识");
}

// useUser is what the header and the page both read: the User, what the
// admin may do to them, and the actions they share. The header draws in
// the layout, around the page's loading and errors, so it doesn't suspend.
function useUser() {
	const { sub } = useParams({ from: "/console/users/$sub" });
	const user = useQuery(userQuery(sub));
	const can = useCan();
	const act = useUserAction(sub);
	const u = user.data;
	// Acting on an admin takes admin-roles:assign too.
	const writable =
		!!u &&
		can("users:write") &&
		(can("admin-roles:assign") ||
			!u.roles.some((r) => r.api === managementAPI));
	return { user, can, act, writable };
}

function useHeader(): Header | null {
	const { user, can, act, writable } = useUser();
	const u = user.data;
	if (user.error || !u) {
		return null;
	}
	const name = primaryIdentifier(u.identifiers);
	const who = name ? `用户 ${name}` : "这个用户";
	return {
		title: (
			<>
				<UserAvatar name={name} size="lg" />
				{name ?? "未绑定登录标识"}
			</>
		),
		badges: (
			<>
				{u.disabledAt ? (
					<Badge variant="destructive">已禁用 · {date(u.disabledAt)}</Badge>
				) : u.pending ? (
					<Badge variant="warning">待激活</Badge>
				) : (
					<Badge variant="success">已激活</Badge>
				)}
				{can("audit:read") && (
					<Link
						to="/console/audit"
						search={{ sub: u.sub, q: name ?? u.sub }}
						className="text-primary-ink text-sm hover:underline"
					>
						查看审计记录
					</Link>
				)}
			</>
		),
		// 待激活 is what an admin needs told: the account signs in, but no
		// token comes of it until the User sets a password of their own.
		description:
			u.pending &&
			"这个用户还没设置自己的密码：能登录，但在本人设置之前拿不到任何令牌。",
		actions: writable && (
			<>
				{u.disabledAt ? (
					<Button
						variant="outline"
						disabled={act.isPending}
						onClick={() =>
							act.mutate({
								method: "POST",
								path: "/enable",
								what: "恢复用户失败",
							})
						}
					>
						恢复
					</Button>
				) : (
					<ConfirmDialog
						trigger={
							<Button variant="outline" disabled={act.isPending}>
								禁用
							</Button>
						}
						title={`禁用${who}？`}
						action="禁用用户"
						onConfirm={() =>
							act.mutate({
								method: "POST",
								path: "/disable",
								what: "禁用用户失败",
							})
						}
					>
						禁用后该用户无法登录，所有会话立即下线；之后可以随时恢复。
					</ConfirmDialog>
				)}
				<DeleteUser
					who={who}
					disabled={act.isPending}
					onConfirm={() =>
						act.mutate({
							method: "DELETE",
							path: "",
							what: "删除用户失败",
							leave: true,
						})
					}
				/>
			</>
		),
	};
}

function UserPage() {
	const { act, writable } = useUser();
	const { sub } = Route.useParams();
	const u = useSuspenseQuery(userQuery(sub)).data;
	const name = primaryIdentifier(u.identifiers);
	return (
		<div className="space-y-10 pt-4">
			<Section title="登录标识与密码">
				<ItemList>
					{identifierKinds.map((kind) => (
						<Row key={kind} label={kindName[kind]}>
							{u.identifiers.find((i) => i.kind === kind)?.value ?? (
								<span className="text-muted-foreground">未绑定</span>
							)}
							{writable && (
								<Button
									size="sm"
									variant="ghost"
									disabled={act.isPending}
									onClick={() => {
										const value = prompt(`新的${kindName[kind]}`);
										if (value) {
											act.mutate({
												method: "PUT",
												path: `/identifiers/${kind}`,
												body: { value },
												what: `更换${kindName[kind]}失败`,
											});
										}
									}}
								>
									更换
								</Button>
							)}
						</Row>
					))}
					<Row label="密码">{u.hasPassword ? "已设置" : "未设置"}</Row>
				</ItemList>
			</Section>
			<Section title="注册邀请">
				<Invite
					sub={u.sub}
					who={name}
					invite={u.invite}
					email={u.identifiers.find((i) => i.kind === "email")?.value}
					writable={writable}
				/>
			</Section>
			<Section title="已绑定的外部账号">
				<ExternalIdentities sub={u.sub} who={name} writable={writable} />
			</Section>
			<Section title="两步验证">
				<ItemList>
					<Row label="状态">
						{u.twoFactor
							? "已开启"
							: u.twoFactorOrPasskey
								? "由 Passkey 满足"
								: "未开启"}
						{writable && u.twoFactor && (
							<ConfirmDialog
								trigger={
									<Button size="sm" variant="ghost" disabled={act.isPending}>
										重置两步验证
									</Button>
								}
								title={`重置${name ? `用户 ${name} ` : "这个用户"}的两步验证？`}
								action="重置两步验证"
								onConfirm={() =>
									act.mutate({
										method: "DELETE",
										path: "/2fa",
										what: "重置两步验证失败",
									})
								}
							>
								请先线下核实对方身份。重置会清除该用户的验证器和全部恢复码，之后只用验证码或密码就能登录，需要再到账号中心重新开启。已登录的设备不会下线。
							</ConfirmDialog>
						)}
					</Row>
				</ItemList>
			</Section>
			<Section title="Passkey">
				<Passkeys sub={u.sub} who={name} writable={writable} />
			</Section>
			<Section title="会话">
				<Sessions sub={u.sub} writable={writable} />
			</Section>
			<Section title="角色">
				<RoleAssignment user={u} />
			</Section>
			<Collapsible>
				<CollapsibleTrigger className="flex items-center gap-1 text-[13px] text-muted-foreground [&[data-panel-open]>svg]:rotate-90">
					<ChevronRight className="size-4 transition-transform" />
					更多信息
				</CollapsibleTrigger>
				<CollapsibleContent>
					<ItemList>
						<Row label="用户 ID">
							<span className="font-mono text-xs">{u.sub}</span>
						</Row>
						<Row label="注册时间">{date(u.createdAt)}</Row>
					</ItemList>
				</CollapsibleContent>
			</Collapsible>
		</div>
	);
}

// DeleteUser confirms deleting a User; when an Application gets user
// deletion notifications, it says so (spec 依赖提示 #13).
function DeleteUser({
	who,
	disabled,
	onConfirm,
}: {
	who: string;
	disabled: boolean;
	onConfirm: () => void;
}) {
	const can = useCan();
	const apps = useQuery({
		queryKey: ["applications"],
		queryFn: () => api<{ applications: Application[] }>("/applications"),
		enabled: can("applications:read"),
	});
	const notifies = apps.data?.applications.some((a) => a.webhookUrl);
	return (
		<ConfirmDialog
			trigger={
				<Button variant="destructive" disabled={disabled || apps.isLoading}>
					删除
				</Button>
			}
			title={`删除${who}？`}
			action="删除用户"
			onConfirm={onConfirm}
		>
			删除等同注销：该用户的全部数据都将删除，无法恢复。
			{notifies && "会通知已配置用户删除通知的应用。"}
		</ConfirmDialog>
	);
}

// useUserAction calls a users:write operation on sub (path under
// /users/{sub}) and refreshes what it changes; what names it in the toast
// if it fails; leave goes back to the Users list after it. The header and the page each hold one; both see whether a
// call is running.
function useUserAction(sub: string) {
	const client = useQueryClient();
	const navigate = useNavigate();
	const mutationKey = ["user-action", sub];
	const { mutate } = useMutation({
		mutationKey,
		mutationFn: (a: {
			method: "POST" | "PUT" | "DELETE";
			path: string;
			body?: unknown;
			what: string;
			leave?: boolean;
		}) =>
			api(`/users/${encodeURIComponent(sub)}${a.path}`, {
				method: a.method,
				body: a.body,
			}),
		onSuccess: (_, a) => {
			if (a.leave) {
				navigate({ to: "/console/users" });
			}
			return client.invalidateQueries();
		},
		onError: (e, a) => failed(a.what)(e),
	});
	const isPending = useIsMutating({ mutationKey }) > 0;
	return { mutate, isPending };
}

// ExternalIdentities lists the accounts at Providers the User signs in
// with. Unbinding is for a User who lost one (an Apple ID, say); it can't
// take their last way to sign in.
function ExternalIdentities({
	sub,
	who,
	writable,
}: {
	sub: string;
	who?: string;
	writable: boolean;
}) {
	const act = useUserAction(sub);
	const list = useSuspenseQuery(externalIdentitiesQuery(sub)).data
		.externalIdentities;
	if (list.length === 0) {
		return (
			<p className="py-3 text-muted-foreground text-sm">没有绑定外部账号。</p>
		);
	}
	return (
		<ItemList>
			{list.map((e) => (
				<Row key={e.provider} label={e.name}>
					<span className="text-muted-foreground text-xs">
						绑定于 {date(e.createdAt)}
					</span>
					{writable && (
						<ConfirmDialog
							trigger={
								<Button size="sm" variant="ghost" disabled={act.isPending}>
									解绑
								</Button>
							}
							title={`解绑${who ? `用户 ${who} ` : "这个用户"}的 ${e.name} 账号？`}
							action="解绑外部账号"
							onConfirm={() =>
								act.mutate({
									method: "DELETE",
									path: `/external-identities/${encodeURIComponent(e.provider)}`,
									what: "解绑外部账号失败",
								})
							}
						>
							请先线下核实对方身份。解绑后该用户不能再用 {e.name} 登录，会通知{" "}
							{e.name}{" "}
							撤销授权；要用得在账号中心重新绑定。如果这是他唯一的登录方式，不能解绑。
						</ConfirmDialog>
					)}
				</Row>
			))}
		</ItemList>
	);
}

// Invite is the User's 注册邀请 (ADR 0016): where it stands, and the three
// things an admin does about it — 发出, 重发, 撤销. 重发 is the same call as
// 发出 (a new link replaces the old one), so the state decides the label, and
// 撤销 only exists while there is a link to take back. A User with no email
// can't be invited at all, and neither can anyone while 密码登录 is off.
function Invite({
	sub,
	who,
	invite,
	email,
	writable,
}: {
	sub: string;
	who?: string;
	invite: UserDetail["invite"];
	email?: string;
	writable: boolean;
}) {
	const act = useUserAction(sub);
	const off = usePasswordLoginOff();
	const sent = invite.state === "sent";
	const them = who ? `用户 ${who} ` : "这个用户";
	const status = sent
		? `已发出${invite.expiresAt ? ` · ${date(invite.expiresAt)} 过期` : ""}`
		: invite.state === "accepted"
			? "已接受"
			: "未发出";
	return (
		<>
			{off && (
				<PasswordLoginNotice detail="关闭时发不出注册邀请，链接指向的设密码页也走不通。" />
			)}
			<ItemList>
				<Row label="状态">
					<span className="text-xs">{status}</span>
					{!email ? (
						<span className="text-muted-foreground text-xs">
							这个用户没有邮箱，发不了邀请。
						</span>
					) : (
						writable && (
							<>
								<ConfirmDialog
									trigger={
										<Button
											size="sm"
											variant="ghost"
											disabled={act.isPending || off}
										>
											{sent ? "重发" : "发出邀请"}
										</Button>
									}
									title={`${sent ? "重发" : "发出"}${them}的注册邀请？`}
									action="发出注册邀请"
									onConfirm={() =>
										act.mutate({
											method: "POST",
											path: "/invite",
											what: "发出注册邀请失败",
										})
									}
								>
									{sent
										? `会往 ${email} 发一条新链接，旧的那条立刻失效，只有最新这封能用。`
										: `会往 ${email} 发一条 7 天有效的一次性链接。`}
									本人点开自己设密码，设完就能登录，这个密码不经过你手上。
								</ConfirmDialog>
								{sent && (
									<ConfirmDialog
										trigger={
											<Button
												size="sm"
												variant="ghost"
												disabled={act.isPending}
											>
												撤销
											</Button>
										}
										title={`撤销${them}的注册邀请？`}
										action="撤销注册邀请"
										onConfirm={() =>
											act.mutate({
												method: "DELETE",
												path: "/invite",
												what: "撤销注册邀请失败",
											})
										}
									>
										撤销后那条链接立刻不能用了，本人得找你重发；已经设置好密码的账号不受影响。
									</ConfirmDialog>
								)}
							</>
						)
					)}
				</Row>
			</ItemList>
		</>
	);
}

function Sessions({ sub, writable }: { sub: string; writable: boolean }) {
	const client = useQueryClient();
	const list = useSuspenseQuery(sessionsQuery(sub)).data.sessions;
	const end = useMutation({
		mutationFn: (id: string) =>
			api(
				`/users/${encodeURIComponent(sub)}/sessions/${encodeURIComponent(id)}`,
				{ method: "DELETE" },
			),
		onSuccess: () => client.invalidateQueries({ queryKey: ["sessions", sub] }),
		onError: failed("下线会话失败"),
	});
	return (
		<>
			<ItemList>
				{list.map((s) => (
					<Row
						key={s.id}
						label={`${s.kind === "app" ? "App" : "浏览器"} · ${s.application}`}
					>
						<span className="text-muted-foreground text-xs">
							{s.active
								? `活跃于 ${date(s.lastSeenAt)}`
								: `已结束 ${date(s.endedAt ?? s.expiresAt)}`}
						</span>
						{writable && s.active && (
							<Button
								size="sm"
								variant="ghost"
								disabled={end.isPending}
								onClick={() => end.mutate(s.id)}
							>
								下线
							</Button>
						)}
					</Row>
				))}
			</ItemList>
			{!list.some((s) => s.active) && (
				<div className="py-3">
					<Empty className="border">
						<EmptyHeader>
							<EmptyTitle>没有登录中的设备</EmptyTitle>
							<EmptyDescription>
								这个用户目前在任何设备上都没有保持登录。
							</EmptyDescription>
						</EmptyHeader>
					</Empty>
				</div>
			)}
		</>
	);
}

// Passkeys lists the User's Passkeys for a lost-device report; deleting
// one is the admin's, written to the audit under their own name.
function Passkeys({
	sub,
	who,
	writable,
}: {
	sub: string;
	who?: string;
	writable: boolean;
}) {
	const client = useQueryClient();
	const list = useSuspenseQuery(passkeysQuery(sub)).data.passkeys;
	const remove = useMutation({
		mutationFn: (id: string) =>
			api(
				`/users/${encodeURIComponent(sub)}/passkeys/${encodeURIComponent(id)}`,
				{ method: "DELETE" },
			),
		onSuccess: () => client.invalidateQueries({ queryKey: ["passkeys", sub] }),
		onError: failed("删除 Passkey 失败"),
	});
	if (list.length === 0) {
		return (
			<p className="py-3 text-muted-foreground text-sm">
				这个用户还没有添加过 Passkey。
			</p>
		);
	}
	return (
		<ItemList>
			{list.map((p) => (
				<Row key={p.id} label={p.name}>
					<span className="text-muted-foreground text-xs">
						添加于 {date(p.createdAt)} ·{" "}
						{p.lastUsedAt ? `最后使用 ${date(p.lastUsedAt)}` : "尚未使用"}
					</span>
					{writable && (
						<ConfirmDialog
							trigger={
								<Button size="sm" variant="ghost" disabled={remove.isPending}>
									删除
								</Button>
							}
							title={`删除${who ? `用户 ${who} ` : "这个用户"}的 Passkey ${p.name}？`}
							action="删除 Passkey"
							onConfirm={() => remove.mutate(p.id)}
						>
							删除后这把 Passkey
							不能再用来登录；处理设备丢失的报告时在这里删掉它。
						</ConfirmDialog>
					)}
				</Row>
			))}
		</ItemList>
	);
}

// RoleAssignment lists every API resource's Roles with the User's ticked;
// each saves on its own. Management API Roles need admin-roles:assign.
function RoleAssignment({ user }: { user: UserDetail }) {
	const can = useCan();
	const { roles } = useSuspenseQuery(rolesQuery).data;
	const [assigning, setAssigning] = useState(false);
	const byAPI = new Map<string, RoleInfo[]>();
	for (const r of roles) {
		byAPI.set(r.api, [...(byAPI.get(r.api) ?? []), r]);
	}
	// Only the built-in Management API Roles: nothing of the reader's own.
	const noOwnRoles = roles.every((r) => r.api === managementAPI);
	const toAPIs = noOwnRoles && can("applications:read") && (
		<Link to="/console/apis" className="underline">
			去「API 资源」添加角色
		</Link>
	);
	// Without one Role the reader may assign, 分配角色 leads nowhere.
	const assignable =
		can("roles:assign") && (!noOwnRoles || can("admin-roles:assign"));
	if (user.roles.length === 0 && !assigning) {
		return (
			<div className="py-3">
				<Empty className="border">
					<EmptyHeader>
						<EmptyTitle>没有角色</EmptyTitle>
						<EmptyDescription>
							这个用户目前只能登录，不带任何权限。
						</EmptyDescription>
					</EmptyHeader>
					<EmptyContent>
						{can("roles:assign") ? (
							<>
								{assignable && (
									<Button size="sm" onClick={() => setAssigning(true)}>
										分配角色
									</Button>
								)}
								{toAPIs}
							</>
						) : (
							<span className="text-muted-foreground">
								需要「管理员」角色才能分配角色。
							</span>
						)}
					</EmptyContent>
				</Empty>
			</div>
		);
	}
	return (
		<>
			<ItemList>
				{[...byAPI].map(([apiID, list]) => (
					<APIRoles key={apiID} user={user} apiID={apiID} roles={list} />
				))}
			</ItemList>
			{can("roles:assign") && toAPIs && (
				<p className="py-3 text-sm">{toAPIs}</p>
			)}
		</>
	);
}

function APIRoles({
	user,
	apiID,
	roles,
}: {
	user: UserDetail;
	apiID: string;
	roles: RoleInfo[];
}) {
	const can = useCan();
	const client = useQueryClient();
	const editable = can(
		apiID === managementAPI ? "admin-roles:assign" : "roles:assign",
	);
	const held = user.roles.filter((r) => r.api === apiID).map((r) => r.key);
	const save = useMutation({
		mutationFn: (keys: string[]) =>
			api(`/users/${encodeURIComponent(user.sub)}/roles`, {
				method: "PUT",
				body: { api: apiID, roles: keys },
			}),
		onSuccess: () => client.invalidateQueries(),
	});
	const form = useForm({
		defaultValues: { roles: held },
		onSubmit: ({ value }) => save.mutate(value.roles, { onSuccess: saved }),
	});
	return (
		<Item
			key={held.join()}
			className="flex-col items-start gap-2"
			render={
				<form
					noValidate
					onSubmit={(e) => {
						e.preventDefault();
						form.handleSubmit();
					}}
				/>
			}
		>
			<form.Field name="roles">
				{(field) => (
					<FieldSet>
						<FieldLegend
							variant="label"
							className="text-[13px] text-muted-foreground font-normal"
						>
							{roles[0].apiName}
						</FieldLegend>
						<div className="flex flex-wrap gap-x-4 gap-y-2">
							{roles.map((r) => (
								<Label key={r.key} className="font-normal">
									<Checkbox
										disabled={!editable}
										checked={field.state.value.includes(r.key)}
										onCheckedChange={(on) =>
											field.handleChange(
												on
													? [...field.state.value, r.key]
													: field.state.value.filter((k) => k !== r.key),
											)
										}
									/>
									{r.name}
								</Label>
							))}
						</div>
					</FieldSet>
				)}
			</form.Field>
			<FormError error={save.error} />
			{editable && (
				<Button
					type="submit"
					size="sm"
					variant="outline"
					disabled={save.isPending}
				>
					保存
				</Button>
			)}
		</Item>
	);
}

function Row({
	label,
	children,
}: {
	label: string;
	children: React.ReactNode;
}) {
	return (
		<Item>
			<ItemContent className="text-muted-foreground">{label}</ItemContent>
			<ItemActions>{children}</ItemActions>
		</Item>
	);
}
