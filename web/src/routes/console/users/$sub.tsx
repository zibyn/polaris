import { revalidateLogic, useForm } from "@tanstack/react-form";
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
import { type ReactNode, useState } from "react";
import { toast } from "sonner";
import { z } from "zod";
import { FormError, FormField, failed, saved } from "#/components/form";
import { ItemList, PropRow } from "#/components/item-list";
import { Badge } from "#/components/ui/badge";
import { Button } from "#/components/ui/button";
import { Checkbox } from "#/components/ui/checkbox";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogTitle,
} from "#/components/ui/dialog";
import {
	Empty,
	EmptyContent,
	EmptyDescription,
	EmptyHeader,
	EmptyTitle,
} from "#/components/ui/empty";
import { FieldGroup, FieldLegend, FieldSet } from "#/components/ui/field";
import { Input } from "#/components/ui/input";
import {
	Item,
	ItemActions,
	ItemContent,
	ItemDescription,
	ItemTitle,
} from "#/components/ui/item";
import { Label } from "#/components/ui/label";
import { UserAvatar } from "#/components/user-avatar";
import { nicknameSchema } from "#/lib/account";
import {
	APIError,
	type Application,
	api,
	type ExternalIdentity,
	type Identifier,
	type RoleInfo,
	type Session,
	type UserDetail,
} from "#/lib/console-api";
import { deviceLabel } from "#/lib/device";
import type { Passkey } from "#/lib/passkey";
import {
	identifierKinds,
	kindName,
	managementAPI,
	primaryIdentifier,
} from "#/lib/users";
import { ConfirmDialog } from "#/routes/console/-components/confirm-dialog";
import { IdLine, Section } from "#/routes/console/-components/section";
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
			用户不存在或已被删除。
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
	const who = name ? `用户 ${name}` : "该用户";
	return {
		title: (
			<>
				<UserAvatar name={u.nickname ?? name} picture={u.picture} size="lg" />
				{name ?? "未绑定登录标识"}
			</>
		),
		badges: u.disabledAt ? (
			<Badge variant="destructive">已禁用 · {date(u.disabledAt)}</Badge>
		) : u.pending ? (
			<Badge variant="warning">待激活</Badge>
		) : (
			<Badge variant="success">已激活</Badge>
		),
		ids: (
			<>
				<IdLine label="用户 ID" value={u.sub} />
				<span className="text-[13px] text-muted-foreground">
					注册于 {date(u.createdAt)}
				</span>
			</>
		),
		// 待激活 is what an admin needs told: the account signs in, but no
		// token comes of it until the User sets a password of their own.
		description: u.pending && "用户设置密码前，登录后无法获取令牌。",
		actions: (
			<>
				{can("audit:read") && (
					<Link
						to="/console/audit"
						search={{ sub: u.sub, q: name ?? u.sub }}
						className="mr-2 whitespace-nowrap rounded-sm text-primary-ink text-sm hover:underline"
					>
						查看审计记录
					</Link>
				)}
				{writable &&
					(u.disabledAt ? (
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
							禁用后用户无法登录，已有会话立即下线。
						</ConfirmDialog>
					))}
				{writable && (
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
				)}
			</>
		),
	};
}

function UserPage() {
	const { act, writable } = useUser();
	const { sub } = Route.useParams();
	const u = useSuspenseQuery(userQuery(sub)).data;
	const name = primaryIdentifier(u.identifiers);
	const [changing, setChanging] = useState<Identifier["kind"] | null>(null);
	const [renaming, setRenaming] = useState(false);
	return (
		<div className="max-w-3xl space-y-10 pt-4">
			<Section title="个人资料">
				<ItemList>
					<PropRow
						label="昵称"
						actions={
							writable && (
								<Button
									size="sm"
									variant="ghost"
									onClick={() => setRenaming(true)}
								>
									修改
								</Button>
							)
						}
					>
						{u.nickname ?? (
							<span className="text-muted-foreground">未设置</span>
						)}
					</PropRow>
					<PropRow
						label="头像"
						actions={
							writable &&
							u.picture && (
								<ConfirmDialog
									trigger={
										<Button size="sm" variant="ghost" disabled={act.isPending}>
											移除
										</Button>
									}
									title="移除头像？"
									action="移除头像"
									onConfirm={() =>
										act.mutate({
											method: "DELETE",
											path: "/avatar",
											what: "移除头像失败",
										})
									}
								>
									头像将从所有应用中移除，用户可重新上传。
								</ConfirmDialog>
							)
						}
					>
						{u.picture ? (
							<UserAvatar picture={u.picture} name={u.nickname ?? name} />
						) : (
							<span className="text-muted-foreground">未上传</span>
						)}
					</PropRow>
				</ItemList>
			</Section>
			{renaming && (
				<EditNickname
					sub={u.sub}
					current={u.nickname ?? ""}
					onClose={() => setRenaming(false)}
				/>
			)}
			<Section title="登录标识与密码">
				<ItemList>
					{identifierKinds.map((kind) => {
						const value = u.identifiers.find((i) => i.kind === kind)?.value;
						return (
							<PropRow
								key={kind}
								label={kindName[kind]}
								actions={
									writable && (
										<Button
											size="sm"
											variant="ghost"
											onClick={() => setChanging(kind)}
										>
											{value ? "更换" : "绑定"}
										</Button>
									)
								}
							>
								{value ?? <span className="text-muted-foreground">未绑定</span>}
							</PropRow>
						);
					})}
					<PropRow label="密码">{u.hasPassword ? "已设置" : "未设置"}</PropRow>
				</ItemList>
			</Section>
			{changing && (
				<ChangeIdentifier
					sub={u.sub}
					kind={changing}
					current={u.identifiers.find((i) => i.kind === changing)?.value}
					onClose={() => setChanging(null)}
				/>
			)}
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
					<PropRow
						label="状态"
						actions={
							writable &&
							u.twoFactor && (
								<ConfirmDialog
									trigger={
										<Button size="sm" variant="ghost" disabled={act.isPending}>
											重置两步验证
										</Button>
									}
									title={`重置${name ? `用户 ${name} ` : "该用户"}的两步验证？`}
									action="重置两步验证"
									onConfirm={() =>
										act.mutate({
											method: "DELETE",
											path: "/2fa",
											what: "重置两步验证失败",
										})
									}
								>
									将清除用户的验证器和全部恢复码，已登录的设备不会下线。请先线下核实用户身份。
								</ConfirmDialog>
							)
						}
					>
						{u.twoFactor
							? "已开启"
							: u.twoFactorOrPasskey
								? "由 Passkey 满足"
								: "未开启"}
					</PropRow>
				</ItemList>
			</Section>
			<Section title="Passkey">
				<Passkeys sub={u.sub} who={name} writable={writable} />
			</Section>
			<Sessions sub={u.sub} writable={writable} />
			<RoleAssignment user={u} />
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
			将永久删除该用户的全部数据。此操作无法撤销。
			{notifies && "已配置用户删除通知的应用会收到通知。"}
		</ConfirmDialog>
	);
}

// ChangeIdentifier sets or replaces a phone number, email or username. What
// an Identifier may be — normalising, uniqueness — is the server's call in
// its own words, as with 创建用户, so only emptiness is checked here.
function ChangeIdentifier({
	sub,
	kind,
	current,
	onClose,
}: {
	sub: string;
	kind: Identifier["kind"];
	current?: string;
	onClose: () => void;
}) {
	const client = useQueryClient();
	const save = useMutation({
		mutationFn: (value: string) =>
			api(`/users/${encodeURIComponent(sub)}/identifiers/${kind}`, {
				method: "PUT",
				body: { value },
			}),
		onSuccess: async () => {
			await client.invalidateQueries();
			saved();
			onClose();
		},
	});
	const form = useForm({
		defaultValues: { value: "" },
		validationLogic: revalidateLogic(),
		validators: {
			onDynamic: z.object({
				value: z.string().trim().min(1, `请输入${kindName[kind]}。`),
			}),
		},
		onSubmit: ({ value }) => save.mutate(value.value.trim()),
	});
	const what = kindName[kind];
	return (
		<Dialog open onOpenChange={(open) => !open && onClose()}>
			<DialogContent>
				<DialogTitle>{current ? `更换${what}` : `绑定${what}`}</DialogTitle>
				<DialogDescription>
					{current
						? `当前为 ${current}。保存后原${what}不能再用于登录。`
						: `绑定后可用于登录，视为已验证。`}
				</DialogDescription>
				<form
					noValidate
					className="space-y-3"
					onSubmit={(e) => {
						e.preventDefault();
						form.handleSubmit();
					}}
				>
					<FieldGroup className="gap-3">
						<form.Field name="value">
							{(field) => (
								<FormField field={field} label={current ? `新${what}` : what}>
									{(control) => (
										<Input
											{...control}
											type={
												kind === "phone"
													? "tel"
													: kind === "email"
														? "email"
														: "text"
											}
											autoComplete="off"
											placeholder={
												kind === "phone"
													? "+86 手机号"
													: kind === "email"
														? "邮箱"
														: "用户名"
											}
										/>
									)}
								</FormField>
							)}
						</form.Field>
					</FieldGroup>
					<FormError error={save.error} />
					<div className="flex justify-end gap-2">
						<Button type="button" variant="outline" onClick={onClose}>
							取消
						</Button>
						<Button type="submit" disabled={save.isPending}>
							保存
						</Button>
					</div>
				</form>
			</DialogContent>
		</Dialog>
	);
}

function EditNickname({
	sub,
	current,
	onClose,
}: {
	sub: string;
	current: string;
	onClose: () => void;
}) {
	const client = useQueryClient();
	const save = useMutation({
		mutationFn: (nickname: string) =>
			api(`/users/${encodeURIComponent(sub)}/profile`, {
				method: "PATCH",
				body: { nickname },
			}),
		onSuccess: async () => {
			await client.invalidateQueries();
			saved();
			onClose();
		},
	});
	const form = useForm({
		defaultValues: { nickname: current },
		validationLogic: revalidateLogic(),
		validators: { onDynamic: nicknameSchema },
		onSubmit: ({ value }) => save.mutate(value.nickname.trim()),
	});
	return (
		<Dialog open onOpenChange={(open) => !open && onClose()}>
			<DialogContent>
				<DialogTitle>修改昵称</DialogTitle>
				<DialogDescription>留空即清除昵称。</DialogDescription>
				<form
					noValidate
					className="space-y-3"
					onSubmit={(e) => {
						e.preventDefault();
						form.handleSubmit();
					}}
				>
					<form.Field name="nickname">
						{(field) => (
							<FormField field={field} label="昵称">
								{(control) => (
									<Input {...control} autoComplete="off" maxLength={64} />
								)}
							</FormField>
						)}
					</form.Field>
					<FormError error={save.error} />
					<div className="flex justify-end gap-2">
						<Button type="button" variant="outline" onClick={onClose}>
							取消
						</Button>
						<Button type="submit" disabled={save.isPending}>
							保存
						</Button>
					</div>
				</form>
			</DialogContent>
		</Dialog>
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
		return <p className="text-muted-foreground text-sm">没有绑定外部账号。</p>;
	}
	return (
		<ItemList>
			{list.map((e) => (
				<Item key={e.provider} size="sm">
					<ItemContent className="min-w-0">
						<ItemTitle className="font-normal">{e.name}</ItemTitle>
						<ItemDescription className="text-[13px]">
							{`绑定于 ${date(e.createdAt)}`}
						</ItemDescription>
					</ItemContent>
					{writable && (
						<ItemActions>
							<ConfirmDialog
								trigger={
									<Button size="sm" variant="ghost" disabled={act.isPending}>
										解绑
									</Button>
								}
								title={`解绑${who ? `用户 ${who} ` : "该用户"}的 ${e.name} 账号？`}
								action="解绑外部账号"
								onConfirm={() =>
									act.mutate({
										method: "DELETE",
										path: `/external-identities/${encodeURIComponent(e.provider)}`,
										what: "解绑外部账号失败",
									})
								}
							>
								解绑后用户不能再用 {e.name} 登录，并会通知 {e.name}{" "}
								撤销授权。请先线下核实用户身份。
							</ConfirmDialog>
						</ItemActions>
					)}
				</Item>
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
	const them = who ? `用户 ${who} ` : "该用户";
	const status = sent
		? `已发出${invite.expiresAt ? ` · ${date(invite.expiresAt)} 过期` : ""}`
		: invite.state === "accepted"
			? "已接受"
			: "未发出";
	return (
		<>
			{off && (
				<PasswordLoginNotice detail="密码登录关闭时，无法发送或使用注册邀请。" />
			)}
			<ItemList>
				<PropRow
					label="状态"
					hint={!email && "用户未绑定邮箱，无法发送邀请。"}
					actions={
						email &&
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
										? `将向 ${email} 发送新链接，旧链接立即失效。`
										: `将向 ${email} 发送设置密码链接，7 天内有效。`}
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
										撤销后链接立即失效，需重新发送。
									</ConfirmDialog>
								)}
							</>
						)
					}
				>
					{status}
				</PropRow>
			</ItemList>
		</>
	);
}

// Sessions is the 会话 section; 全部下线 sits in its title row.
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
	const active = list.filter((s) => s.active);
	// For a lost device: sign the User out everywhere in one go, rather than
	// row by row.
	const endAll = useMutation({
		mutationFn: () =>
			Promise.all(
				active.map((s) =>
					api(
						`/users/${encodeURIComponent(sub)}/sessions/${encodeURIComponent(s.id)}`,
						{ method: "DELETE" },
					),
				),
			),
		onSettled: () => client.invalidateQueries({ queryKey: ["sessions", sub] }),
		onSuccess: () => toast.success("已全部下线"),
		onError: failed("下线会话失败"),
	});
	return (
		<Section
			title="会话"
			actions={
				writable &&
				active.length > 1 && (
					<ConfirmDialog
						trigger={
							<Button size="sm" variant="outline" disabled={endAll.isPending}>
								全部下线
							</Button>
						}
						title="下线该用户的全部会话？"
						action="全部下线"
						onConfirm={() => endAll.mutate()}
					>
						用户将在所有设备上退出登录。
					</ConfirmDialog>
				)
			}
		>
			<ItemList>
				{list.map((s) => (
					<Item key={s.id} size="sm">
						<ItemContent className="min-w-0">
							<ItemTitle className="font-normal">{`${deviceLabel(s.userAgent)} · ${s.application}`}</ItemTitle>
							<ItemDescription className="text-[13px]">
								{[
									s.ip,
									s.active
										? `活跃于 ${date(s.lastSeenAt)}`
										: `已结束 ${date(s.endedAt ?? s.expiresAt)}`,
								]
									.filter(Boolean)
									.join(" · ")}
							</ItemDescription>
						</ItemContent>
						{writable && s.active && (
							<ItemActions>
								<Button
									size="sm"
									variant="ghost"
									disabled={end.isPending}
									onClick={() => end.mutate(s.id)}
								>
									下线
								</Button>
							</ItemActions>
						)}
					</Item>
				))}
			</ItemList>
			{active.length === 0 && (
				<Empty className={list.length > 0 ? "mt-3 border" : "border"}>
					<EmptyHeader>
						<EmptyTitle>没有登录中的设备</EmptyTitle>
						<EmptyDescription>该用户当前未在任何设备上登录。</EmptyDescription>
					</EmptyHeader>
				</Empty>
			)}
		</Section>
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
		return <p className="text-muted-foreground text-sm">还没有 Passkey。</p>;
	}
	return (
		<ItemList>
			{list.map((p) => (
				<Item key={p.id} size="sm">
					<ItemContent className="min-w-0">
						<ItemTitle className="font-normal">{p.name}</ItemTitle>
						<ItemDescription className="text-[13px]">
							{`添加于 ${date(p.createdAt)} · ${p.lastUsedAt ? `最后使用 ${date(p.lastUsedAt)}` : "尚未使用"}`}
						</ItemDescription>
					</ItemContent>
					{writable && (
						<ItemActions>
							<ConfirmDialog
								trigger={
									<Button size="sm" variant="ghost" disabled={remove.isPending}>
										删除
									</Button>
								}
								title={`删除${who ? `用户 ${who} ` : "该用户"}的 Passkey ${p.name}？`}
								action="删除 Passkey"
								onConfirm={() => remove.mutate(p.id)}
							>
								删除后该 Passkey 无法再用于登录。
							</ConfirmDialog>
						</ItemActions>
					)}
				</Item>
			))}
		</ItemList>
	);
}

// RoleAssignment is the 角色 section: every API resource's Roles with the
// User's ticked; each saves on its own. Management API Roles need
// admin-roles:assign.
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
		<Link
			to="/console/apis"
			className="rounded-sm text-primary-ink text-sm hover:underline"
		>
			去「API 资源」添加角色
		</Link>
	);
	// Without one Role the reader may assign, 分配角色 leads nowhere.
	const assignable =
		can("roles:assign") && (!noOwnRoles || can("admin-roles:assign"));
	if (user.roles.length === 0 && !assigning) {
		return (
			<Section title="角色">
				<Empty className="border">
					<EmptyHeader>
						<EmptyTitle>没有角色</EmptyTitle>
						<EmptyDescription>用户当前没有任何权限。</EmptyDescription>
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
			</Section>
		);
	}
	return (
		<Section title="角色" actions={can("roles:assign") && toAPIs}>
			<ItemList>
				{[...byAPI].map(([apiID, list]) => (
					<APIRoles key={apiID} user={user} apiID={apiID} roles={list} />
				))}
			</ItemList>
		</Section>
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
		<form
			key={held.join()}
			noValidate
			className="space-y-2 py-3"
			onSubmit={(e) => {
				e.preventDefault();
				form.handleSubmit();
			}}
		>
			<form.Field name="roles">
				{(field) => (
					<FieldSet className="gap-2">
						<FieldLegend
							variant="label"
							className="mb-0 font-normal text-[13px] text-muted-foreground"
						>
							{roles[0].apiName}
						</FieldLegend>
						<div className="flex flex-wrap items-center gap-x-4 gap-y-2">
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
						</div>
					</FieldSet>
				)}
			</form.Field>
			<FormError error={save.error} />
		</form>
	);
}
