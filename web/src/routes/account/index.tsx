import { revalidateLogic, useForm, useStore } from "@tanstack/react-form";
import {
	queryOptions,
	useMutation,
	useQueryClient,
	useSuspenseQuery,
} from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { encode } from "uqr";
import { CopyButton } from "#/components/copy-button";
import { FormError, FormField, failed, saved } from "#/components/form";
import { ItemList } from "#/components/item-list";
import { Star } from "#/components/star";
import { Badge } from "#/components/ui/badge";
import { Button } from "#/components/ui/button";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogTitle,
} from "#/components/ui/dialog";
import { FieldGroup } from "#/components/ui/field";
import { Input } from "#/components/ui/input";
import {
	Item,
	ItemActions,
	ItemContent,
	ItemDescription,
	ItemTitle,
} from "#/components/ui/item";
import { UserAvatar } from "#/components/user-avatar";
import {
	bindSchema,
	deleteSchema,
	passkeyNameSchema,
	passwordSchema,
	providerReturn,
	type ReauthChoice,
	type ReauthMethod,
	reauthChoices,
	reauthMethods,
	reauthSchema,
	recoveryCodesText,
	totpSchema,
} from "#/lib/account";
import {
	APIError,
	api,
	forget,
	type Login,
	logout,
	type Me,
	type Session,
	type TOTPSetup,
} from "#/lib/account-api";
import { deviceLabel } from "#/lib/device";
import { loginLine } from "#/lib/logins";
import {
	type AssertionOptions,
	type CreationOptions,
	createPasskey,
	getPasskey,
	type Passkey,
	passkeySupported,
} from "#/lib/passkey";
import { kindName, primaryIdentifier } from "#/lib/users";
import { meQuery } from "#/routes/account/route";
import { ConfirmDialog } from "#/routes/console/-components/confirm-dialog";
import { Panel } from "#/routes/console/-components/panel";
import { DangerZone, Section } from "#/routes/console/-components/section";

export const Route = createFileRoute("/account/")({
	loader: ({ context }) =>
		context.queryClient
			.ensureQueryData(passkeysQuery)
			.then(() =>
				Promise.all([
					context.queryClient.ensureQueryData(sessionsQuery),
					context.queryClient.ensureQueryData(loginsQuery),
				]),
			),
	component: Account,
});

const sessionsQuery = queryOptions({
	queryKey: ["account", "sessions"],
	queryFn: () => api<{ sessions: Session[] }>("/sessions"),
});

const loginsQuery = queryOptions({
	queryKey: ["account", "logins"],
	queryFn: () => api<{ logins: Login[]; failedCount: number }>("/logins"),
});

const passkeysQuery = queryOptions({
	queryKey: ["account", "passkeys"],
	queryFn: () => api<{ passkeys: Passkey[] }>("/passkeys"),
});

const date = (s: string) => new Date(s).toLocaleString("zh-CN");

// Sensitive actions run once the User has authenticated in the last 10
// minutes; otherwise the reauthentication dialog comes first.
type Guard = (action: () => void) => void;

function Account() {
	// The page's own data: bindings and passwords change it in place.
	const user = useSuspenseQuery(meQuery).data;
	const queryClient = useQueryClient();
	const [pending, setPending] = useState<(() => void) | null>(null);
	const [deleted, setDeleted] = useState(false);
	// Back from a Provider: say how it went, once.
	useEffect(() => {
		const back = providerReturn(
			location.search,
			(id) => user.providers.find((p) => p.id === id)?.name ?? id,
		);
		if (!back) return;
		history.replaceState(null, "", location.pathname);
		if ("error" in back) toast.error(back.error);
		else toast.success(back.success);
	}, [user.providers]);

	if (deleted) {
		return (
			<main className="flex min-h-svh flex-col items-center justify-center gap-2 bg-canvas px-4 text-center">
				<h1 className="font-semibold text-2xl">账号已注销</h1>
				<p className="text-muted-foreground text-sm">
					你的数据已全部删除。同一个手机号或邮箱再次登录,将是一个新账号。
				</p>
			</main>
		);
	}
	const guard: Guard = (action) => {
		if (new Date(user.recentAuthUntil).getTime() - 5_000 > Date.now()) {
			action();
		} else {
			setPending(() => action);
		}
	};
	const main = primaryIdentifier(user.identifiers);

	return (
		<div className="min-h-svh bg-canvas p-2 text-sm sm:p-6">
			<Panel className="mx-auto max-w-2xl space-y-10 px-6 py-8 sm:px-14 sm:py-11">
				<div className="flex items-center gap-2 font-semibold">
					<Star className="size-5 text-star" />
					Polaris
				</div>
				<header className="flex items-center gap-4">
					<UserAvatar name={main} size="lg" />
					<div className="min-w-0">
						<h1 className="truncate font-semibold text-2xl tracking-tight">
							{main ?? user.sub}
						</h1>
						<p className="text-[13px] text-muted-foreground">
							注册于 {date(user.createdAt)}
						</p>
					</div>
					<Button variant="outline" className="ml-auto" onClick={logout}>
						退出登录
					</Button>
				</header>
				<LoginMethods me={user} guard={guard} />
				<Security me={user} guard={guard} />
				<Sessions />
				<RecentLogins />
				<Section title="数据与隐私">
					<ItemList>
						<Row
							label="导出我的数据"
							hint="登录方式、设备与会话、同意记录和与你相关的安全事件,JSON 格式"
						>
							<Button
								variant="outline"
								size="sm"
								onClick={() =>
									guard(() => exportData(user.sub).catch(failed("导出失败")))
								}
							>
								导出
							</Button>
						</Row>
					</ItemList>
				</Section>
				<DangerZone title="危险操作">
					<DeleteAccount guard={guard} onDeleted={() => setDeleted(true)} />
				</DangerZone>
			</Panel>
			<Reauth
				me={user}
				open={pending !== null}
				onClose={() => setPending(null)}
				onDone={async () => {
					await queryClient.invalidateQueries(meQuery);
					const action = pending;
					setPending(null);
					action?.();
				}}
			/>
		</div>
	);
}

async function exportData(sub: string) {
	const data = await api<unknown>("/export");
	saveFile(
		`polaris-${sub}.json`,
		new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }),
	);
}

// toProvider sends the browser to a Provider; it comes back to /account.
const toProvider = (id: string, action: "bind" | "reauth") =>
	api<{ url: string }>(`/providers/${id}/${action}`, { method: "POST" }).then(
		(r) => location.assign(r.url),
	);

// saveFile hands the browser a file to download.
function saveFile(name: string, blob: Blob) {
	const a = document.createElement("a");
	a.href = URL.createObjectURL(blob);
	a.download = name;
	a.click();
	URL.revokeObjectURL(a.href);
}

function LoginMethods({ me, guard }: { me: Me; guard: Guard }) {
	const queryClient = useQueryClient();
	const [editing, setEditing] = useState<"phone" | "email" | null>(null);
	const unbind = useMutation({
		mutationFn: (kind: string) =>
			api(`/identifiers/${kind}`, { method: "DELETE" }),
		onSuccess: () => queryClient.invalidateQueries(meQuery),
		onError: failed("解绑失败"),
	});
	const unbindProvider = useMutation({
		mutationFn: (id: string) => api(`/providers/${id}`, { method: "DELETE" }),
		onSuccess: () => queryClient.invalidateQueries(meQuery),
		onError: failed("解绑失败"),
	});
	const bindProvider = useMutation({
		mutationFn: (id: string) => toProvider(id, "bind"),
		onError: failed("绑定失败"),
	});
	const username = me.identifiers.find((i) => i.kind === "username");
	return (
		<Section title="登录方式">
			<ItemList>
				{(["phone", "email"] as const).map((kind) => {
					const id = me.identifiers.find((i) => i.kind === kind);
					return (
						<Row key={kind} label={kindName[kind]} hint={id?.value ?? "未绑定"}>
							{id ? (
								<>
									<Button
										variant="ghost"
										size="sm"
										onClick={() => guard(() => setEditing(kind))}
									>
										更换
									</Button>
									<Button
										variant="ghost"
										size="sm"
										disabled={unbind.isPending}
										onClick={() => guard(() => unbind.mutate(kind))}
									>
										解绑
									</Button>
								</>
							) : (
								<Button
									variant="outline"
									size="sm"
									onClick={() => guard(() => setEditing(kind))}
								>
									绑定
								</Button>
							)}
						</Row>
					);
				})}
				{username && (
					<Row label="用户名" hint={username.value}>
						{null}
					</Row>
				)}
				{me.externalIdentities.map((x) => (
					<Row
						key={x.provider}
						label={x.name}
						hint={`已绑定外部账号 · ${date(x.boundAt)}${x.enabled ? "" : " · 已停用"}`}
					>
						<Button
							variant="ghost"
							size="sm"
							disabled={unbindProvider.isPending}
							onClick={() => guard(() => unbindProvider.mutate(x.provider))}
						>
							解绑
						</Button>
					</Row>
				))}
				{me.providers
					.filter(
						(p) => !me.externalIdentities.some((x) => x.provider === p.id),
					)
					.map((p) => (
						<Row key={p.id} label={p.name} hint="未绑定外部账号">
							<Button
								variant="outline"
								size="sm"
								disabled={bindProvider.isPending}
								onClick={() => guard(() => bindProvider.mutate(p.id))}
							>
								绑定
							</Button>
						</Row>
					))}
			</ItemList>
			{editing && (
				<BindIdentifier kind={editing} onClose={() => setEditing(null)} />
			)}
		</Section>
	);
}

// BindIdentifier verifies a new phone number or email with a code and binds
// it in place of the User's.
function BindIdentifier({
	kind,
	onClose,
}: {
	kind: "phone" | "email";
	onClose: () => void;
}) {
	const queryClient = useQueryClient();
	const [sent, setSent] = useState(false);
	const send = useMutation({
		mutationFn: (value: string) =>
			api(`/identifiers/${kind}/code`, { method: "POST", body: { value } }),
		onSuccess: () => setSent(true),
	});
	const bind = useMutation({
		mutationFn: (v: { value: string; code: string }) =>
			api(`/identifiers/${kind}`, { method: "PUT", body: v }),
		onSuccess: async () => {
			await queryClient.invalidateQueries(meQuery);
			saved();
			onClose();
		},
	});
	const form = useForm({
		defaultValues: { value: "", code: "" },
		validationLogic: revalidateLogic(),
		validators: { onDynamic: bindSchema(kind, sent) },
		onSubmit: ({ value }) =>
			sent ? bind.mutate(value) : send.mutate(value.value),
	});
	return (
		<Dialog open onOpenChange={(open) => !open && onClose()}>
			<DialogContent>
				<DialogTitle>绑定新{kindName[kind]}</DialogTitle>
				<DialogDescription>
					验证码会发到新{kindName[kind]},无需验证原来的。
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
						<form.Field
							name="value"
							listeners={{ onChange: () => setSent(false) }}
						>
							{(field) => (
								<FormField field={field} label={`新${kindName[kind]}`}>
									{(control) => (
										<Input
											{...control}
											type={kind === "phone" ? "tel" : "email"}
											autoComplete={kind === "phone" ? "tel" : "email"}
											placeholder={kind === "phone" ? "+86 手机号" : "邮箱"}
										/>
									)}
								</FormField>
							)}
						</form.Field>
						{sent && (
							<form.Field name="code">
								{(field) => (
									<FormField field={field} label="验证码">
										{(control) => (
											<Input
												{...control}
												inputMode="numeric"
												autoComplete="one-time-code"
												placeholder="6 位验证码"
											/>
										)}
									</FormField>
								)}
							</form.Field>
						)}
					</FieldGroup>
					<FormError error={send.error ?? bind.error} />
					<div className="flex justify-end gap-2">
						{sent && (
							<Button
								type="button"
								variant="ghost"
								disabled={send.isPending}
								onClick={() => send.mutate(form.state.values.value)}
							>
								重新发送
							</Button>
						)}
						<Button type="submit" disabled={send.isPending || bind.isPending}>
							{sent ? "确认绑定" : "发送验证码"}
						</Button>
					</div>
				</form>
			</DialogContent>
		</Dialog>
	);
}

function Security({ me, guard }: { me: Me; guard: Guard }) {
	const queryClient = useQueryClient();
	const [editing, setEditing] = useState(false);
	const remove = useMutation({
		mutationFn: () => api("/password", { method: "DELETE" }),
		onSuccess: () => queryClient.invalidateQueries(meQuery),
		onError: failed("删除密码失败"),
	});
	return (
		<Section title="安全" id="passkeys">
			<ItemList>
				{me.passwordAllowed && (
					<Row
						label="密码"
						hint={
							me.hasPassword
								? "已设置,可配合手机号、邮箱或用户名登录"
								: "未设置;忘记密码时用验证码登录后在这里修改"
						}
					>
						{me.hasPassword && (
							<Button
								variant="ghost"
								size="sm"
								disabled={remove.isPending}
								onClick={() => guard(() => remove.mutate())}
							>
								删除
							</Button>
						)}
						<Button
							variant="outline"
							size="sm"
							onClick={() => guard(() => setEditing(true))}
						>
							{me.hasPassword ? "修改" : "设置"}
						</Button>
					</Row>
				)}
				{me.passkeyLogin && <Passkeys guard={guard} />}
				<TwoFactor me={me} guard={guard} />
			</ItemList>
			{editing && <SetPassword onClose={() => setEditing(false)} />}
		</Section>
	);
}

// Passkeys lists the User's Passkeys and adds one through the browser's
// system dialog; renaming is anyone's business, deleting a guarded one.
function Passkeys({ guard }: { guard: Guard }) {
	const queryClient = useQueryClient();
	const { passkeys } = useSuspenseQuery(passkeysQuery).data;
	const [renaming, setRenaming] = useState<Passkey | null>(null);
	const [deleting, setDeleting] = useState<Passkey | null>(null);
	const add = useMutation({
		mutationFn: async () => {
			const { options } = await api<{ options: CreationOptions }>(
				"/passkeys/options",
				{ method: "POST" },
			);
			return api("/passkeys", {
				method: "POST",
				body: await createPasskey(options),
			});
		},
		onSuccess: async () => {
			await queryClient.invalidateQueries(passkeysQuery);
			saved();
		},
		onError: failed("添加 Passkey 失败"),
	});
	const remove = useMutation({
		mutationFn: (id: string) => api(`/passkeys/${id}`, { method: "DELETE" }),
		onSuccess: () => queryClient.invalidateQueries(passkeysQuery),
		onError: failed("删除 Passkey 失败"),
	});
	return (
		<>
			{passkeys.map((p) => (
				<Row
					key={p.id}
					label={p.name}
					hint={`添加于 ${date(p.createdAt)} · ${
						p.lastUsedAt ? `最后使用 ${date(p.lastUsedAt)}` : "尚未使用"
					}`}
				>
					<Button variant="ghost" size="sm" onClick={() => setRenaming(p)}>
						重命名
					</Button>
					<Button
						variant="ghost"
						size="sm"
						disabled={remove.isPending}
						onClick={() => guard(() => setDeleting(p))}
					>
						删除
					</Button>
				</Row>
			))}
			{passkeySupported && (
				<Row label="Passkey" hint="在设备或密码管理器里各存一把,登录免验证码">
					<Button
						variant="outline"
						size="sm"
						disabled={add.isPending}
						onClick={() => guard(() => add.mutate())}
					>
						添加 Passkey
					</Button>
				</Row>
			)}
			{renaming && (
				<RenamePasskey passkey={renaming} onClose={() => setRenaming(null)} />
			)}
			<ConfirmDialog
				open={deleting !== null}
				onOpenChange={(open) => !open && setDeleting(null)}
				title="删除 Passkey?"
				action="删除"
				onConfirm={() => {
					if (deleting) remove.mutate(deleting.id);
					setDeleting(null);
				}}
			>
				删除后这把 Passkey 不能再用来登录;丢了设备时在这里删掉它。
			</ConfirmDialog>
		</>
	);
}

// RenamePasskey gives a Passkey a name its owner knows it by.
function RenamePasskey({
	passkey,
	onClose,
}: {
	passkey: Passkey;
	onClose: () => void;
}) {
	const queryClient = useQueryClient();
	const save = useMutation({
		mutationFn: (name: string) =>
			api(`/passkeys/${passkey.id}`, { method: "PATCH", body: { name } }),
		onSuccess: async () => {
			await queryClient.invalidateQueries(passkeysQuery);
			saved();
			onClose();
		},
	});
	const form = useForm({
		defaultValues: { name: passkey.name },
		validationLogic: revalidateLogic(),
		validators: { onDynamic: passkeyNameSchema },
		onSubmit: ({ value }) => save.mutate(value.name.trim()),
	});
	return (
		<Dialog open onOpenChange={(open) => !open && onClose()}>
			<DialogContent>
				<DialogTitle>重命名 Passkey</DialogTitle>
				<form
					noValidate
					className="space-y-3"
					onSubmit={(e) => {
						e.preventDefault();
						form.handleSubmit();
					}}
				>
					<form.Field name="name">
						{(field) => (
							<FormField field={field} label="名称">
								{(control) => (
									<Input {...control} placeholder="工作电脑" maxLength={64} />
								)}
							</FormField>
						)}
					</form.Field>
					<FormError error={save.error} />
					<div className="flex justify-end">
						<Button type="submit" disabled={save.isPending}>
							保存
						</Button>
					</div>
				</form>
			</DialogContent>
		</Dialog>
	);
}

// TwoFactor turns 两步验证 on and off and replaces the recovery codes.
function TwoFactor({ me, guard }: { me: Me; guard: Guard }) {
	const queryClient = useQueryClient();
	const [codes, setCodes] = useState<string[] | null>(null);
	const [disabling, setDisabling] = useState(false);
	const begin = useMutation({
		mutationFn: () => api<TOTPSetup>("/2fa/totp", { method: "POST" }),
		onError: failed("开启两步验证失败"),
	});
	const regenerate = useMutation({
		mutationFn: () =>
			api<{ recoveryCodes: string[] }>("/2fa/recovery-codes", {
				method: "POST",
			}),
		onSuccess: async (r) => {
			setCodes(r.recoveryCodes);
			await queryClient.invalidateQueries(meQuery);
		},
		onError: failed("重新生成恢复码失败"),
	});
	const disable = useMutation({
		mutationFn: () => api("/2fa", { method: "DELETE" }),
		onSuccess: () => queryClient.invalidateQueries(meQuery),
		onError: failed("关闭两步验证失败"),
	});
	const { enabled, recoveryCodesLeft } = me.twoFactor;
	return (
		<>
			<Row
				label="两步验证"
				hint={
					enabled
						? `已开启 · 剩余 ${recoveryCodesLeft} 个恢复码`
						: "未开启;开启后用验证码或密码登录时,还要输入验证器中的 6 位数字"
				}
			>
				{enabled ? (
					<>
						<Button
							variant="ghost"
							size="sm"
							disabled={regenerate.isPending}
							onClick={() => guard(() => regenerate.mutate())}
						>
							重新生成恢复码
						</Button>
						<Button
							variant="ghost"
							size="sm"
							disabled={disable.isPending}
							onClick={() => guard(() => setDisabling(true))}
						>
							关闭
						</Button>
					</>
				) : (
					<Button
						variant="outline"
						size="sm"
						disabled={begin.isPending}
						onClick={() => guard(() => begin.mutate())}
					>
						开启
					</Button>
				)}
			</Row>
			{begin.data && (
				<EnableTwoFactor
					setup={begin.data}
					onClose={() => begin.reset()}
					onEnabled={(codes) => {
						begin.reset();
						setCodes(codes);
					}}
				/>
			)}
			{codes && <RecoveryCodes codes={codes} onClose={() => setCodes(null)} />}
			<ConfirmDialog
				open={disabling}
				onOpenChange={setDisabling}
				title="关闭两步验证?"
				action="关闭两步验证"
				onConfirm={() => disable.mutate()}
			>
				验证器里的条目和全部恢复码都会作废,之后登录只需验证码或密码。其他设备不会下线。
			</ConfirmDialog>
		</>
	);
}

// EnableTwoFactor adds the new TOTP to an authenticator, by QR code or by
// copying the key, and turns 两步验证 on with one of its codes.
function EnableTwoFactor({
	setup,
	onClose,
	onEnabled,
}: {
	setup: TOTPSetup;
	onClose: () => void;
	onEnabled: (recoveryCodes: string[]) => void;
}) {
	const queryClient = useQueryClient();
	const confirm = useMutation({
		mutationFn: (code: string) =>
			api<{ recoveryCodes: string[] }>("/2fa/totp/confirm", {
				method: "POST",
				body: { code },
			}),
		onSuccess: async (r) => {
			await queryClient.invalidateQueries(meQuery);
			onEnabled(r.recoveryCodes);
		},
	});
	const form = useForm({
		defaultValues: { code: "" },
		validationLogic: revalidateLogic(),
		validators: { onDynamic: totpSchema },
		onSubmit: ({ value }) => confirm.mutate(value.code.trim()),
	});
	return (
		<Dialog open onOpenChange={(open) => !open && onClose()}>
			<DialogContent>
				<DialogTitle>开启两步验证</DialogTitle>
				<DialogDescription>
					用验证器 App 扫描二维码;密码管理器等不能扫码时,复制密钥手动添加。
				</DialogDescription>
				<QRCode value={setup.uri} className="mx-auto size-44" />
				<div className="flex items-center gap-2">
					<code className="min-w-0 flex-1 break-all rounded-md bg-muted px-2 py-1.5 font-mono text-xs">
						{setup.secret}
					</code>
					<CopyButton value={setup.secret} />
				</div>
				<form
					noValidate
					className="space-y-3"
					onSubmit={(e) => {
						e.preventDefault();
						form.handleSubmit();
					}}
				>
					<form.Field name="code">
						{(field) => (
							<FormField field={field} label="验证器中的 6 位数字">
								{(control) => (
									<Input
										{...control}
										inputMode="numeric"
										autoComplete="one-time-code"
										placeholder="123456"
									/>
								)}
							</FormField>
						)}
					</form.Field>
					<FormError error={confirm.error} />
					<div className="flex justify-end">
						<Button type="submit" disabled={confirm.isPending}>
							确认开启
						</Button>
					</div>
				</form>
			</DialogContent>
		</Dialog>
	);
}

// QRCode draws text as a QR code, dark on white whatever the theme, so
// any camera reads it.
function QRCode({ value, className }: { value: string; className?: string }) {
	const { data } = encode(value, { border: 2 });
	const d = data
		.flatMap((row, y) =>
			row.map((dark, x) => (dark ? `M${x} ${y}h1v1h-1z` : "")),
		)
		.join("");
	return (
		<svg
			viewBox={`0 0 ${data.length} ${data.length}`}
			className={className}
			role="img"
			aria-label="两步验证二维码"
			shapeRendering="crispEdges"
		>
			<rect width={data.length} height={data.length} fill="white" />
			<path d={d} fill="black" />
		</svg>
	);
}

// RecoveryCodes shows a new set of recovery codes, the only time they are
// shown.
function RecoveryCodes({
	codes,
	onClose,
}: {
	codes: string[];
	onClose: () => void;
}) {
	return (
		<Dialog open onOpenChange={(open) => !open && onClose()}>
			<DialogContent>
				<DialogTitle>保存恢复码</DialogTitle>
				<DialogDescription>
					丢了验证器时,每个恢复码可代替一次 6
					位数字,用过即作废。它们只显示这一次,请存到安全的地方。
				</DialogDescription>
				<ul className="grid grid-cols-2 gap-2 rounded-lg bg-muted p-4 text-center font-mono">
					{codes.map((c) => (
						<li key={c}>{c}</li>
					))}
				</ul>
				<div className="flex justify-end gap-2">
					<CopyButton value={codes.join("\n")} />
					<Button
						variant="outline"
						size="sm"
						onClick={() =>
							saveFile(
								"polaris-recovery-codes.txt",
								new Blob([recoveryCodesText(location.hostname, codes)], {
									type: "text/plain",
								}),
							)
						}
					>
						下载
					</Button>
					<Button size="sm" onClick={onClose}>
						我已保存
					</Button>
				</div>
			</DialogContent>
		</Dialog>
	);
}

function SetPassword({ onClose }: { onClose: () => void }) {
	const queryClient = useQueryClient();
	const save = useMutation({
		mutationFn: (password: string) =>
			api("/password", { method: "PUT", body: { password } }),
		onSuccess: async () => {
			await queryClient.invalidateQueries(meQuery);
			saved();
			onClose();
		},
	});
	const form = useForm({
		defaultValues: { password: "" },
		validationLogic: revalidateLogic(),
		validators: { onDynamic: passwordSchema },
		onSubmit: ({ value }) => save.mutate(value.password),
	});
	return (
		<Dialog open onOpenChange={(open) => !open && onClose()}>
			<DialogContent>
				<DialogTitle>设置密码</DialogTitle>
				<form
					noValidate
					className="space-y-3"
					onSubmit={(e) => {
						e.preventDefault();
						form.handleSubmit();
					}}
				>
					<form.Field name="password">
						{(field) => (
							<FormField field={field} label="新密码">
								{(control) => (
									<Input
										{...control}
										type="password"
										autoComplete="new-password"
										placeholder="至少 8 位"
									/>
								)}
							</FormField>
						)}
					</form.Field>
					<FormError error={save.error} />
					<div className="flex justify-end">
						<Button type="submit" disabled={save.isPending}>
							保存
						</Button>
					</div>
				</form>
			</DialogContent>
		</Dialog>
	);
}

function Sessions() {
	const queryClient = useQueryClient();
	const { sessions } = useSuspenseQuery(sessionsQuery).data;
	const end = useMutation({
		mutationFn: (id: string) => api(`/sessions/${id}`, { method: "DELETE" }),
		onSuccess: () => queryClient.invalidateQueries(sessionsQuery),
		onError: failed("下线失败"),
	});
	// The one action for a lost device: this browser stays signed in.
	const others = sessions.filter((s) => s.active && !s.current);
	const endOthers = useMutation({
		mutationFn: () =>
			Promise.all(
				others.map((s) => api(`/sessions/${s.id}`, { method: "DELETE" })),
			),
		onSettled: () => queryClient.invalidateQueries(sessionsQuery),
		onSuccess: () => toast.success("其他设备已下线"),
		onError: failed("下线失败"),
	});
	return (
		<Section
			title="设备与会话"
			id="sessions"
			intro="不限设备数,可逐个下线或一次下线其他设备;已结束的保留 30 天"
		>
			{others.length > 0 && (
				<div className="mb-3 flex justify-end">
					<ConfirmDialog
						trigger={
							<Button
								variant="outline"
								size="sm"
								disabled={endOthers.isPending}
							>
								下线其他设备
							</Button>
						}
						title="下线其他设备?"
						action="下线其他设备"
						onConfirm={() => endOthers.mutate()}
					>
						其他设备上的会话立即结束，需要重新登录；本设备不受影响。
					</ConfirmDialog>
				</div>
			)}
			<ItemList>
				{sessions.map((s) => (
					<Row
						key={s.id}
						label={
							<span className="flex items-center gap-2">
								{deviceLabel(s.userAgent)} · {s.application}
								{s.current && <Badge>本设备</Badge>}
								{!s.active && <Badge variant="secondary">已结束</Badge>}
							</span>
						}
						hint={[
							s.ip,
							`登录于 ${date(s.authTime)}`,
							`最近活动 ${date(s.lastSeenAt)}`,
						]
							.filter(Boolean)
							.join(" · ")}
					>
						{s.active && !s.current && (
							<Button
								variant="ghost"
								size="sm"
								disabled={end.isPending}
								onClick={() => end.mutate(s.id)}
							>
								下线
							</Button>
						)}
					</Row>
				))}
			</ItemList>
		</Section>
	);
}

// RecentLogins is the User's own login history: no actions per row, only a
// pointer to the password and to signing other devices out.
function RecentLogins() {
	const { logins, failedCount } = useSuspenseQuery(loginsQuery).data;
	return (
		<Section
			title="最近登录"
			intro={
				failedCount > 0
					? `过去 30 天有 ${failedCount} 次登录失败`
					: "过去 30 天的登录,最多 50 条"
			}
		>
			{logins.length === 0 ? (
				<p className="text-muted-foreground">过去 30 天没有登录记录</p>
			) : (
				<ItemList>
					{logins.map((l, i) => {
						const line = loginLine(l);
						return (
							<Row
								// biome-ignore lint/suspicious/noArrayIndexKey: events carry no id; the list is never reordered
								key={i}
								label={
									<span className="flex items-center gap-2">
										{line.what} · {l.application}
										<Badge
											variant={
												l.result === "succeeded" ? "secondary" : "destructive"
											}
										>
											{line.result}
										</Badge>
									</span>
								}
								hint={`${date(l.at)} · ${line.device}`}
							>
								{null}
							</Row>
						);
					})}
				</ItemList>
			)}
			<p className="mt-3 text-[13px] text-muted-foreground">
				有不认识的登录?
				<a className="underline" href="#passkeys">
					修改密码
				</a>
				,并在上方
				<a className="underline" href="#sessions">
					下线其他设备
				</a>
			</p>
		</Section>
	);
}

function DeleteAccount({
	guard,
	onDeleted,
}: {
	guard: Guard;
	onDeleted: () => void;
}) {
	const [open, setOpen] = useState(false);
	const remove = useMutation({
		mutationFn: () => api("/me", { method: "DELETE" }),
		onSuccess: () => {
			forget();
			onDeleted();
		},
	});
	const form = useForm({
		defaultValues: { confirm: "" },
		validationLogic: revalidateLogic(),
		validators: { onDynamic: deleteSchema },
		onSubmit: () => remove.mutate(),
	});
	const confirmed = useStore(
		form.store,
		(s) => s.values.confirm.trim() === "注销",
	);
	return (
		<>
			<Row label="注销账号" hint="立即生效,不可恢复">
				<Button
					variant="destructive"
					size="sm"
					onClick={() => guard(() => setOpen(true))}
				>
					注销
				</Button>
			</Row>
			<Dialog open={open} onOpenChange={setOpen}>
				<DialogContent>
					<DialogTitle>注销账号</DialogTitle>
					<DialogDescription>
						立即生效,没有冷静期:所有登录方式、设备和数据都会被删除,各应用会收到通知。此操作不可恢复。
					</DialogDescription>
					<form
						noValidate
						className="space-y-3"
						onSubmit={(e) => {
							e.preventDefault();
							form.handleSubmit();
						}}
					>
						<form.Field name="confirm">
							{(field) => (
								<FormField field={field} label="输入「注销」确认">
									{(control) => <Input {...control} placeholder="注销" />}
								</FormField>
							)}
						</form.Field>
						<FormError error={remove.error} />
						<div className="flex justify-end gap-2">
							<Button
								type="button"
								variant="outline"
								onClick={() => setOpen(false)}
							>
								取消
							</Button>
							<Button
								type="submit"
								variant="destructive"
								disabled={!confirmed || remove.isPending}
							>
								永久注销
							</Button>
						</div>
					</form>
				</DialogContent>
			</Dialog>
		</>
	);
}

// Reauth proves the User again with a Passkey, a code to one of their
// Identifiers, their password, or — with 两步验证 on — a TOTP or recovery
// code.
function Reauth({
	me,
	open,
	onClose,
	onDone,
}: {
	me: Me;
	open: boolean;
	onClose: () => void;
	onDone: () => void;
}) {
	// A Passkey's options name this User's Passkeys; there is one to offer
	// only once the account center has loaded them.
	const hasPasskey = useSuspenseQuery(passkeysQuery).data.passkeys.length > 0;
	const twoFactor = me.twoFactor.enabled;
	const choices = reauthChoices(me, hasPasskey, passkeySupported);
	// A Provider the User bound signs them in afresh, without 两步验证.
	const viaProvider = twoFactor
		? []
		: me.externalIdentities.filter((x) => x.enabled);
	const leave = useMutation({
		mutationFn: (id: string) => toProvider(id, "reauth"),
	});
	const [method, setMethod] = useState<ReauthChoice | undefined>();
	const current =
		method && (choices.includes(method) || (twoFactor && method === "recovery"))
			? method
			: choices[0];
	const byPasskey = current === "passkey";
	// The method whose secret the form checks, where there is one; the
	// Passkey branch never reads it.
	const secretMethod: ReauthMethod =
		current && current !== "passkey" ? current : "password";
	const byCode = current === "phone" || current === "email";
	const [sent, setSent] = useState(false);
	const pick = (m: ReauthChoice) => {
		setMethod(m);
		setSent(false);
		form.reset();
	};
	const send = useMutation({
		mutationFn: () =>
			api("/reauth/code", { method: "POST", body: { kind: current } }),
		onSuccess: () => setSent(true),
	});
	const verify = useMutation({
		mutationFn: (secret: string) =>
			api("/reauth", {
				method: "POST",
				body: reauthMethods[secretMethod].body(secret),
			}),
		onSuccess: () => {
			form.reset();
			setSent(false);
			onDone();
		},
	});
	// The Passkey ceremony: options naming the User's own Passkeys, then the
	// assertion the API checks.
	const authenticate = useMutation({
		mutationFn: async () => {
			const { options } = await api<{ options: AssertionOptions }>(
				"/reauth/passkey",
				{ method: "POST" },
			);
			const assertion = await getPasskey(options);
			return api("/reauth", {
				method: "POST",
				body: { passkey: JSON.stringify(assertion) },
			});
		},
		onSuccess: onDone,
	});
	const form = useForm({
		defaultValues: { secret: "" },
		validationLogic: revalidateLogic(),
		validators: {
			onDynamic: reauthSchema(secretMethod, sent),
		},
		onSubmit: ({ value }) =>
			byCode && !sent ? send.mutate() : verify.mutate(value.secret),
	});
	const error = send.error ?? verify.error ?? authenticate.error ?? leave.error;
	const target = me.identifiers.find((i) => i.kind === current)?.value;
	return (
		<Dialog open={open} onOpenChange={(o) => !o && onClose()}>
			<DialogContent>
				<DialogTitle>请重新验证身份</DialogTitle>
				<DialogDescription>
					换绑、解绑、两步验证、导出和注销,须在 10 分钟内验证过身份。
				</DialogDescription>
				{choices.length > 1 && (
					<div className="flex flex-wrap gap-2">
						{choices.map((m) => (
							<Button
								key={m}
								size="sm"
								variant={m === current ? "secondary" : "ghost"}
								onClick={() => pick(m)}
							>
								{choiceLabel(m)}
							</Button>
						))}
					</div>
				)}
				{current === undefined ? (
					viaProvider.length === 0 && <p>没有可用的验证方式,请联系管理员。</p>
				) : byPasskey ? (
					<div className="space-y-3">
						<p className="text-muted-foreground">
							用这台设备或密码管理器里的 Passkey 验证一下。
						</p>
						<FormError error={error} />
						<Button
							type="button"
							disabled={authenticate.isPending}
							onClick={() => authenticate.mutate()}
						>
							使用 Passkey 验证
						</Button>
					</div>
				) : (
					<form
						noValidate
						className="space-y-3"
						onSubmit={(e) => {
							e.preventDefault();
							form.handleSubmit();
						}}
					>
						{byCode && (
							<p className="text-muted-foreground">验证码将发送到 {target}</p>
						)}
						{(!byCode || sent) && (
							<form.Field name="secret">
								{(field) => (
									<FormField
										field={field}
										label={reauthMethods[secretMethod].label}
									>
										{(control) => (
											<Input
												{...control}
												{...reauthMethods[secretMethod].input}
											/>
										)}
									</FormField>
								)}
							</form.Field>
						)}
						<FormError
							error={
								error instanceof APIError && error.status === 403
									? new Error("请重新验证")
									: error
							}
						/>
						<div className="flex justify-end gap-2">
							{twoFactor && (
								<Button
									type="button"
									variant="ghost"
									onClick={() => pick(current === "totp" ? "recovery" : "totp")}
								>
									{current === "totp" ? "使用恢复码" : "使用验证器"}
								</Button>
							)}
							<Button
								type="submit"
								disabled={send.isPending || verify.isPending}
							>
								{byCode && !sent ? "发送验证码" : "验证"}
							</Button>
						</div>
					</form>
				)}
				{viaProvider.length > 0 && (
					<div className="flex flex-wrap gap-2">
						{viaProvider.map((x) => (
							<Button
								key={x.provider}
								variant="outline"
								size="sm"
								disabled={leave.isPending}
								onClick={() => leave.mutate(x.provider)}
							>
								用 {x.name} 验证
							</Button>
						))}
					</div>
				)}
				{current === undefined && <FormError error={leave.error} />}
			</DialogContent>
		</Dialog>
	);
}

// choiceLabel is a reauthentication choice's button text.
function choiceLabel(m: ReauthChoice): string {
	switch (m) {
		case "passkey":
			return "Passkey";
		case "phone":
		case "email":
			return `${kindName[m]}验证码`;
		case "totp":
			return "验证器";
		case "recovery":
			return "恢复码";
		default:
			return "密码";
	}
}

function Row({
	label,
	hint,
	children,
}: {
	label: React.ReactNode;
	hint?: string;
	children: React.ReactNode;
}) {
	return (
		<Item>
			<ItemContent className="min-w-0">
				<ItemTitle className="font-normal">{label}</ItemTitle>
				{hint && (
					<ItemDescription className="truncate text-[13px]">
						{hint}
					</ItemDescription>
				)}
			</ItemContent>
			<ItemActions className="shrink-0 gap-1">{children}</ItemActions>
		</Item>
	);
}
