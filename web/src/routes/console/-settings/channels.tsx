import { revalidateLogic, useForm } from "@tanstack/react-form";
import {
	type UseMutationResult,
	useMutation,
	useQueryClient,
	useSuspenseQuery,
} from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { type ReactNode, useState } from "react";
import { FormError, FormField, failed, saved } from "#/components/form";
import { ItemList, PropRow } from "#/components/item-list";
import { Alert, AlertDescription } from "#/components/ui/alert";
import { Button } from "#/components/ui/button";
import { Dialog, DialogContent, DialogTitle } from "#/components/ui/dialog";
import { FieldGroup } from "#/components/ui/field";
import { Input } from "#/components/ui/input";
import {
	Select,
	SelectContent,
	SelectItem,
	SelectTrigger,
	SelectValue,
} from "#/components/ui/select";
import {
	api,
	type ChannelPlugin,
	type ChannelSettings,
} from "#/lib/console-api";
import { channelSchema, smsLocked, testSchema } from "#/lib/login";
import { channelsQuery } from "#/lib/queries";
import { ConfirmDialog } from "#/routes/console/-components/confirm-dialog";
import { FormSheet } from "#/routes/console/-components/form-sheet";
import { SectionHeading } from "#/routes/console/-components/section";
import { useCan } from "#/routes/console/route";
import { PolicyNumber, usePolicy } from "./policy";

// ChannelsLink leads to the 通道 Tab from a hint that needs a channel.
export function ChannelsLink({
	children = "设置验证码通道",
}: {
	children?: ReactNode;
}) {
	return <Link to="/console/channels">{children}</Link>;
}

// lose is what users can't do while the kind has no channel.
const kinds = [
	{
		kind: "phone",
		label: "短信",
		placeholder: "+8613800001111",
		lose: "用户无法使用手机号验证码登录，也无法绑定手机号。",
	},
	{
		kind: "email",
		label: "邮件",
		placeholder: "you@example.com",
		lose: "用户无法使用邮箱验证码登录。",
	},
] as const;

const date = (s: string) => new Date(s).toLocaleString("zh-CN");

export function ChannelsTab() {
	return (
		<div className="space-y-4">
			<Channels />
			<PolicyNumber
				title="每日发送上限"
				field="dailySendLimit"
				label="每天最多发送"
				suffix="条"
				help="达到上限后当天停止发送验证码。"
				min={0}
				warning={(plan) =>
					plan.warn.sendsNothing && (
						<Alert variant="warning">
							<AlertDescription>
								设为 0 将停止发送所有验证码，包括登录和绑定手机号。
							</AlertDescription>
						</Alert>
					)
				}
			/>
		</div>
	);
}

function Channels() {
	const { plugins, channels } = useSuspenseQuery(channelsQuery).data;
	return (
		<section>
			<SectionHeading
				title="验证码通道"
				intro="用于发送短信和邮件验证码，各启用一个供应商。"
			/>
			<div className="mt-4">
				<ItemList>
					{kinds.map((k) => (
						<Channel
							key={k.kind}
							{...k}
							plugins={plugins.filter((p) => p.kinds.includes(k.kind))}
							current={channels.find((c) => c.kind === k.kind)}
						/>
					))}
				</ItemList>
			</div>
		</section>
	);
}

function Channel({
	kind,
	label,
	placeholder,
	lose,
	plugins,
	current,
}: {
	kind: "phone" | "email";
	label: string;
	placeholder: string;
	lose: string;
	plugins: ChannelPlugin[];
	current?: ChannelSettings;
}) {
	const can = useCan();
	const editable = can("config:write");
	const { policy } = usePolicy();
	// Until the policy loads, assume the lock so SMS can't slip out.
	const needed = smsLocked(kind, policy.requirePhone);
	const client = useQueryClient();
	const [editing, setEditing] = useState(false);
	const [testing, setTesting] = useState(false);
	const remove = useMutation({
		mutationFn: () => api(`/channels/${kind}`, { method: "DELETE" }),
		onSuccess: () => client.invalidateQueries(channelsQuery),
		onError: failed(`停用${label}通道失败`),
	});
	const pluginName = plugins.find((p) => p.key === current?.plugin)?.name;

	const stopButton = (
		<Button type="button" variant="ghost" size="sm" disabled={remove.isPending}>
			停用
		</Button>
	);
	return (
		<>
			<PropRow
				label={label}
				hint={
					current ? `更新于 ${date(current.updatedAt)}` : `未启用时，${lose}`
				}
				actions={
					editable &&
					(current ? (
						<>
							<Button
								variant="ghost"
								size="sm"
								onClick={() => setEditing(true)}
							>
								编辑
							</Button>
							<Button
								variant="ghost"
								size="sm"
								onClick={() => setTesting(true)}
							>
								发送测试
							</Button>
							{needed ? (
								<ConfirmDialog
									trigger={stopButton}
									title={`停用${label}通道？`}
								>
									需先在登录方式中关闭「必须绑定手机号」，否则停用短信后，没有手机号的用户将无法登录。{" "}
									<Link to="/console/sign-in" className="underline">
										前往登录方式
									</Link>
								</ConfirmDialog>
							) : (
								<ConfirmDialog
									trigger={stopButton}
									title={`停用${label}通道？`}
									action={`停用${label}通道`}
									onConfirm={() => remove.mutate()}
								>
									停用后，{lose}
								</ConfirmDialog>
							)}
						</>
					) : (
						<Button
							variant="outline"
							size="sm"
							onClick={() => setEditing(true)}
						>
							启用
						</Button>
					))
				}
			>
				<span className="text-sm">
					{current ? `已启用 · ${pluginName ?? current.plugin}` : "未启用"}
				</span>
			</PropRow>
			<FormSheet
				open={editing}
				onOpenChange={setEditing}
				title={`${current ? "编辑" : "启用"}${label}通道`}
			>
				<ChannelForm
					kind={kind}
					label={label}
					plugins={plugins}
					current={current}
					onSaved={() => setEditing(false)}
				/>
			</FormSheet>
			{testing && (
				<Dialog open onOpenChange={setTesting}>
					<DialogContent>
						<DialogTitle>发送测试验证码</DialogTitle>
						<TestForm kind={kind} placeholder={placeholder} />
					</DialogContent>
				</Dialog>
			)}
		</>
	);
}

// ChannelForm picks the plugin and edits its config. The sheet mounts it
// afresh on each open, so it starts from what's stored.
function ChannelForm({
	kind,
	label,
	plugins,
	current,
	onSaved,
}: {
	kind: "phone" | "email";
	label: string;
	plugins: ChannelPlugin[];
	current?: ChannelSettings;
	onSaved: () => void;
}) {
	const client = useQueryClient();
	const [pluginKey, setPluginKey] = useState(current?.plugin ?? "");
	const plugin = plugins.find((p) => p.key === pluginKey);
	// Stored values belong to the stored plugin only.
	const stored = current?.plugin === pluginKey ? current : undefined;
	const save = useMutation({
		mutationFn: (config: Record<string, string>) =>
			api(`/channels/${kind}`, {
				method: "PUT",
				body: { plugin: pluginKey, config },
			}),
		onSuccess: () => {
			// Toast here, not in mutate(): the form unmounts as the sheet closes.
			saved();
			onSaved();
			return client.invalidateQueries(channelsQuery);
		},
	});
	return (
		<div className="space-y-4">
			<Select
				value={pluginKey}
				onValueChange={(v) => {
					setPluginKey(`${v ?? ""}`);
					save.reset();
				}}
			>
				<SelectTrigger className="w-48" aria-label={`${label}供应商`}>
					<SelectValue>
						{(v: string) =>
							plugins.find((p) => p.key === v)?.name ?? "选择供应商"
						}
					</SelectValue>
				</SelectTrigger>
				<SelectContent>
					{plugins.map((p) => (
						<SelectItem key={p.key} value={p.key}>
							{p.name}
						</SelectItem>
					))}
				</SelectContent>
			</Select>
			{plugin && (
				<ConfigForm
					key={pluginKey}
					kind={kind}
					plugin={plugin}
					stored={stored}
					save={save}
					submit={current && !stored ? "切换并保存" : "保存"}
				/>
			)}
		</div>
	);
}

// ConfigForm edits the chosen plugin's fields. A secret already set shows
// empty and stays as it is unless retyped.
function ConfigForm({
	kind,
	plugin,
	stored,
	save,
	submit,
}: {
	kind: "phone" | "email";
	plugin: ChannelPlugin;
	stored?: ChannelSettings;
	save: UseMutationResult<unknown, Error, Record<string, string>>;
	submit: string;
}) {
	const form = useForm({
		defaultValues: Object.fromEntries(
			plugin.fields.map((f) => [
				f.key,
				f.secret ? "" : (stored?.config[f.key] ?? ""),
			]),
		),
		validationLogic: revalidateLogic(),
		validators: {
			onDynamic: channelSchema(plugin.fields, stored?.secrets ?? {}),
		},
		onSubmit: ({ value }) =>
			save.mutate(
				Object.fromEntries(
					Object.entries(value).map(([k, v]) => [k, v.trim()]),
				),
			),
	});
	return (
		<form
			noValidate
			className="space-y-4"
			onSubmit={(e) => {
				e.preventDefault();
				form.handleSubmit();
			}}
		>
			<FieldGroup className="gap-4">
				{plugin.fields.map((f) => {
					const setAt = stored?.secrets[f.key];
					return (
						<form.Field key={`${kind}-${f.key}`} name={f.key}>
							{(field) => (
								<FormField
									field={field}
									label={f.label}
									en={f.optional ? "选填" : undefined}
									help={f.help}
								>
									{(control) => (
										<Input
											{...control}
											type={f.secret ? "password" : f.type}
											autoComplete={f.secret ? "new-password" : "off"}
											placeholder={
												setAt
													? `已设置 · 更新于 ${date(setAt)}，留空不修改`
													: ""
											}
										/>
									)}
								</FormField>
							)}
						</form.Field>
					);
				})}
			</FieldGroup>
			<FormError error={save.error} />
			<Button type="submit" disabled={save.isPending}>
				{submit}
			</Button>
		</form>
	);
}

// TestForm sends a test code through the enabled channel.
function TestForm({
	kind,
	placeholder,
}: {
	kind: "phone" | "email";
	placeholder: string;
}) {
	const test = useMutation({
		mutationFn: (to: string) =>
			api<{ code: string }>(`/channels/${kind}/test`, {
				method: "POST",
				body: { to },
			}),
	});
	const form = useForm({
		defaultValues: { to: "" },
		validationLogic: revalidateLogic(),
		validators: { onDynamic: testSchema(kind) },
		onSubmit: ({ value }) => test.mutate(value.to.trim()),
	});
	return (
		<form
			noValidate
			className="flex flex-col gap-2"
			onSubmit={(e) => {
				e.preventDefault();
				form.handleSubmit();
			}}
		>
			<form.Field name="to">
				{(field) => (
					<FormField field={field} label="发送到">
						{(control) => (
							<div className="flex flex-wrap items-center gap-2">
								<Input
									{...control}
									type={kind === "email" ? "email" : "tel"}
									placeholder={placeholder}
									className="w-64"
								/>
								<Button
									type="submit"
									variant="outline"
									disabled={test.isPending}
								>
									发送
								</Button>
							</div>
						)}
					</FormField>
				)}
			</form.Field>
			<FormError error={test.error} />
			{test.data && (
				<p className="text-sm">
					已发送 <span className="font-mono">{test.data.code}</span>
					，请核对收到的验证码
				</p>
			)}
		</form>
	);
}
