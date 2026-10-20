import { revalidateLogic, useForm } from "@tanstack/react-form";
import {
	queryOptions,
	type UseMutationResult,
	useMutation,
	useQueryClient,
	useSuspenseQuery,
} from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { type ReactNode, useState } from "react";
import { FormError, FormField, failed, saved } from "#/components/form";
import { ItemList } from "#/components/item-list";
import { Alert, AlertDescription } from "#/components/ui/alert";
import { Button } from "#/components/ui/button";
import { FieldGroup } from "#/components/ui/field";
import { Input } from "#/components/ui/input";
import {
	Item,
	ItemContent,
	ItemDescription,
	ItemTitle,
} from "#/components/ui/item";
import {
	Select,
	SelectContent,
	SelectItem,
	SelectTrigger,
	SelectValue,
} from "#/components/ui/select";
import { Separator } from "#/components/ui/separator";
import {
	api,
	type ChannelPlugin,
	type ChannelSettings,
} from "#/lib/console-api";
import {
	channelSchema,
	sendsNothing,
	smsLocked,
	testSchema,
} from "#/lib/login";
import { ConfirmDialog } from "#/routes/console/-components/confirm-dialog";
import { SectionHeading } from "#/routes/console/-components/section";
import { useCan } from "#/routes/console/route";
import { PolicyNumber, usePolicy } from "./policy";

export const channelsQuery = queryOptions({
	queryKey: ["channels"],
	queryFn: () =>
		api<{ plugins: ChannelPlugin[]; channels: ChannelSettings[] }>("/channels"),
});

// ChannelsLink leads to the 通道 Tab from a hint that needs a channel.
export function ChannelsLink({
	children = "去设置通道",
}: {
	children?: ReactNode;
}) {
	return (
		<Link to="/console/settings" search={{ tab: "channels" }}>
			{children}
		</Link>
	);
}

// lose is what users can't do while the kind has no channel.
const kinds = [
	{
		kind: "phone",
		label: "短信",
		placeholder: "+8613800001111",
		lose: "用户不能用手机号收验证码登录，也不能绑定手机号。",
	},
	{
		kind: "email",
		label: "邮件",
		placeholder: "you@example.com",
		lose: "用户不能用邮箱收验证码登录。",
	},
] as const;

const date = (s: string) => new Date(s).toLocaleString("zh-CN");

export function ChannelsTab() {
	return (
		<div className="space-y-10">
			<Channels />
			<PolicyNumber
				title="每日发送上限"
				field="dailySendLimit"
				label="每天最多发送"
				suffix="条"
				help="认证服务每天最多发出这么多条验证码，防止短信被盗刷。达到上限后，当天不再发送。"
				min={0}
				warning={(n) =>
					sendsNothing(n) && (
						<Alert variant="warning">
							<AlertDescription>
								设为 0 后所有验证码都不再发送，包括登录和绑定手机号。
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
				intro="认证服务通过它们把验证码发到手机号或邮箱。短信和邮件各启用一个服务商。"
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
	const [pluginKey, setPluginKey] = useState(current?.plugin ?? "");
	const plugin = plugins.find((p) => p.key === pluginKey);
	// Stored values belong to the stored plugin only.
	const stored = current?.plugin === pluginKey ? current : undefined;
	const refresh = () => client.invalidateQueries({ queryKey: ["channels"] });

	const save = useMutation({
		mutationFn: (config: Record<string, string>) =>
			api(`/channels/${kind}`, {
				method: "PUT",
				body: { plugin: pluginKey, config },
			}),
		onSuccess: refresh,
	});
	const remove = useMutation({
		mutationFn: () => api(`/channels/${kind}`, { method: "DELETE" }),
		onSuccess: () => {
			setPluginKey("");
			return refresh();
		},
		onError: failed(`停用${label}通道失败`),
	});

	const stopButton = (
		<Button type="button" variant="outline" disabled={remove.isPending}>
			停用
		</Button>
	);
	return (
		<Item className="flex-col items-stretch gap-4 py-6">
			<ItemContent>
				<ItemTitle>
					{label}
					<span className="font-normal text-muted-foreground text-xs">
						{current ? `已启用 · 更新于 ${date(current.updatedAt)}` : "未启用"}
					</span>
				</ItemTitle>
				<ItemDescription className="text-[13px]">
					没开启时，{lose}
				</ItemDescription>
			</ItemContent>
			<div>
				<Select
					value={pluginKey}
					disabled={!editable}
					onValueChange={(v) => {
						setPluginKey(`${v ?? ""}`);
						save.reset();
					}}
				>
					<SelectTrigger className="w-48" aria-label={`${label}服务商`}>
						<SelectValue>
							{(v: string) =>
								plugins.find((p) => p.key === v)?.name ?? "选择服务商"
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
			</div>

			{plugin && (
				<ConfigForm
					key={`${pluginKey}-${current?.updatedAt}`}
					kind={kind}
					plugin={plugin}
					stored={stored}
					editable={editable}
					save={save}
					submit={current && !stored ? "切换并保存" : "保存"}
				>
					{current &&
						(needed ? (
							<ConfirmDialog trigger={stopButton} title={`停用${label}通道？`}>
								先在登录方式里关闭必须绑定手机号。开着它时停用短信，没有手机号的用户收不到绑定验证码，就登录不进来。{" "}
								<Link to="/console/settings" className="underline">
									去登录方式
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
						))}
				</ConfigForm>
			)}

			{editable && current && (
				<TestForm kind={kind} placeholder={placeholder} />
			)}
		</Item>
	);
}

// ConfigForm edits the chosen plugin's fields. A secret already set shows
// empty and stays as it is unless retyped.
function ConfigForm({
	kind,
	plugin,
	stored,
	editable,
	save,
	submit,
	children,
}: {
	kind: "phone" | "email";
	plugin: ChannelPlugin;
	stored?: ChannelSettings;
	editable: boolean;
	save: UseMutationResult<unknown, Error, Record<string, string>>;
	submit: string;
	children: ReactNode;
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
				{ onSuccess: saved },
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
											disabled={!editable}
											placeholder={
												setAt ? `已设置 · 更新于 ${date(setAt)},留空不修改` : ""
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
			{editable && (
				<div className="flex gap-2">
					<Button type="submit" disabled={save.isPending}>
						{submit}
					</Button>
					{children}
				</div>
			)}
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
		<>
			<Separator className="my-4" />
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
						<FormField field={field} label="发送测试验证码到">
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
										发送测试验证码
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
						,请核对收到的验证码
					</p>
				)}
			</form>
		</>
	);
}
