import { revalidateLogic, useForm, useStore } from "@tanstack/react-form";
import {
	queryOptions,
	useMutation,
	useQuery,
	useQueryClient,
	useSuspenseQuery,
} from "@tanstack/react-query";
import {
	createFileRoute,
	Link,
	notFound,
	stripSearchParams,
	useBlocker,
	useNavigate,
	useParams,
	useSearch,
} from "@tanstack/react-router";
import { Check, ChevronRight } from "lucide-react";
import { type ReactNode, useEffect, useState } from "react";
import { z } from "zod";
import { CopyButton } from "#/components/copy-button";
import { FormField, failed, saved } from "#/components/form";
import { ItemList, PropRow } from "#/components/item-list";
import { Alert, AlertDescription } from "#/components/ui/alert";
import { Badge } from "#/components/ui/badge";
import { Button } from "#/components/ui/button";
import { Checkbox } from "#/components/ui/checkbox";
import {
	Collapsible,
	CollapsibleContent,
	CollapsibleTrigger,
} from "#/components/ui/collapsible";
import {
	Field,
	FieldContent,
	FieldDescription,
	FieldLabel,
	FieldLegend,
	FieldSet,
	FieldTitle,
} from "#/components/ui/field";
import { Input } from "#/components/ui/input";
import { Label } from "#/components/ui/label";
import { RadioGroup, RadioGroupItem } from "#/components/ui/radio-group";
import {
	Select,
	SelectContent,
	SelectItem,
	SelectTrigger,
	SelectValue,
} from "#/components/ui/select";
import { Slider } from "#/components/ui/slider";
import { Switch } from "#/components/ui/switch";
import { TabsContent } from "#/components/ui/tabs";
import { Textarea } from "#/components/ui/textarea";
import {
	androidApps,
	androidLines,
	backchannelSchema,
	basicSchema,
	jwksSchema,
	jwksText,
	loginSchema,
	m2mAPIs,
	nativeSchema,
	typeName,
	typeWhy,
	webhookSchema,
} from "#/lib/apps";
import {
	type Application,
	type ApplicationRoles,
	api,
	type LoginMethod,
	type TokenAuthMethod,
} from "#/lib/console-api";
import {
	checklist,
	lines,
	newSecrets,
	type Platform,
	platformKeys,
	snippet,
} from "#/lib/onboarding";
import {
	applicationsQuery,
	patchApplication,
	useSaveApplication,
} from "#/lib/queries";
import { managementAPI } from "#/lib/users";
import { BrandSection } from "#/routes/console/-components/brand-section";
import { ConfirmDialog } from "#/routes/console/-components/confirm-dialog";
import {
	DangerZone,
	IdLine,
	SaveBar,
	Section,
} from "#/routes/console/-components/section";
import { apisQuery } from "#/routes/console/apis/index";
import { providersQuery } from "#/routes/console/providers/index";
import { type Header, useCan } from "#/routes/console/route";
import { date } from "#/routes/console/users/index";

// tabsFor gives an Application's tabs in order; an M2M Application has no
// login to configure, but does carry Roles.
const tabsFor = (type: Application["type"]): [string, string][] => [
	["basic", "基本"],
	...(type === "m2m"
		? ([["roles", "角色"]] as [string, string][])
		: ([["login", "登录"]] as [string, string][])),
	["webhook", "用户删除通知"],
];

const defaults = { tab: "basic" } as const;
const search = z.object({
	tab: z
		.enum(["basic", "login", "roles", "webhook"])
		.default(defaults.tab)
		.catch(defaults.tab),
	// set once, by the create page: show the 接入清单 for this platform
	onboarding: z.enum(platformKeys).optional().catch(undefined),
});

// applicationRolesQuery reads the Roles an M2M Application holds on its API.
export const applicationRolesQuery = (clientId: string) =>
	queryOptions({
		queryKey: ["applications", clientId, "roles"],
		queryFn: () => api<ApplicationRoles>(`/applications/${clientId}/roles`),
	});

export const Route = createFileRoute("/console/apps/$clientId")({
	staticData: { crumb: ApplicationName, useHeader },
	validateSearch: search,
	search: { middlewares: [stripSearchParams(defaults)] },
	loader: async ({ context: { queryClient }, params }) => {
		const [apps] = await Promise.all([
			queryClient.ensureQueryData(applicationsQuery),
			queryClient.ensureQueryData(apisQuery),
		]);
		const app = apps.applications.find((a) => a.clientId === params.clientId);
		if (!app) {
			throw notFound();
		}
		// Only an M2M Application has a 角色 Tab.
		if (app.type === "m2m") {
			await queryClient.ensureQueryData(applicationRolesQuery(params.clientId));
		}
	},
	notFoundComponent: () => (
		<p className="text-sm">
			应用不存在或已被删除。
			<Link to="/console/apps" className="underline">
				返回应用列表
			</Link>
		</p>
	),
	component: ApplicationPage,
});

const day = 86400;

// fingerprintHint is what a SHA-256 certificate fingerprint looks like in
// the Android App textarea.
const fingerprintHint =
	"14:6D:E9:83:C5:73:06:50:D8:EE:B9:95:2F:34:FC:64:16:A0:83:42:E6:1D:BE:A8:8A:04:96:B2:3F:CF:44:E5";

const useApplication = (clientId: string) =>
	useQuery(applicationsQuery).data?.applications.find(
		(a) => a.clientId === clientId,
	);

// ApplicationName is the Application's crumb, kept current by the query.
function ApplicationName(): ReactNode {
	const { clientId } = useParams({ from: "/console/apps/$clientId" });
	return useApplication(clientId)?.name;
}

// useHeader heads an Application's page: its name, type and tabs, why it
// can't be edited, and the 接入清单 right after creating it.
function useHeader(): Header | null {
	const { clientId } = useParams({ from: "/console/apps/$clientId" });
	const search = useSearch({ from: "/console/apps/$clientId" });
	// The 接入清单 shows once: kept for this visit, gone from the URL so a
	// reload or a copied link doesn't bring it back.
	const [onboarding] = useState(search.onboarding);
	const navigate = useNavigate({ from: "/console/apps/$clientId" });
	useEffect(() => {
		if (search.onboarding) {
			navigate({
				search: (s) => ({ ...s, onboarding: undefined }),
				replace: true,
			});
		}
	}, [search.onboarding, navigate]);
	const app = useApplication(clientId);
	const can = useCan();
	if (!app) {
		return null;
	}
	const editable = can("applications:write") && !app.builtin;
	return {
		title: app.name,
		badges: (
			<>
				<Badge variant="secondary">{typeName[app.type]}</Badge>
				{app.builtin && <Badge variant="outline">内置</Badge>}
			</>
		),
		ids: <IdLine label="client_id" value={app.clientId} />,
		tabs: tabsFor(app.type),
		details: (
			<>
				{!editable && (
					<p className="text-muted-foreground text-sm">
						{app.builtin
							? "内置应用不能修改或删除。"
							: "需要「管理员」角色才能修改。"}
					</p>
				)}
				{app.noLoginMethod && (
					<Alert variant="warning">
						<AlertDescription>
							该应用指定的登录方式在实例中均未开启，用户无法登录。
							<Link
								to="/console/apps/$clientId"
								params={{ clientId }}
								search={{ tab: "login" }}
							>
								修改登录方式
							</Link>
						</AlertDescription>
					</Alert>
				)}
				{onboarding && <Onboarding app={app} platform={onboarding} />}
			</>
		),
	};
}

function ApplicationPage() {
	const { clientId } = Route.useParams();
	const { applications } = useSuspenseQuery(applicationsQuery).data;
	const can = useCan();
	const app = applications.find((a) => a.clientId === clientId);
	// The loader checked; this covers it going in a later refetch.
	if (!app) {
		throw notFound();
	}
	const editable = can("applications:write") && !app.builtin;
	return (
		<>
			<TabsContent value="basic">
				<BasicTab app={app} editable={editable} />
			</TabsContent>
			{app.type !== "m2m" && (
				<TabsContent value="login">
					<LoginTab app={app} editable={editable} />
				</TabsContent>
			)}
			{app.type === "m2m" && (
				<TabsContent value="roles">
					<RolesTab app={app} />
				</TabsContent>
			)}
			<TabsContent value="webhook">
				<WebhookTab app={app} editable={editable} />
			</TabsContent>
		</>
	);
}

type TabProps = { app: Application; editable: boolean };

function BasicTab({ app, editable }: TabProps) {
	const save = useSaveApplication(app);
	const saveApi = useSaveApplication(app);
	const isM2M = app.type === "m2m";
	// An M2M Application may call the Management API; nothing may call the
	// Account API (ADR 0015).
	const apis = useSuspenseQuery(apisQuery).data.apis;
	const registered = isM2M ? m2mAPIs(apis) : apis.filter((a) => !a.builtin);
	const defaultAPIName =
		registered.find((a) => a.identifier === app.defaultApi)?.name ??
		app.defaultApi;
	const form = useForm({
		defaultValues: { name: app.name },
		validationLogic: revalidateLogic(),
		validators: { onDynamic: basicSchema },
		onSubmit: ({ value }) =>
			save.mutate({ name: value.name.trim() }, { onSuccess: saved }),
	});
	const apiForm = useForm({
		defaultValues: {
			defaultApi: app.defaultApi ?? "",
			requireRole: app.requireRole ?? false,
		},
		onSubmit: ({ value }) =>
			saveApi.mutate(
				// The Roles checked are on the default API: none, nothing to require.
				{ ...value, requireRole: !!value.defaultApi && value.requireRole },
				{ onSuccess: saved },
			),
	});
	const chosenApi = useStore(apiForm.store, (s) => s.values.defaultApi);
	return (
		<div className="space-y-10">
			<Section
				title="基本信息"
				editable={editable}
				form={form}
				footer={editable && <SaveBar save={save} />}
			>
				{/* max-w-2xl: as wide as the form's fields */}
				<div className="max-w-2xl">
					<PropRow label="类型" hint={typeWhy[app.type]}>
						<span className="text-sm">{typeName[app.type]}</span>
					</PropRow>
				</div>
				<form.Field name="name">
					{(field) => (
						<FormField field={field} label="名称">
							{(control) => (
								<Input {...control} placeholder="如：星选商城 App" />
							)}
						</FormField>
					)}
				</form.Field>
			</Section>
			{app.type !== "public" && <ClientAuthn app={app} editable={editable} />}
			{isM2M ? (
				<Section title="访问令牌" editable={false}>
					<ItemList>
						<PropRow
							label="默认 API 资源"
							hint="access token 仅对该 API 有效，创建后不能更改。调用其他 API 需另建后端服务。"
						>
							<Link
								to="/console/apis/$api"
								params={{ api: app.defaultApi ?? "" }}
								className="text-sm underline"
							>
								{defaultAPIName}
							</Link>
						</PropRow>
					</ItemList>
				</Section>
			) : (
				<Section
					title="访问令牌"
					editable={editable}
					form={apiForm}
					footer={
						editable && registered.length > 0 && <SaveBar save={saveApi} />
					}
				>
					{registered.length === 0 ? (
						<Field>
							<FieldTitle>默认 API 资源</FieldTitle>
							<Alert variant="warning">
								<AlertDescription>
									还没有 API 资源。
									<Link to="/console/apis">添加 API 资源</Link>
								</AlertDescription>
							</Alert>
						</Field>
					) : (
						<apiForm.Field name="defaultApi">
							{(field) => (
								<FormField
									field={field}
									label="默认 API 资源"
									help="用户的 access token 用于调用该 API，并包含用户在其中的角色。不选时不含角色。"
								>
									{({ id }) => (
										<div className="flex items-center gap-3">
											<Select
												disabled={!editable}
												value={field.state.value}
												onValueChange={(v) => field.handleChange(`${v ?? ""}`)}
											>
												<SelectTrigger id={id} className="flex-1">
													<SelectValue>
														{(v: string) =>
															registered.find((a) => a.identifier === v)
																?.name ?? "不选"
														}
													</SelectValue>
												</SelectTrigger>
												<SelectContent>
													<SelectItem value="">不选</SelectItem>
													{registered.map((a) => (
														<SelectItem key={a.identifier} value={a.identifier}>
															{a.name}
															<span className="font-mono text-muted-foreground text-xs">
																{a.identifier}
															</span>
														</SelectItem>
													))}
												</SelectContent>
											</Select>
											{app.defaultApi && (
												<Link
													to="/console/apis/$api"
													params={{ api: app.defaultApi }}
													className="text-sm underline"
												>
													查看 API 资源
												</Link>
											)}
										</div>
									)}
								</FormField>
							)}
						</apiForm.Field>
					)}
					{registered.length > 0 && (
						<apiForm.Field name="requireRole">
							{(field) => (
								<FormField
									field={field}
									label="要求用户有角色"
									help={
										chosenApi
											? "开启后，在默认 API 资源上没有角色的用户无法登录该应用，已登录的无法续期。"
											: "需先选择默认 API 资源。"
									}
								>
									{({ id }) => (
										<Switch
											id={id}
											disabled={!editable || !chosenApi}
											checked={!!chosenApi && field.state.value}
											onCheckedChange={field.handleChange}
										/>
									)}
								</FormField>
							)}
						</apiForm.Field>
					)}
				</Section>
			)}
			{editable && <DeleteApplication app={app} />}
		</div>
	);
}

// authMethods are the two 客户端认证方式 a non-public Application picks
// from; only one works at a time (ADR 0023).
const authMethods: {
	value: Exclude<TokenAuthMethod, "none">;
	label: string;
	help: string;
}[] = [
	{
		value: "client_secret_basic",
		label: "共享密钥",
		help: "后端用 client secret 换取令牌。",
	},
	{
		value: "private_key_jwt",
		label: "私钥签名",
		help: "后端用私钥签名（RS256 或 ES256），以下方登记的公钥验证。client secret 不再可用。",
	},
];

// ClientAuthn is the 客户端认证方式 block: which method is on, the secret
// while it is the shared one, and the 应用公钥, saved apart from the
// method so a backend can be given its keys before the switch.
function ClientAuthn({ app, editable }: TabProps) {
	const client = useQueryClient();
	const save = useSaveApplication(app);
	const [asked, setAsked] = useState<TokenAuthMethod | null>(null);
	// The secret switching back issued; shown this once, like on create.
	const [issued, setIssued] = useState<string>();
	const change = useMutation({
		mutationFn: (method: TokenAuthMethod) =>
			api<{ secret?: string }>(`/applications/${app.clientId}/auth-method`, {
				method: "POST",
				body: { method },
			}),
		onSuccess: (out) => {
			setIssued(out.secret);
			client.invalidateQueries(applicationsQuery);
		},
		onError: failed("切换客户端认证方式失败"),
	});
	const form = useForm({
		defaultValues: { jwks: jwksText(app.jwks) },
		validationLogic: revalidateLogic(),
		validators: { onDynamic: jwksSchema },
		onSubmit: ({ value }) =>
			save.mutate({ jwks: JSON.parse(value.jwks) }, { onSuccess: saved }),
	});
	const keyless = !app.jwks?.keys.length;
	const toKeys = asked === "private_key_jwt";
	return (
		<Section
			title="客户端认证方式"
			intro="后端换取令牌时的身份认证方式，同一时间只能使用一种。"
			editable={editable}
			form={form}
			footer={editable && <SaveBar save={save} />}
		>
			<FieldSet>
				<FieldLegend variant="label">认证方式</FieldLegend>
				<RadioGroup
					value={app.tokenAuthMethod}
					onValueChange={(v) => setAsked(v as TokenAuthMethod)}
					disabled={change.isPending}
				>
					{authMethods.map((m) => {
						const id = `token-auth-method-${m.value}`;
						return (
							<Field key={m.value} orientation="horizontal">
								<RadioGroupItem
									id={id}
									value={m.value}
									disabled={m.value === "private_key_jwt" && keyless}
								/>
								<FieldContent>
									<FieldLabel htmlFor={id} className="font-normal">
										{m.label}
									</FieldLabel>
									<FieldDescription>
										{m.help}
										{m.value === "private_key_jwt" &&
											keyless &&
											" 需先登记并保存公钥。"}
									</FieldDescription>
								</FieldContent>
							</Field>
						);
					})}
				</RadioGroup>
			</FieldSet>
			{app.tokenAuthMethod === "client_secret_basic" && (
				<ClientSecret app={app} editable={editable} issued={issued} />
			)}
			<form.Field name="jwks">
				{(field) => (
					<FormField
						field={field}
						label="应用公钥"
						help="JWKS 格式，仅含公钥：RSA（至少 2048 位）或 EC P-256，kid 不能重复，最多 5 把。"
					>
						{(control) => (
							<Textarea
								{...control}
								rows={8}
								className="font-mono text-xs"
								placeholder='{"keys": [...]}'
							/>
						)}
					</FormField>
				)}
			</form.Field>
			<ConfirmDialog
				open={asked !== null}
				onOpenChange={(open) => !open && setAsked(null)}
				title={toKeys ? "切换到私钥签名？" : "切换回共享密钥？"}
				action={toKeys ? "切换到私钥签名" : "切换并生成 secret"}
				destructive={toKeys}
				onConfirm={() => {
					if (asked) {
						change.mutate(asked);
					}
					setAsked(null);
				}}
			>
				{toKeys
					? "当前 client secret 将立即失效，请先让后端改用私钥签名。"
					: "将生成新的 client secret，仅显示一次。私钥签名将不再可用，已登记的公钥保留。"}
			</ConfirmDialog>
		</Section>
	);
}

function ClientSecret({
	app,
	editable,
	issued,
}: TabProps & { issued?: string }) {
	const rotate = useMutation({
		mutationFn: () =>
			api<{ secret: string }>(`/applications/${app.clientId}/secret`, {
				method: "POST",
			}),
		onError: failed("重新生成 client secret 失败"),
	});
	const shown = rotate.data?.secret ?? issued;
	return (
		<div className="max-w-2xl">
			<PropRow
				label="client secret"
				hint="后端换取令牌时使用，仅在生成时显示一次。"
				actions={
					!shown &&
					editable && (
						<ConfirmDialog
							trigger={
								<Button
									type="button"
									variant="ghost"
									size="sm"
									disabled={rotate.isPending}
								>
									重新生成
								</Button>
							}
							title="重新生成 client secret？"
							action="重新生成"
							destructive={false}
							onConfirm={() => rotate.mutate()}
						>
							旧的 client secret 将立即失效，仍在使用它的后端将无法换取令牌。
						</ConfirmDialog>
					)
				}
			>
				{shown ? (
					<Alert variant="warning">
						<AlertDescription>
							新的 client secret 仅显示一次：
							<span className="block break-all font-mono">{shown}</span>
						</AlertDescription>
					</Alert>
				) : (
					<span className="break-all font-mono text-muted-foreground text-sm">
						••••••••••••••••
					</span>
				)}
			</PropRow>
		</div>
	);
}

function DeleteApplication({ app }: { app: Application }) {
	const client = useQueryClient();
	const navigate = useNavigate();
	const remove = useMutation({
		mutationFn: () =>
			api(`/applications/${app.clientId}`, { method: "DELETE" }),
		onSuccess: async () => {
			await navigate({ to: "/console/apps" });
			client.invalidateQueries(applicationsQuery);
		},
		onError: failed("删除应用失败"),
	});
	return (
		<DangerZone title="删除应用">
			<p className="text-sm">删除后，用户无法再通过该应用登录。</p>
			<ConfirmDialog
				trigger={
					<Button
						type="button"
						variant="destructive"
						disabled={remove.isPending}
					>
						删除应用
					</Button>
				}
				title={`删除「${app.name}」？`}
				action="删除应用"
				onConfirm={() => remove.mutate()}
			>
				用户将无法再通过该应用登录。此操作无法撤销。
			</ConfirmDialog>
		</DangerZone>
	);
}

function LoginTab({ app, editable }: TabProps) {
	const save = useSaveApplication(app);
	const form = useForm({
		defaultValues: {
			redirectUris: app.redirectUris.join("\n"),
			postLogoutRedirectUris: app.postLogoutRedirectUris.join("\n"),
			homeUrl: app.homeUrl ?? "",
			idleDays: app.sessionIdleTimeout
				? `${app.sessionIdleTimeout / day}`
				: "0",
			maxDays: app.sessionMaxLifetime ? `${app.sessionMaxLifetime / day}` : "0",
			refreshTokens: app.refreshTokens,
		},
		validationLogic: revalidateLogic(),
		validators: { onDynamic: loginSchema },
		onSubmit: ({ value }) =>
			save.mutate(
				{
					redirectUris: lines(value.redirectUris),
					postLogoutRedirectUris: lines(value.postLogoutRedirectUris),
					homeUrl: value.homeUrl.trim(),
					sessionIdleTimeout: Number(value.idleDays.trim() || 0) * day,
					sessionMaxLifetime: Number(value.maxDays.trim() || 0) * day,
					refreshTokens: value.refreshTokens,
				},
				{ onSuccess: saved },
			),
	});
	return (
		<div className="space-y-10">
			<Section
				title="登录跳转"
				editable={editable}
				form={form}
				footer={editable && <SaveBar save={save} />}
			>
				<form.Field name="redirectUris">
					{(field) => (
						<FormField
							field={field}
							label="回调地址"
							en="redirect URI"
							help="登录完成后跳转回应用的地址，仅允许此处登记的地址。"
						>
							{(control) => (
								<Textarea
									{...control}
									className="font-mono"
									placeholder="每行一个，如 https://shop.example.com/callback"
								/>
							)}
						</FormField>
					)}
				</form.Field>
				{/* keepMounted: a folded field's error still shows when unfolded. */}
				<Collapsible>
					<CollapsibleTrigger className="flex items-center gap-1 font-medium text-[13px] [&[data-panel-open]>svg]:rotate-90">
						<ChevronRight className="size-4 transition-transform" />
						高级
					</CollapsibleTrigger>
					<CollapsibleContent keepMounted className="mt-6 space-y-6">
						<form.Field name="postLogoutRedirectUris">
							{(field) => (
								<FormField
									field={field}
									label="退出后跳转地址"
									en="post-logout redirect URI"
									help="用户退出登录后跳转的地址，仅允许此处登记的地址。"
								>
									{(control) => (
										<Textarea
											{...control}
											className="font-mono"
											placeholder="每行一个，如 https://shop.example.com"
										/>
									)}
								</FormField>
							)}
						</form.Field>
						<form.Field name="homeUrl">
							{(field) => (
								<FormField
									field={field}
									label="首页地址"
									en="home URL"
									help="账号中心通过 /account?client_id= 打开时，显示「返回」链接回到这里。留空则不显示。"
								>
									{(control) => (
										<Input
											{...control}
											className="font-mono"
											placeholder="https://shop.example.com"
										/>
									)}
								</FormField>
							)}
						</form.Field>
						<form.Field name="refreshTokens">
							{(field) => (
								<FormField
									field={field}
									label="允许 App 保持登录"
									en="签发 refresh token，每次刷新都给会话续期"
									help="开启后，App 可在后台续期会话；关闭后约 10 分钟需重新登录。"
								>
									{({ id }) => (
										<Switch
											id={id}
											disabled={!editable}
											checked={field.state.value}
											onCheckedChange={field.handleChange}
										/>
									)}
								</FormField>
							)}
						</form.Field>
						<form.Field name="idleDays">
							{(field) => {
								const days = Number(field.state.value) || 0;
								return (
									<FormField
										field={field}
										label="闲置多久需重新登录"
										help="闲置超过该天数需重新登录。0 为默认值（无后端 90 天，有后端 30 天）。仅对之后新登录的会话生效。"
									>
										{(control) => (
											<div className="flex max-w-md items-center gap-4">
												<Slider
													min={0}
													max={365}
													step={1}
													value={[days]}
													disabled={!editable}
													aria-label="闲置天数"
													onValueChange={(v) =>
														field.handleChange(
															String(Array.isArray(v) ? v[0] : v),
														)
													}
												/>
												<Input
													{...control}
													type="number"
													min={0}
													max={365}
													className="w-20"
												/>
												<span className="shrink-0 text-sm">天</span>
											</div>
										)}
									</FormField>
								);
							}}
						</form.Field>
						<form.Field name="maxDays">
							{(field) => {
								const days = Number(field.state.value) || 0;
								return (
									<FormField
										field={field}
										label="最长多久需重新登录"
										help="自上次登录或重新验证身份起算，到期需重新登录。0 为默认值（App 180 天，浏览器 90 天）。仅对之后新登录的会话生效。"
									>
										{(control) => (
											<div className="flex max-w-md items-center gap-4">
												<Slider
													min={0}
													max={365}
													step={1}
													value={[days]}
													disabled={!editable}
													aria-label="最长天数"
													onValueChange={(v) =>
														field.handleChange(
															String(Array.isArray(v) ? v[0] : v),
														)
													}
												/>
												<Input
													{...control}
													type="number"
													min={0}
													max={365}
													className="w-20"
												/>
												<span className="shrink-0 text-sm">天</span>
											</div>
										)}
									</FormField>
								);
							}}
						</form.Field>
					</CollapsibleContent>
				</Collapsible>
			</Section>
			{!app.builtin && <LoginMethods app={app} editable={editable} />}
			{!app.builtin && <AppBrand app={app} editable={editable} />}
			{app.type === "public" && <NativeApps app={app} editable={editable} />}
			{app.type === "confidential" && (
				<BackchannelLogout app={app} editable={editable} />
			)}
		</div>
	);
}

const methodNames: [LoginMethod, string][] = [
	["sms", "短信验证码"],
	["email", "邮箱验证码"],
	["password", "密码"],
	["passkey", "Passkey"],
];

// LoginMethods is the 登录方式 section: follow the instance, or only the
// ones ticked, as far as the instance has them on (ADR 0027). The built-in
// Applications always follow, so they don't show it.
function LoginMethods({ app, editable }: TabProps) {
	const save = useSaveApplication(app);
	// Without config:read the Providers can't be listed; the ones chosen
	// still show, by ID.
	const providers =
		useQuery({ ...providersQuery, retry: false }).data?.providers ?? [];
	const chosen = app.loginMethods?.providers ?? [];
	const listed = [
		...providers.map((p) => ({
			id: p.id,
			name: p.enabled ? p.name : `${p.name}（已停用）`,
		})),
		...chosen
			.filter((id) => !providers.some((p) => p.id === id))
			.map((id) => ({ id, name: id })),
	];
	const form = useForm({
		defaultValues: {
			own: !!app.loginMethods,
			methods: app.loginMethods?.methods ?? [],
			providers: chosen,
		},
		onSubmit: ({ value }) =>
			save.mutate(
				{
					loginMethods: value.own
						? { methods: value.methods, providers: value.providers }
						: undefined,
				},
				{ onSuccess: saved },
			),
	});
	const own = useStore(form.store, (s) => s.values.own);
	const tick = <T extends string>(list: T[], key: T, on: boolean) =>
		on ? [...list, key] : list.filter((k) => k !== key);
	return (
		<Section
			title="登录方式"
			intro="默认跟随实例的登录方式和已启用的认证源。指定后仅可使用勾选且实例已开启的方式，用其他方式登录的用户进入该应用时需重新登录。"
			editable={editable}
			form={form}
			footer={editable && <SaveBar save={save} />}
		>
			<form.Field name="own">
				{(field) => (
					<FormField field={field} label="只允许指定的登录方式">
						{({ id }) => (
							<Switch
								id={id}
								disabled={!editable}
								checked={field.state.value}
								onCheckedChange={field.handleChange}
							/>
						)}
					</FormField>
				)}
			</form.Field>
			{own && (
				<>
					<form.Field name="methods">
						{(field) => (
							<div className="flex flex-wrap gap-x-4 gap-y-2">
								{methodNames.map(([key, name]) => (
									<Label key={key} className="font-normal">
										<Checkbox
											disabled={!editable}
											checked={field.state.value.includes(key)}
											onCheckedChange={(on) =>
												field.handleChange(tick(field.state.value, key, on))
											}
										/>
										{name}
									</Label>
								))}
							</div>
						)}
					</form.Field>
					{listed.length > 0 && (
						<form.Field name="providers">
							{(field) => (
								<FieldSet>
									<FieldLegend
										variant="label"
										className="text-[13px] text-muted-foreground font-normal"
									>
										认证源
									</FieldLegend>
									<div className="flex flex-wrap gap-x-4 gap-y-2">
										{listed.map((p) => (
											<Label key={p.id} className="font-normal">
												<Checkbox
													disabled={!editable}
													checked={field.state.value.includes(p.id)}
													onCheckedChange={(on) =>
														field.handleChange(
															tick(field.state.value, p.id, on),
														)
													}
												/>
												{p.name}
											</Label>
										))}
									</div>
								</FieldSet>
							)}
						</form.Field>
					)}
				</>
			)}
		</Section>
	);
}

// AppBrand is the Application's own 品牌 items over the instance's (ADR
// 0028); the built-in Applications always follow, so they don't show it.
function AppBrand({ app, editable }: TabProps) {
	const save = useSaveApplication(app);
	const client = useQueryClient();
	return (
		<BrandSection
			intro="默认跟随实例的品牌，填写的项覆盖实例设置。"
			brand={app.brand}
			editable={editable}
			follows="跟随实例"
			logoPath={`/applications/${app.clientId}/brand/logo`}
			onLogo={(logo) => {
				// The next save sends the Logo back; it must be this one.
				patchApplication(client, app.clientId, (a) => ({
					brand: { ...a.brand, logo },
				}));
				return client.invalidateQueries(applicationsQuery);
			}}
			save={{
				...save,
				mutate: (brand, o) => save.mutate({ brand }, o),
			}}
		/>
	);
}

// NativeApps is the 原生 App 关联 section: what makes iOS and Android
// allow this domain's Passkeys and password autofill in the App. Only
// 无后端应用 have it; a web Application is never a native App.
function NativeApps({ app, editable }: TabProps) {
	const save = useSaveApplication(app);
	const form = useForm({
		defaultValues: {
			apple: app.appleAppIds.join("\n"),
			android: androidLines(app.androidApps),
		},
		validationLogic: revalidateLogic(),
		validators: { onDynamic: nativeSchema },
		onSubmit: ({ value }) =>
			save.mutate(
				{
					appleAppIds: lines(value.apple),
					androidApps: androidApps(value.android),
				},
				{ onSuccess: saved },
			),
	});
	return (
		<Section
			title="原生 App 关联"
			intro="登记后，这些 iOS 和 Android 应用可使用本域名的 Passkey 和密码自动填充，保存后立即生效。"
			editable={editable}
			form={form}
			footer={editable && <SaveBar save={save} />}
		>
			<form.Field name="apple">
				{(field) => (
					<FormField
						field={field}
						label="iOS App"
						en="Team ID.Bundle ID"
						help="见 Apple 开发者后台的 Membership 和 Identifiers 页面。"
					>
						{(control) => (
							<Textarea
								{...control}
								className="font-mono"
								placeholder="每行一个，如 ABCDE12345.com.example.app"
							/>
						)}
					</FormField>
				)}
			</form.Field>
			<form.Field name="android">
				{(field) => (
					<FormField
						field={field}
						label="Android App"
						en="包名 + SHA-256 签名指纹"
						help="可用 gradlew signingReport 查看签名指纹。"
					>
						{(control) => (
							<Textarea
								{...control}
								className="font-mono"
								placeholder={`每行一个，包名后接指纹（多个用空格分隔），如 com.example.app ${fingerprintHint}`}
							/>
						)}
					</FormField>
				)}
			</form.Field>
		</Section>
	);
}

// BackchannelLogout is where a web Application's back end hears that a
// login session it signed in through has ended (ADR 0022).
function BackchannelLogout({ app, editable }: TabProps) {
	const save = useSaveApplication(app);
	const form = useForm({
		defaultValues: { backchannelLogoutUri: app.backchannelLogoutUri ?? "" },
		validationLogic: revalidateLogic(),
		validators: { onDynamic: backchannelSchema },
		onSubmit: ({ value }) =>
			save.mutate(
				{ backchannelLogoutUri: value.backchannelLogoutUri.trim() },
				{ onSuccess: saved },
			),
	});
	return (
		<Section
			title="退出通知"
			intro="用户退出登录、被下线、禁用或删除时，向该地址发送 OIDC Back-Channel Logout 通知。留空则不发送。"
			editable={editable}
			form={form}
			footer={editable && <SaveBar save={save} />}
		>
			<form.Field name="backchannelLogoutUri">
				{(field) => (
					<FormField
						field={field}
						label="通知地址"
						en="backchannel_logout_uri"
						help="需能从认证服务访问。"
					>
						{(control) => (
							<Input
								{...control}
								type="url"
								className="font-mono"
								placeholder="https://shop.example.com/backchannel-logout"
							/>
						)}
					</FormField>
				)}
			</form.Field>
		</Section>
	);
}

function WebhookTab({ app, editable }: TabProps) {
	const save = useSaveApplication(app);
	const secretSet = !!app.webhookSecretUpdatedAt;
	const form = useForm({
		defaultValues: { webhookUrl: app.webhookUrl ?? "", webhookSecret: "" },
		validationLogic: revalidateLogic(),
		validators: { onDynamic: webhookSchema(secretSet) },
		onSubmit: ({ value }) =>
			save.mutate(
				{
					webhookUrl: value.webhookUrl.trim(),
					webhookSecret: value.webhookSecret || undefined,
				},
				{
					onSuccess: () => {
						form.setFieldValue("webhookSecret", "");
						saved();
					},
				},
			),
	});
	const url = useStore(form.store, (s) => s.values.webhookUrl.trim());
	return (
		<Section
			title="用户删除通知"
			editable={editable}
			intro="用户被删除或注销账号时，向该地址发送通知。留空则不发送。"
			form={form}
			footer={editable && <SaveBar save={save} />}
		>
			<form.Field name="webhookUrl">
				{(field) => (
					<FormField field={field} label="通知地址" help="需能从公网访问。">
						{(control) => (
							<Input
								{...control}
								type="url"
								className="font-mono"
								placeholder="https://shop.example.com/hooks/polaris"
							/>
						)}
					</FormField>
				)}
			</form.Field>
			{!url && secretSet && (
				<Alert variant="warning">
					<AlertDescription>保存后 Webhook 密钥会一并清除。</AlertDescription>
				</Alert>
			)}
			<form.Field name="webhookSecret">
				{(field) => (
					<FormField
						field={field}
						label="Webhook 密钥"
						help="用于验证通知来源。填写通知地址时必填。"
					>
						{(control) => (
							<>
								{secretSet && (
									<p className="text-muted-foreground text-sm">
										已设置 · 更新于 {date(app.webhookSecretUpdatedAt ?? "")}
									</p>
								)}
								<Input
									{...control}
									type="password"
									autoComplete="new-password"
									placeholder="随机字符串，如 whsec_ 开头的格式"
								/>
							</>
						)}
					</FormField>
				)}
			</form.Field>
		</Section>
	);
}

// RolesTab assigns the Roles an M2M Application holds on its one API; its
// access token carries them (ADR 0015). Management API Roles need
// admin-roles:assign, like everywhere else.
function RolesTab({ app }: { app: Application }) {
	const can = useCan();
	const client = useQueryClient();
	const { apis } = useSuspenseQuery(apisQuery).data;
	const held = useSuspenseQuery(applicationRolesQuery(app.clientId)).data.roles;
	const apiDef = apis.find((a) => a.identifier === app.defaultApi);
	const roles = apiDef?.roles ?? [];
	const editable = can(
		app.defaultApi === managementAPI ? "admin-roles:assign" : "roles:assign",
	);
	const save = useMutation({
		mutationFn: (keys: string[]) =>
			api(`/applications/${app.clientId}/roles`, {
				method: "PUT",
				body: { roles: keys },
			}),
		// Role counts on the API pages change with it.
		onSuccess: () =>
			Promise.all([
				client.invalidateQueries(applicationRolesQuery(app.clientId)),
				client.invalidateQueries(apisQuery),
				client.invalidateQueries({ queryKey: ["roles"] }),
			]),
	});
	const form = useForm({
		defaultValues: { roles: held },
		onSubmit: ({ value }) => save.mutate(value.roles, { onSuccess: saved }),
	});
	if (roles.length === 0) {
		return (
			<Section title="角色" editable={false}>
				<Alert>
					<AlertDescription>
						该 API 资源还没有角色。
						<Link
							to="/console/apis/$api"
							params={{ api: app.defaultApi ?? "" }}
							className="underline"
						>
							添加角色
						</Link>
					</AlertDescription>
				</Alert>
			</Section>
		);
	}
	return (
		<Section
			title="角色"
			intro="应用的 access token 包含勾选的角色及其权限。"
			editable={editable}
			form={form}
			footer={editable && <SaveBar save={save} />}
		>
			<form.Field name="roles">
				{(field) => (
					<FieldSet>
						<FieldLegend
							variant="label"
							className="text-[13px] text-muted-foreground font-normal"
						>
							{apiDef?.name}
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
		</Section>
	);
}

const steps = {
	clientId: "记下 client_id",
	secret: "保存 client secret",
	api: "选择默认 API 资源（可选）",
	code: "接入代码",
};

// Onboarding is the 接入清单 shown once, right after the create page sent
// us here; each step ticks itself from the Application. A new client
// secret holds the reader on this page until they say it's saved.
function Onboarding({
	app,
	platform,
}: {
	app: Application;
	platform: Platform;
}) {
	const [secret] = useState(() => newSecrets.get(app.clientId));
	useEffect(() => {
		newSecrets.delete(app.clientId);
	}, [app.clientId]);
	const [saved, setSaved] = useState(false);
	const holding = !!secret && !saved;
	const blocker = useBlocker({
		shouldBlockFn: ({ current, next }) =>
			holding && current.pathname !== next.pathname,
		enableBeforeUnload: () => holding,
		withResolver: true,
	});
	const issuer = location.origin;
	const code = snippet(platform, {
		issuer,
		clientId: app.clientId,
		redirectUri: app.redirectUris[0],
	});
	// After a reload the secret is gone: nothing left to save here.
	const items = checklist(app, saved || !secret);
	const body = {
		clientId: (
			<div className="flex items-center gap-2">
				<span className="font-mono text-sm">{app.clientId}</span>
				<CopyButton value={app.clientId} />
			</div>
		),
		secret: secret ? (
			<div className="space-y-2 rounded-xl bg-amber-500/10 p-4">
				<div className="flex items-center gap-2">
					<span className="break-all font-mono text-sm">{secret}</span>
					<CopyButton value={secret} />
				</div>
				<p className="text-[13px] text-muted-foreground">
					仅显示一次，请立即保存。丢失后需重新生成，旧的将立即失效。
				</p>
				<Label className="font-normal">
					<Checkbox checked={saved} onCheckedChange={setSaved} />
					我已保存 client secret
				</Label>
			</div>
		) : (
			<p className="text-[13px] text-muted-foreground">
				client secret
				仅在创建时显示一次。如未保存，可在下方「客户端认证方式」中重新生成。
			</p>
		),
		api: (
			<p className="text-[13px] text-muted-foreground">
				{app.type === "m2m"
					? "access token 仅对该 API 有效，创建后不能更改。"
					: "用户的 access token 可调用该 API 资源，并包含用户在其中的角色。可在下方「访问令牌」中选择，不调用自有 API 可跳过。"}
			</p>
		),
		code: (
			<div className="space-y-2">
				<p className="text-[13px] text-muted-foreground">{code.help}</p>
				<pre className="overflow-x-auto rounded-lg bg-card p-4 text-xs">
					{code.code}
				</pre>
				<div className="flex items-center gap-2 text-sm">
					<span className="text-muted-foreground">认证服务地址</span>
					<span className="font-mono">{issuer}</span>
					<CopyButton value={issuer} />
				</div>
			</div>
		),
	};
	return (
		<Collapsible defaultOpen className="rounded-xl bg-primary-soft p-6">
			<CollapsibleTrigger className="flex items-center gap-1 font-semibold text-[15px] [&[data-panel-open]>svg]:rotate-90">
				<ChevronRight className="size-4 transition-transform" />
				接入清单
			</CollapsibleTrigger>
			<CollapsibleContent>
				<ol className="mt-4 space-y-4">
					{items.map((item, n) => (
						<li key={item.key} className="flex gap-3">
							<span
								className={`grid size-5 shrink-0 place-items-center rounded-full text-xs ${item.done ? "bg-primary text-primary-foreground" : "bg-card text-primary-ink ring-1 ring-border"}`}
							>
								{item.done ? <Check className="size-3" /> : n + 1}
							</span>
							<div className="flex-1 space-y-1">
								<p className="font-medium text-sm">
									{item.key === "api" && app.type === "m2m"
										? "默认 API 资源"
										: steps[item.key]}
								</p>
								{body[item.key]}
							</div>
						</li>
					))}
				</ol>
				<div className="mt-4 space-y-1 text-muted-foreground text-sm">
					<p>
						在
						<Link to="/console/settings" className="underline">
							「登录方式」
						</Link>
						中查看用户可用的登录方式。
					</p>
					<p>
						如需在用户注销时清理数据，请配置
						<Link
							from={Route.fullPath}
							search={{ tab: "webhook" }}
							className="underline"
						>
							「用户删除通知」
						</Link>
						。
					</p>
				</div>
			</CollapsibleContent>
			<ConfirmDialog
				open={blocker.status === "blocked"}
				onOpenChange={(open) => !open && blocker.reset?.()}
				title="离开前保存 client secret？"
			>
				client secret
				仅显示一次，离开后无法再查看。请先保存，并勾选「我已保存」。
			</ConfirmDialog>
		</Collapsible>
	);
}
