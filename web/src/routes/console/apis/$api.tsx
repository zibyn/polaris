import { revalidateLogic, useForm } from "@tanstack/react-form";
import {
	type UseMutationResult,
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
	useNavigate,
	useParams,
} from "@tanstack/react-router";
import { type ReactNode, useState } from "react";
import { z } from "zod";
import { FormError, FormField, failed, saved } from "#/components/form";
import { ItemList } from "#/components/item-list";
import { Alert, AlertDescription } from "#/components/ui/alert";
import { Badge } from "#/components/ui/badge";
import { Button } from "#/components/ui/button";
import { Checkbox } from "#/components/ui/checkbox";
import {
	Empty,
	EmptyContent,
	EmptyDescription,
	EmptyHeader,
	EmptyTitle,
} from "#/components/ui/empty";
import { FieldLegend, FieldSet } from "#/components/ui/field";
import { Input } from "#/components/ui/input";
import {
	Item,
	ItemActions,
	ItemContent,
	ItemDescription,
	ItemTitle,
} from "#/components/ui/item";
import { Label } from "#/components/ui/label";
import { TabsContent } from "#/components/ui/tabs";
import {
	defaultFor,
	permissionSchema,
	roleSchema,
	rolesWith,
} from "#/lib/apis";
import {
	type APIDef,
	type Application,
	api,
	apiPath,
	type RoleDef,
} from "#/lib/console-api";
import { ConfirmDialog } from "#/routes/console/-components/confirm-dialog";
import { FormSheet } from "#/routes/console/-components/form-sheet";
import { DangerZone } from "#/routes/console/-components/section";
import { apisQuery } from "#/routes/console/apis/index";
import { applicationsQuery } from "#/routes/console/apps/index";
import { type Header, useCan } from "#/routes/console/route";

const defaults = { tab: "permissions" } as const;
const search = z.object({
	tab: z
		.enum(["permissions", "roles"])
		.default(defaults.tab)
		.catch(defaults.tab),
});

export const Route = createFileRoute("/console/apis/$api")({
	staticData: { crumb: APIName, useHeader },
	validateSearch: search,
	search: { middlewares: [stripSearchParams(defaults)] },
	loader: async ({ context: { queryClient }, params }) => {
		const [apis] = await Promise.all([
			queryClient.ensureQueryData(apisQuery),
			queryClient.ensureQueryData(applicationsQuery),
		]);
		if (!apis.apis.some((a) => a.identifier === params.api)) {
			throw notFound();
		}
	},
	notFoundComponent: () => (
		<p className="text-sm">
			没有这个 API 资源，它可能已经被删除。
			<Link to="/console/apis" className="underline">
				返回 API 资源列表
			</Link>
		</p>
	),
	component: APIPage,
});

const tabs = [
	["permissions", "权限"],
	["roles", "角色"],
] as const;

// useAPIMutation runs a Management API write and refreshes the API list.
// Pass onError for an action outside a form; a form shows the error itself.
function useAPIMutation<T>(
	fn: (v: T) => Promise<unknown>,
	onError?: (e: Error) => void,
) {
	const client = useQueryClient();
	return useMutation({
		mutationFn: fn,
		onSuccess: () => client.invalidateQueries(apisQuery),
		onError,
	});
}

// useAPI finds the API resource and the Applications defaulting to it,
// once both lists are in.
function useAPI(identifier: string) {
	const apis = useQuery(apisQuery).data;
	const apps = useQuery(applicationsQuery).data;
	const def = apis?.apis.find((a) => a.identifier === identifier);
	return {
		def,
		defaulting:
			def && apps ? defaultFor(apps.applications, def.identifier) : undefined,
	};
}

// APIName is the API resource's crumb, kept current by the query.
function APIName(): ReactNode {
	const { api: identifier } = useParams({ from: "/console/apis/$api" });
	return useAPI(identifier).def?.name;
}

function useHeader(): Header | null {
	const { api: identifier } = useParams({ from: "/console/apis/$api" });
	const { def, defaulting } = useAPI(identifier);
	if (!def || !defaulting) {
		return null;
	}
	return {
		title: def.name,
		badges: def.builtin && <Badge variant="secondary">内置</Badge>,
		tabs,
		details: (
			<dl className="grid gap-1 text-sm sm:grid-cols-[10rem_1fr]">
				<dt className="text-muted-foreground">API 资源标识符</dt>
				<dd>
					<span className="font-mono">{def.identifier}</span>
					<p className="text-[13px] text-muted-foreground">
						你的后端校验令牌时认的名字，即 access token 的 aud。
					</p>
				</dd>
				<dt className="text-muted-foreground">用作默认 API 资源</dt>
				<dd>
					{defaulting.length ? (
						<AppLinks apps={defaulting} />
					) : (
						<span className="text-muted-foreground">没有应用</span>
					)}
				</dd>
			</dl>
		),
	};
}

function APIPage() {
	const { api: identifier } = Route.useParams();
	const { apis } = useSuspenseQuery(apisQuery).data;
	const { applications } = useSuspenseQuery(applicationsQuery).data;
	const def = apis.find((a) => a.identifier === identifier);
	// The loader checked; this covers it going in a later refetch.
	if (!def) {
		throw notFound();
	}
	const defaulting = defaultFor(applications, def.identifier);
	return (
		<div className="space-y-10">
			<TabsContent value="permissions">
				<Permissions def={def} />
			</TabsContent>
			<TabsContent value="roles">
				<Roles def={def} noDefaultApps={defaulting.length === 0} />
			</TabsContent>
			<DeleteAPI def={def} defaulting={defaulting} />
		</div>
	);
}

function AppLinks({ apps }: { apps: Application[] }) {
	return (
		<span className="flex flex-wrap gap-x-3">
			{apps.map((a) => (
				<Link
					key={a.clientId}
					to="/console/apps/$clientId"
					params={{ clientId: a.clientId }}
					className="underline"
				>
					{a.name}
				</Link>
			))}
		</span>
	);
}

function Permissions({ def }: { def: APIDef }) {
	const can = useCan();
	const editable = can("applications:write") && !def.builtin;
	const base = apiPath(def.identifier);
	const put = useAPIMutation((v: { key: string; name: string }) =>
		api(`${base}/permissions/${encodeURIComponent(v.key)}`, {
			method: "PUT",
			body: { name: v.name },
		}),
	);
	const remove = useAPIMutation(
		(key: string) =>
			api(`${base}/permissions/${encodeURIComponent(key)}`, {
				method: "DELETE",
			}),
		failed("删除权限失败"),
	);
	const [adding, setAdding] = useState(false);
	const add = editable ? (
		<Button size="sm" onClick={() => setAdding(true)}>
			添加权限
		</Button>
	) : (
		<CannotCreate />
	);
	return (
		<div className="space-y-3">
			{def.permissions.length === 0 && def.builtin && (
				<p className="text-muted-foreground text-sm">
					内置 API 资源的权限由认证服务定义，不能添加。
				</p>
			)}
			{def.permissions.length === 0 && !def.builtin && (
				<Empty className="border">
					<EmptyHeader>
						<EmptyTitle>还没有权限</EmptyTitle>
						<EmptyDescription>
							权限是你的后端检查的最小单位，比如“导出订单”。先定义权限，再把它们组合成角色。
						</EmptyDescription>
					</EmptyHeader>
					<EmptyContent>{add}</EmptyContent>
				</Empty>
			)}
			<ItemList>
				{def.permissions.map((p) => {
					const n = rolesWith(def.roles, p.key);
					return (
						<Item key={p.key}>
							<ItemContent>
								<ItemTitle>
									{p.name}
									<span className="font-mono font-normal text-muted-foreground text-xs">
										{p.key}
									</span>
								</ItemTitle>
							</ItemContent>
							{editable && (
								<ItemActions>
									<ConfirmDialog
										trigger={
											<Button
												size="sm"
												variant="ghost"
												disabled={remove.isPending}
											>
												删除
											</Button>
										}
										title={`删除权限「${p.name}」？`}
										action="删除权限"
										onConfirm={() => remove.mutate(p.key)}
									>
										{n
											? `它会从 ${n} 个角色中移除，持有这些角色的用户随即失去这项权限。此操作无法撤销。`
											: "没有角色用到它。此操作无法撤销。"}
									</ConfirmDialog>
								</ItemActions>
							)}
						</Item>
					);
				})}
			</ItemList>
			{def.permissions.length > 0 && editable && add}
			<FormSheet
				open={adding}
				onOpenChange={setAdding}
				title="添加权限"
				description="权限是你的后端检查的最小单位，比如“导出订单”。先定义权限，再把它们组合成角色。"
			>
				<PermissionForm save={put} onDone={() => setAdding(false)} />
			</FormSheet>
		</div>
	);
}

function PermissionForm({
	save,
	onDone,
}: {
	save: UseMutationResult<unknown, Error, { key: string; name: string }>;
	onDone: () => void;
}) {
	const form = useForm({
		defaultValues: { key: "", name: "" },
		validationLogic: revalidateLogic(),
		validators: { onDynamic: permissionSchema },
		onSubmit: ({ value }) =>
			save.mutate(
				{ key: value.key.trim(), name: value.name.trim() },
				{
					onSuccess: () => {
						saved();
						onDone();
					},
				},
			),
	});
	return (
		<form
			noValidate
			className="flex flex-col gap-5"
			onSubmit={(e) => {
				e.preventDefault();
				form.handleSubmit();
			}}
		>
			<form.Field name="key">
				{(field) => (
					<FormField field={field} label="权限 key">
						{(control) => (
							<Input
								{...control}
								placeholder="如：orders:export"
								className="font-mono"
							/>
						)}
					</FormField>
				)}
			</form.Field>
			<form.Field name="name">
				{(field) => (
					<FormField field={field} label="名称">
						{(control) => <Input {...control} placeholder="如：导出订单" />}
					</FormField>
				)}
			</form.Field>
			<FormError error={save.error} />
			<div className="flex gap-2">
				<Button type="submit" disabled={save.isPending}>
					添加权限
				</Button>
				<Button type="button" variant="ghost" onClick={onDone}>
					取消
				</Button>
			</div>
		</form>
	);
}

function Roles({
	def,
	noDefaultApps,
}: {
	def: APIDef;
	noDefaultApps: boolean;
}) {
	const can = useCan();
	// Management API Roles hand out admin Permissions: owners only.
	const editable =
		can("applications:write") && (!def.builtin || can("admin-roles:assign"));
	const [editing, setEditing] = useState<RoleDef | "new" | null>(null);
	const close = () => setEditing(null);
	const add = editable ? (
		<Button size="sm" onClick={() => setEditing("new")}>
			添加角色
		</Button>
	) : (
		<CannotCreate />
	);
	return (
		<div className="space-y-3">
			{noDefaultApps && (
				<Alert variant="warning">
					<AlertDescription>
						还没有应用以它为默认 API
						资源，给用户分配的角色不会出现在任何令牌里。{" "}
						<Link to="/console/apps">去「应用」</Link>
					</AlertDescription>
				</Alert>
			)}
			{def.roles.length === 0 && (
				<Empty className="border">
					<EmptyHeader>
						<EmptyTitle>还没有角色</EmptyTitle>
						<EmptyDescription>
							角色是一组权限，分给用户后，他们登录拿到的令牌里就带着这些权限。
						</EmptyDescription>
					</EmptyHeader>
					<EmptyContent>{add}</EmptyContent>
				</Empty>
			)}
			<ItemList>
				{def.roles.map((r) => (
					<RoleRow
						key={r.key}
						def={def}
						role={r}
						editable={editable}
						onEdit={() => setEditing(r)}
					/>
				))}
			</ItemList>
			{def.roles.length > 0 && editable && add}
			<FormSheet
				open={editing !== null}
				onOpenChange={(open) => !open && close()}
				title={
					editing === null || editing === "new"
						? "添加角色"
						: `编辑角色「${editing.name}」`
				}
				description="角色是一组权限，分给用户后，他们登录拿到的令牌里就带着这些权限。"
			>
				{editing !== null && (
					<RoleForm
						def={def}
						role={editing === "new" ? undefined : editing}
						onDone={close}
					/>
				)}
			</FormSheet>
		</div>
	);
}

// holders names who holds a Role, for the count line and the delete prompt.
const holders = (role: RoleDef): string[] =>
	[
		role.users ? `${role.users} 个用户` : "",
		role.applications ? `${role.applications} 个 Application` : "",
	].filter(Boolean);

// RoleRow shows a Role; 编辑 opens it in the drawer. Built-in Roles stay as
// they are.
function RoleRow({
	def,
	role,
	editable: canEdit,
	onEdit,
}: {
	def: APIDef;
	role: RoleDef;
	editable: boolean;
	onEdit: () => void;
}) {
	const editable = canEdit && !role.builtin;
	const remove = useAPIMutation(
		(force: boolean) =>
			api(
				`${apiPath(def.identifier)}/roles/${encodeURIComponent(role.key)}${force ? "?force=true" : ""}`,
				{ method: "DELETE" },
			),
		failed("删除角色失败"),
	);
	// mark turns 默认 Role on and off; the Role keeps its name and Permissions.
	const mark = useAPIMutation(
		(dflt: boolean) =>
			api(`${apiPath(def.identifier)}/roles/${encodeURIComponent(role.key)}`, {
				method: "PUT",
				body: {
					name: role.name,
					permissions: role.permissions,
					default: dflt,
				},
			}),
		failed("设置默认角色失败"),
	);
	const held = holders(role);
	// 默认 Role reaches every new User, which only makes sense per API resource.
	const canMark = !def.builtin;
	return (
		<Item>
			<ItemContent>
				<ItemTitle>
					{role.name}
					<span className="font-mono font-normal text-muted-foreground text-xs">
						{role.key}
					</span>
					{role.builtin && <Badge variant="secondary">内置</Badge>}
					{role.default && canMark && !editable && (
						<Badge variant="secondary" title="新用户自动获得">
							默认
						</Badge>
					)}
				</ItemTitle>
				<ItemDescription className="text-xs">
					{role.permissions.length} 项权限 ·{" "}
					<Link
						to="/console/users"
						search={{ api: def.identifier, role: role.key }}
					>
						{role.users} 个用户
					</Link>
					{role.applications > 0 && ` · ${role.applications} 个 Application`}
				</ItemDescription>
			</ItemContent>
			{editable && (
				<ItemActions>
					{canMark && (
						<Label
							className="text-muted-foreground text-xs font-normal"
							title="新用户创建时自动获得它"
						>
							<Checkbox
								checked={role.default}
								disabled={mark.isPending}
								onCheckedChange={(on) => mark.mutate(on === true)}
							/>
							默认
						</Label>
					)}
					<Button size="sm" variant="ghost" onClick={onEdit}>
						编辑
					</Button>
					<ConfirmDialog
						trigger={
							<Button size="sm" variant="ghost" disabled={remove.isPending}>
								删除
							</Button>
						}
						title={`删除角色「${role.name}」？`}
						action="删除角色"
						onConfirm={() => remove.mutate(held.length > 0)}
					>
						{held.length
							? `它仍分配给 ${held.join("、")}，删除后这些持有者随即失去它。此操作无法撤销。`
							: "没有用户或 Application 持有它。此操作无法撤销。"}
					</ConfirmDialog>
				</ItemActions>
			)}
		</Item>
	);
}

// RoleForm edits a Role; without one it defines a new one.
function RoleForm({
	def,
	role,
	onDone,
}: {
	def: APIDef;
	role?: RoleDef;
	onDone: () => void;
}) {
	const put = useAPIMutation(
		(v: { key: string; name: string; permissions: string[] }) =>
			api(`${apiPath(def.identifier)}/roles/${encodeURIComponent(v.key)}`, {
				method: "PUT",
				body: {
					name: v.name,
					permissions: v.permissions,
					// 默认 Role is toggled on the row; keep it as it is here, so
					// an edit never clears it.
					default: role?.default ?? false,
				},
			}),
	);
	const form = useForm({
		defaultValues: {
			key: role?.key ?? "",
			name: role?.name ?? "",
			permissions: role?.permissions ?? [],
		},
		validationLogic: revalidateLogic(),
		validators: { onDynamic: roleSchema },
		onSubmit: ({ value }) =>
			put.mutate(
				{ ...value, key: value.key.trim(), name: value.name.trim() },
				{
					onSuccess: () => {
						saved();
						onDone();
					},
				},
			),
	});
	return (
		<form
			noValidate
			className="flex flex-col gap-5"
			onSubmit={(e) => {
				e.preventDefault();
				form.handleSubmit();
			}}
		>
			{!role && (
				<form.Field name="key">
					{(field) => (
						<FormField field={field} label="角色 key">
							{(control) => (
								<Input
									{...control}
									placeholder="如：editor"
									className="font-mono"
								/>
							)}
						</FormField>
					)}
				</form.Field>
			)}
			<form.Field name="name">
				{(field) => (
					<FormField field={field} label="名称">
						{(control) => <Input {...control} placeholder="如：编辑" />}
					</FormField>
				)}
			</form.Field>
			<form.Field name="permissions">
				{(field) => (
					<FieldSet>
						<FieldLegend variant="label">权限</FieldLegend>
						{def.permissions.length === 0 ? (
							<p className="text-muted-foreground text-[13px]">
								这个 API 资源还没有权限，先到「权限」标签定义。
							</p>
						) : (
							<div className="flex max-h-64 flex-wrap gap-x-4 gap-y-2 overflow-y-auto">
								{def.permissions.map((p) => (
									<Label key={p.key} className="font-normal">
										<Checkbox
											checked={field.state.value.includes(p.key)}
											onCheckedChange={(on) =>
												field.handleChange(
													on
														? [...field.state.value, p.key]
														: field.state.value.filter((k) => k !== p.key),
												)
											}
										/>
										{p.name}
									</Label>
								))}
							</div>
						)}
					</FieldSet>
				)}
			</form.Field>
			<FormError error={put.error} />
			<div className="flex gap-2">
				<Button type="submit" disabled={put.isPending}>
					保存
				</Button>
				<Button type="button" variant="ghost" onClick={onDone}>
					取消
				</Button>
			</div>
		</form>
	);
}

function DeleteAPI({
	def,
	defaulting,
}: {
	def: APIDef;
	defaulting: Application[];
}) {
	const can = useCan();
	const client = useQueryClient();
	const navigate = useNavigate();
	// The confirm dialog already warns that role assignments go too.
	const remove = useMutation({
		mutationFn: () =>
			api(`${apiPath(def.identifier)}?force=true`, { method: "DELETE" }),
		onSuccess: async () => {
			await navigate({ to: "/console/apis" });
			client.invalidateQueries(apisQuery);
		},
		onError: failed("删除 API 资源失败"),
	});
	if (!can("applications:write") || def.builtin) {
		return null;
	}
	return (
		<DangerZone title="删除 API 资源">
			{defaulting.length ? (
				<div className="space-y-1 text-sm">
					<p>先在这些应用里改掉默认 API 资源：</p>
					<AppLinks apps={defaulting} />
				</div>
			) : (
				<p className="text-sm">
					它的权限、角色和所有角色分配都会一起删除。此操作无法撤销。
				</p>
			)}
			<ConfirmDialog
				trigger={
					<Button
						variant="destructive"
						disabled={defaulting.length > 0 || remove.isPending}
					>
						删除 API 资源
					</Button>
				}
				title={`删除 API 资源「${def.name}」？`}
				action="删除 API 资源"
				onConfirm={() => remove.mutate()}
			>
				它的权限、角色和所有角色分配都会一起删除，用户随即失去这些角色。此操作无法撤销。
			</ConfirmDialog>
		</DangerZone>
	);
}

function CannotCreate() {
	return (
		<span className="text-muted-foreground">需要「管理员」角色才能创建。</span>
	);
}
