import {
	useInfiniteQuery,
	useMutation,
	useQueries,
	useQuery,
	useQueryClient,
	useSuspenseQuery,
} from "@tanstack/react-query";
import {
	createFileRoute,
	Link,
	notFound,
	stripSearchParams,
	useParams,
} from "@tanstack/react-router";
import { type ReactNode, useState } from "react";
import { z } from "zod";
import { FormError, failed, saved } from "#/components/form";
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
import {
	Item,
	ItemActions,
	ItemContent,
	ItemDescription,
	ItemTitle,
} from "#/components/ui/item";
import { Label } from "#/components/ui/label";
import { TabsContent } from "#/components/ui/tabs";
import { UserAvatar } from "#/components/user-avatar";
import { toggled } from "#/lib/apis";
import { type APIDef, api, type RoleDef, type User } from "#/lib/console-api";
import { applicationsQuery } from "#/lib/queries";
import { primaryIdentifier } from "#/lib/users";
import { ConfirmDialog } from "#/routes/console/-components/confirm-dialog";
import { FormSheet } from "#/routes/console/-components/form-sheet";
import { IdLine, Section } from "#/routes/console/-components/section";
import { PermissionPicker } from "#/routes/console/apis/-components/permission-picker";
import { RoleForm } from "#/routes/console/apis/$api/index";
import { apisQuery } from "#/routes/console/apis/index";
import { applicationRolesQuery } from "#/routes/console/apps/$clientId";
import { type Header, useCan } from "#/routes/console/route";
import { Search, userName, usersQuery } from "#/routes/console/users/index";

const defaults = { tab: "permissions" } as const;
const search = z.object({
	tab: z
		.enum(["permissions", "users", "applications"])
		.default(defaults.tab)
		.catch(defaults.tab),
});

export const Route = createFileRoute("/console/apis/$api/roles/$role")({
	staticData: { crumb: RoleName, useHeader },
	validateSearch: search,
	search: { middlewares: [stripSearchParams(defaults)] },
	component: RolePage,
});

const tabs = [
	["permissions", "权限"],
	["users", "用户"],
	["applications", "应用"],
] as const;

// useRole finds the API resource and its Role once the list is in.
function useRole() {
	const params = useParams({ from: "/console/apis/$api/roles/$role" });
	const def = useQuery(apisQuery).data?.apis.find(
		(a) => a.identifier === params.api,
	);
	return { def, role: def?.roles.find((r) => r.key === params.role) };
}

function RoleName(): ReactNode {
	return useRole().role?.name;
}

function useHeader(): Header | null {
	const { def, role } = useRole();
	if (!def || !role) {
		return null;
	}
	return {
		title: role.name,
		badges: (
			<>
				{role.builtin && <Badge variant="secondary">内置</Badge>}
				{role.default && (
					<Badge variant="secondary" title="新用户自动获得">
						默认
					</Badge>
				)}
			</>
		),
		tabs,
		ids: (
			<>
				<IdLine label="角色 key" value={role.key} />
				<span className="text-[13px] text-muted-foreground">
					所属 API 资源{" "}
					<Link
						to="/console/apis/$api"
						params={{ api: def.identifier }}
						search={{ tab: "roles" }}
						className="underline"
					>
						{def.name}
					</Link>
				</span>
			</>
		),
	};
}

function RolePage() {
	const params = Route.useParams();
	const def = useSuspenseQuery(apisQuery).data.apis.find(
		(a) => a.identifier === params.api,
	);
	const role = def?.roles.find((r) => r.key === params.role);
	if (!def || !role) {
		throw notFound();
	}
	return (
		<>
			<TabsContent value="permissions" className="max-w-3xl">
				<Permissions def={def} role={role} />
			</TabsContent>
			<TabsContent value="users">
				<RoleUsers def={def} role={role} />
			</TabsContent>
			<TabsContent value="applications">
				<RoleApplications def={def} role={role} />
			</TabsContent>
		</>
	);
}

type RoleProps = { def: APIDef; role: RoleDef };

function Permissions({ def, role }: RoleProps) {
	const can = useCan();
	// As on the API page: Management API Roles are open to owners only.
	const editable =
		can("applications:write") &&
		!role.builtin &&
		(!def.builtin || can("admin-roles:assign"));
	if (editable) {
		return <RoleForm def={def} role={role} />;
	}
	return (
		<Section title="权限" intro="持有该角色的用户和应用获得以下权限。">
			<PermissionPicker
				permissions={def.permissions}
				value={role.permissions}
				onChange={() => {}}
				disabled
			/>
		</Section>
	);
}

// useAssign gives Users the Role or takes it away, keeping their other Roles
// on the API. shortcut: it rewrites each User's Roles on the API from the
// list as fetched, so a Role assigned to them elsewhere in between is lost;
// move to a server-side add/remove endpoint if admins start racing on this.
function useAssign(def: APIDef, role: RoleDef) {
	const client = useQueryClient();
	return useMutation({
		mutationFn: ({ users, on }: { users: User[]; on: boolean }) =>
			Promise.all(
				users.map((u) =>
					api(`/users/${encodeURIComponent(u.sub)}/roles`, {
						method: "PUT",
						body: {
							api: def.identifier,
							roles: toggled(
								u.roles
									.filter((r) => r.api === def.identifier)
									.map((r) => r.key),
								[role.key],
								on,
							),
						},
					}),
				),
			),
		// Some may have gone through even when one failed.
		onSettled: () =>
			Promise.all(
				[["users"], ["user"], ["roles"], ["apis"], ["audit"]].map((queryKey) =>
					client.invalidateQueries({ queryKey }),
				),
			),
	});
}

function RoleUsers({ def, role }: RoleProps) {
	const can = useCan();
	const editable = can(def.builtin ? "admin-roles:assign" : "roles:assign");
	const holders = useInfiniteQuery({
		...usersQuery({
			q: "",
			api: def.identifier,
			role: role.key,
			provider: "",
			status: "any",
		}),
		enabled: can("users:read"),
	});
	const remove = useAssign(def, role);
	const [adding, setAdding] = useState(false);
	if (!can("users:read")) {
		return (
			<p className="text-muted-foreground text-sm">
				需要能查看用户的角色才能查看持有人。
			</p>
		);
	}
	const rows = holders.data?.pages.flatMap((p) => p.users) ?? [];
	const add = editable && (
		<Button size="sm" onClick={() => setAdding(true)}>
			分配用户
		</Button>
	);
	return (
		<Section
			title="用户"
			intro="持有该角色的用户。权限变更在其 access token 过期后生效（最长 10 分钟）。"
			actions={rows.length > 0 && add}
		>
			{holders.isPending && (
				<p className="text-muted-foreground text-sm">加载中…</p>
			)}
			{holders.isError && (
				<Alert variant="destructive">
					<AlertDescription>{holders.error.message}</AlertDescription>
				</Alert>
			)}
			{holders.isSuccess && rows.length === 0 && (
				<Empty className="border">
					<EmptyHeader>
						<EmptyTitle>还没有用户持有该角色</EmptyTitle>
						<EmptyDescription>
							{role.default
								? "这是默认角色：之后注册的新用户会自动获得。"
								: "分配后，用户的令牌会带上该角色的权限。"}
						</EmptyDescription>
					</EmptyHeader>
					{add && <EmptyContent>{add}</EmptyContent>}
				</Empty>
			)}
			<ItemList>
				{rows.map((u) => (
					<Item key={u.sub}>
						<UserAvatar name={primaryIdentifier(u.identifiers)} />
						<ItemContent>
							<ItemTitle>
								<Link
									to="/console/users/$sub"
									params={{ sub: u.sub }}
									search={{ tab: "roles" }}
									className="rounded-sm hover:underline"
								>
									{userName(u)}
								</Link>
								{u.disabledAt && <Badge variant="destructive">已禁用</Badge>}
								{u.pending && <Badge variant="warning">待激活</Badge>}
							</ItemTitle>
							<ItemDescription className="text-xs">
								{u.identifiers.map((i) => i.value).join(" · ") || "—"}
							</ItemDescription>
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
											移除
										</Button>
									}
									title={`收回 ${primaryIdentifier(u.identifiers) ?? "该用户"} 的角色「${role.name}」？`}
									action="收回角色"
									onConfirm={() =>
										remove.mutate(
											{ users: [u], on: false },
											{ onError: failed("收回角色失败") },
										)
									}
								>
									该用户在「{def.name}」上的其他角色不受影响。
								</ConfirmDialog>
							</ItemActions>
						)}
					</Item>
				))}
			</ItemList>
			{holders.hasNextPage && (
				<Button
					variant="outline"
					className="mt-3"
					disabled={holders.isFetchingNextPage}
					onClick={() => holders.fetchNextPage()}
				>
					加载更多
				</Button>
			)}
			<FormSheet
				open={adding}
				onOpenChange={setAdding}
				title={`分配角色「${role.name}」`}
				description="搜索并勾选用户，他们在该 API 资源上的其他角色保持不变。"
			>
				{adding && (
					<AddUsers def={def} role={role} onDone={() => setAdding(false)} />
				)}
			</FormSheet>
		</Section>
	);
}

// AddUsers picks Users from a search to give the Role; those who hold it
// already show ticked and can't be picked.
function AddUsers({
	def,
	role,
	onDone,
}: RoleProps & {
	onDone: () => void;
}) {
	const [q, setQ] = useState("");
	const [picked, setPicked] = useState(new Map<string, User>());
	const found = useInfiniteQuery(
		usersQuery({ q, api: "", role: "", provider: "", status: "any" }),
	);
	const assign = useAssign(def, role);
	const rows = found.data?.pages.flatMap((p) => p.users) ?? [];
	const holds = (u: User) =>
		u.roles.some((r) => r.api === def.identifier && r.key === role.key);
	const pick = (u: User, on: boolean) => {
		const next = new Map(picked);
		if (on) {
			next.set(u.sub, u);
		} else {
			next.delete(u.sub);
		}
		setPicked(next);
	};
	return (
		<div className="flex flex-col gap-4">
			<Search key={q} q={q} onSearch={setQ} />
			<div className="max-h-[50vh] divide-y overflow-y-auto rounded-lg border">
				{found.isPending && (
					<p className="px-3 py-2 text-[13px] text-muted-foreground">加载中…</p>
				)}
				{found.isSuccess && rows.length === 0 && (
					<p className="px-3 py-2 text-[13px] text-muted-foreground">
						没有符合条件的用户。
					</p>
				)}
				{rows.map((u) => (
					<Label key={u.sub} className="flex px-3 py-2 font-normal">
						<Checkbox
							disabled={holds(u)}
							checked={holds(u) || picked.has(u.sub)}
							onCheckedChange={(on) => pick(u, on)}
						/>
						<span className="min-w-0 truncate">{userName(u)}</span>
						<span className="ml-auto shrink-0 text-muted-foreground text-xs">
							{holds(u)
								? "已持有"
								: u.identifiers.map((i) => i.value).join(" · ")}
						</span>
					</Label>
				))}
				{found.hasNextPage && (
					<Button
						variant="ghost"
						className="w-full rounded-none"
						disabled={found.isFetchingNextPage}
						onClick={() => found.fetchNextPage()}
					>
						加载更多
					</Button>
				)}
			</div>
			<FormError error={assign.error} />
			<div className="flex gap-2">
				<Button
					disabled={picked.size === 0 || assign.isPending}
					onClick={() =>
						assign.mutate(
							{ users: [...picked.values()], on: true },
							{
								onSuccess: () => {
									saved();
									onDone();
								},
							},
						)
					}
				>
					分配给 {picked.size} 个用户
				</Button>
				<Button variant="ghost" onClick={onDone}>
					取消
				</Button>
			</div>
		</div>
	);
}

// RoleApplications lists the M2M Applications holding the Role. Only those
// defaulting to this API can (ADR 0015); they're assigned on their own page.
function RoleApplications({ def, role }: RoleProps) {
	const { applications } = useSuspenseQuery(applicationsQuery).data;
	const m2m = applications.filter(
		(a) => a.type === "m2m" && a.defaultApi === def.identifier,
	);
	const held = useQueries({
		queries: m2m.map((a) => applicationRolesQuery(a.clientId)),
	});
	const holding = m2m.filter((_, i) => held[i].data?.roles.includes(role.key));
	const loading = held.some((h) => h.isPending);
	return (
		<Section
			title="应用"
			intro="持有该角色的 M2M 应用。在应用详情的「角色」标签页中分配。"
		>
			{loading && <p className="text-muted-foreground text-sm">加载中…</p>}
			{!loading && holding.length === 0 && (
				<p className="text-muted-foreground text-sm">
					{m2m.length
						? "没有 M2M 应用持有该角色。"
						: "没有以该 API 资源为默认 API 的 M2M 应用。"}
				</p>
			)}
			<ItemList>
				{holding.map((a) => (
					<Item key={a.clientId}>
						<ItemContent>
							<ItemTitle>
								<Link
									to="/console/apps/$clientId"
									params={{ clientId: a.clientId }}
									search={{ tab: "roles" }}
									className="rounded-sm hover:underline"
								>
									{a.name}
								</Link>
							</ItemTitle>
							<ItemDescription className="font-mono text-xs">
								{a.clientId}
							</ItemDescription>
						</ItemContent>
					</Item>
				))}
			</ItemList>
		</Section>
	);
}
