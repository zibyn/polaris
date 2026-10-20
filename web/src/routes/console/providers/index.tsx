import {
	queryOptions,
	useMutation,
	useQuery,
	useQueryClient,
	useSuspenseQuery,
} from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import { createColumnHelper } from "@tanstack/react-table";
import { useMemo } from "react";
import { DataTable, type features } from "#/components/data-table";
import { failed } from "#/components/form";
import { Badge } from "#/components/ui/badge";
import { Button, buttonVariants } from "#/components/ui/button";
import {
	Empty,
	EmptyContent,
	EmptyDescription,
	EmptyHeader,
	EmptyTitle,
} from "#/components/ui/empty";
import { api, type ProviderInfo, type ProviderType } from "#/lib/console-api";
import { disableImpact } from "#/lib/login";
import { ConfirmDialog } from "#/routes/console/-components/confirm-dialog";
import { type Header, useCan } from "#/routes/console/route";

export const Route = createFileRoute("/console/providers/")({
	staticData: { useHeader },
	loader: ({ context: { queryClient } }) =>
		queryClient.ensureQueryData(providersQuery),
	component: Providers,
});

export const providersQuery = queryOptions({
	queryKey: ["providers"],
	queryFn: () =>
		api<{ types: ProviderType[]; providers: ProviderInfo[] }>("/providers"),
});

// useAdd is the one 添加认证源 button, or false without the Permission.
// With no Providers yet the empty state carries it instead of the header.
function useAdd(providers?: ProviderInfo[]) {
	const can = useCan();
	const add = can("config:write") && (
		<Link to="/console/providers/new" className={buttonVariants()}>
			添加认证源
		</Link>
	);
	return { add, empty: providers?.length === 0 };
}

function useHeader(): Header | null {
	// The header draws around the page's loading, so it reads the cache
	// without suspending.
	const providers = useQuery(providersQuery).data?.providers;
	const { add, empty } = useAdd(providers);
	return {
		title: "认证源",
		description:
			"用户可以在登录页用这些账号登录，比如 Google 或公司自建的 Keycloak。第一次用它登录的用户会自动注册。",
		actions: !empty && add,
	};
}

const helper = createColumnHelper<typeof features, ProviderInfo>();

function Providers() {
	const { types, providers } = useSuspenseQuery(providersQuery).data;
	const editable = useCan()("config:write");
	const { add, empty } = useAdd(providers);
	const columns = useMemo(
		() => [
			helper.accessor("name", {
				header: "名称",
				sortFn: "alphanumeric",
				cell: ({ row }) => (
					<Link
						to="/console/providers/$id"
						params={{ id: row.original.id }}
						className="font-medium hover:underline"
					>
						{row.original.name}
					</Link>
				),
			}),
			helper.accessor(
				(p) => types.find((t) => t.key === p.type)?.name ?? p.type,
				{ id: "type", header: "类型", sortFn: "alphanumeric" },
			),
			helper.accessor("id", {
				header: "Provider ID",
				sortFn: "alphanumeric",
				cell: ({ getValue }) => (
					<span className="font-mono text-muted-foreground text-xs">
						{getValue()}
					</span>
				),
			}),
			helper.accessor((p) => (p.enabled ? 1 : 0), {
				id: "status",
				header: "状态",
				sortFn: "basic",
				cell: ({ row }) =>
					row.original.enabled ? (
						<Badge variant="success">已启用</Badge>
					) : (
						<Badge variant="secondary">已停用</Badge>
					),
			}),
			helper.accessor("bound", {
				header: "已绑定人数",
				sortFn: "basic",
				cell: ({ getValue }) => (
					<span className="tabular-nums">{getValue()}</span>
				),
			}),
			helper.display({
				id: "actions",
				header: "",
				enableSorting: false,
				enableGlobalFilter: false,
				cell: ({ row }) =>
					editable ? <ProviderActions provider={row.original} /> : null,
			}),
		],
		[types, editable],
	);
	return (
		<div className="flex flex-col gap-6">
			{empty && (
				<Empty className="border">
					<EmptyHeader>
						<EmptyTitle>还没有添加认证源</EmptyTitle>
						<EmptyDescription>
							加上 Google、GitHub
							这些认证源，用户就能用它们登录；不加的话，用户只能用密码或验证码。
						</EmptyDescription>
					</EmptyHeader>
					<EmptyContent>
						{add || (
							<span className="text-muted-foreground">
								需要「管理员」角色才能添加。
							</span>
						)}
					</EmptyContent>
				</Empty>
			)}
			{!empty && (
				<DataTable
					data={providers}
					columns={columns}
					filterPlaceholder="搜索认证源名称、类型或 ID"
					empty="没有匹配的认证源"
				/>
			)}
		</div>
	);
}

// ProviderActions is a row's 编辑/停用/启用/删除, with the confirmations.
function ProviderActions({ provider: p }: { provider: ProviderInfo }) {
	const client = useQueryClient();
	const act = useMutation({
		mutationFn: (a: {
			method: "POST" | "DELETE";
			path: string;
			what: string;
		}) =>
			api(`/providers/${encodeURIComponent(p.id)}${a.path}`, {
				method: a.method,
			}),
		onSuccess: () => client.invalidateQueries(providersQuery),
		onError: (e, a) => failed(a.what)(e),
	});
	return (
		<div className="flex justify-end gap-1">
			<Button
				size="sm"
				variant="ghost"
				render={<Link to="/console/providers/$id" params={{ id: p.id }} />}
			>
				编辑
			</Button>
			{p.enabled ? (
				<ConfirmDialog
					trigger={
						<Button size="sm" variant="ghost" disabled={act.isPending}>
							停用
						</Button>
					}
					title={`停用 ${p.name}？`}
					action="停用认证源"
					onConfirm={() =>
						act.mutate({
							method: "POST",
							path: "/disable",
							what: "停用认证源失败",
						})
					}
				>
					登录页不再显示「使用 {p.name} 登录」。{disableImpact(p)}
				</ConfirmDialog>
			) : (
				<Button
					size="sm"
					variant="ghost"
					disabled={act.isPending}
					onClick={() =>
						act.mutate({
							method: "POST",
							path: "/enable",
							what: "启用认证源失败",
						})
					}
				>
					启用
				</Button>
			)}
			{/* With bindings it can only be disabled (#87 story 5). */}
			{p.bound === 0 && (
				<ConfirmDialog
					trigger={
						<Button
							size="sm"
							variant="ghost"
							className="text-destructive"
							disabled={act.isPending}
						>
							删除
						</Button>
					}
					title={`删除 ${p.name}？`}
					action="删除认证源"
					onConfirm={() =>
						act.mutate({
							method: "DELETE",
							path: "",
							what: "删除认证源失败",
						})
					}
				>
					登录页不再显示这个按钮，它的设置一并删除。之后要用得重新添加，回调 URL
					不变。
				</ConfirmDialog>
			)}
		</div>
	);
}
