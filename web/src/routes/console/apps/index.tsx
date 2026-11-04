import { useQuery, useSuspenseQuery } from "@tanstack/react-query";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { createColumnHelper } from "@tanstack/react-table";
import { useMemo } from "react";
import { z } from "zod";
import { DataTable, type features } from "#/components/data-table";
import { Badge } from "#/components/ui/badge";
import { buttonVariants } from "#/components/ui/button";
import {
	Empty,
	EmptyContent,
	EmptyDescription,
	EmptyHeader,
	EmptyTitle,
} from "#/components/ui/empty";
import { onlyBuiltin, typeName } from "#/lib/apps";
import { type Application, api } from "#/lib/console-api";
import { apisQuery } from "#/routes/console/apis/index";
import { type Header, useCan } from "#/routes/console/route";
import { CreateAppSheet } from "./-components/create-app";

export const Route = createFileRoute("/console/apps/")({
	staticData: { useHeader },
	// create opens 创建应用 in a drawer over the list
	validateSearch: z.object({ create: z.boolean().optional().catch(undefined) }),
	loader: ({ context: { queryClient } }) =>
		Promise.all([
			queryClient.ensureQueryData(applicationsQuery),
			queryClient.ensureQueryData(apisQuery),
		]),
	component: Applications,
});

export const applicationsQuery = {
	queryKey: ["applications"],
	queryFn: () => api<{ applications: Application[] }>("/applications"),
};

// useCreate is the one create button, or false without the Permission.
// When there are no apps of your own, the empty state carries it instead
// of the header.
function useCreate(applications?: Application[]) {
	const can = useCan();
	const create = can("applications:write") && (
		<Link
			to="/console/apps"
			search={{ create: true }}
			className={buttonVariants()}
		>
			创建应用
		</Link>
	);
	const empty = !!applications && onlyBuiltin(applications);
	return { create, empty };
}

function useHeader(): Header | null {
	// The header draws in the layout, around the page's loading and
	// errors, so it reads without suspending.
	const apps = useQuery(applicationsQuery).data;
	const { create, empty } = useCreate(apps?.applications);
	return { title: "应用", actions: !empty && create };
}

const helper = createColumnHelper<typeof features, Application>();

function Applications() {
	const { applications } = useSuspenseQuery(applicationsQuery).data;
	const { apis } = useSuspenseQuery(apisQuery).data;
	const { create, empty } = useCreate(applications);
	const creating = !!Route.useSearch().create;
	const navigate = useNavigate({ from: Route.fullPath });
	const columns = useMemo(() => {
		const apiName = (identifier?: string) =>
			apis.find((a) => a.identifier === identifier)?.name ?? identifier;
		return [
			helper.accessor("name", {
				header: "名称",
				sortFn: "alphanumeric",
				cell: ({ row }) => (
					<>
						<Link
							to="/console/apps/$clientId"
							params={{ clientId: row.original.clientId }}
							className="font-medium hover:underline"
						>
							{row.original.name}
						</Link>{" "}
						{row.original.builtin && <Badge variant="secondary">内置</Badge>}
					</>
				),
			}),
			helper.accessor("clientId", {
				header: "client_id",
				sortFn: "alphanumeric",
				cell: ({ getValue }) => (
					<span className="font-mono text-muted-foreground text-xs">
						{getValue()}
					</span>
				),
			}),
			helper.accessor("type", {
				header: "类型",
				sortFn: "alphanumeric",
				cell: ({ getValue }) => typeName[getValue()],
			}),
			helper.accessor((a) => a.defaultApi ?? "", {
				id: "defaultApi",
				header: "默认 API 资源",
				sortFn: "alphanumeric",
				cell: ({ row }) => apiName(row.original.defaultApi) || "—",
			}),
		];
	}, [apis]);
	return (
		<div className="flex flex-col gap-6">
			{empty && (
				<Empty className="border">
					<EmptyHeader>
						<EmptyTitle>还没有应用</EmptyTitle>
						<EmptyDescription>
							App、网站或小程序需先在此创建，用户才能登录。
						</EmptyDescription>
					</EmptyHeader>
					<EmptyContent>
						{create || (
							<span className="text-muted-foreground">
								需要「管理员」角色才能创建。
							</span>
						)}
					</EmptyContent>
				</Empty>
			)}
			{!empty && (
				<DataTable
					data={applications}
					columns={columns}
					filterPlaceholder="搜索应用名称或 client_id"
					empty="没有匹配的应用"
				/>
			)}
			<CreateAppSheet
				open={creating}
				onOpenChange={(open) => !open && navigate({ search: {} })}
			/>
		</div>
	);
}
