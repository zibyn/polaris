import { useSuspenseQuery } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import { createColumnHelper } from "@tanstack/react-table";
import { DataTable, type features } from "#/components/data-table";
import { Badge } from "#/components/ui/badge";
import type { APIDef, RoleDef } from "#/lib/console-api";
import { apisQuery } from "#/routes/console/apis/index";

// 角色与权限 lists every API resource's Roles in one table; adding and
// editing them stays on the API resource's own page.
export const Route = createFileRoute("/console/roles")({
	staticData: {
		useHeader: () => ({
			title: "角色与权限",
			description:
				"所有 API 资源上的角色。添加和编辑角色在对应的 API 资源中进行。",
		}),
	},
	loader: ({ context }) => context.queryClient.ensureQueryData(apisQuery),
	component: Roles,
});

type Row = RoleDef & { api: Pick<APIDef, "identifier" | "name" | "builtin"> };

const helper = createColumnHelper<typeof features, Row>();
const columns = [
	helper.accessor("name", {
		header: "角色",
		sortFn: "alphanumeric",
		cell: ({ row: { original: r } }) => (
			<span className="flex flex-wrap items-center gap-2">
				<Link
					to="/console/apis/$api/roles/$role"
					params={{ api: r.api.identifier, role: r.key }}
					className="font-medium hover:underline"
				>
					{r.name}
				</Link>
				<span className="font-mono text-muted-foreground text-xs">{r.key}</span>
				{r.builtin && <Badge variant="secondary">内置</Badge>}
				{r.default && <Badge variant="outline">默认</Badge>}
			</span>
		),
	}),
	helper.accessor((r) => r.api.name, {
		id: "api",
		header: "API 资源",
		sortFn: "alphanumeric",
		cell: ({ row: { original: r } }) => (
			<Link
				to="/console/apis/$api"
				params={{ api: r.api.identifier }}
				search={{ tab: "roles" }}
				className="hover:underline"
			>
				{r.api.name}
			</Link>
		),
	}),
	helper.accessor((r) => r.permissions.length, {
		id: "permissions",
		header: "权限",
		sortFn: "basic",
		cell: ({ getValue }) => <span className="tabular-nums">{getValue()}</span>,
	}),
	helper.accessor("users", {
		header: "持有人数",
		sortFn: "basic",
		cell: ({ getValue }) => <span className="tabular-nums">{getValue()}</span>,
	}),
];

function Roles() {
	const { apis } = useSuspenseQuery(apisQuery).data;
	const rows: Row[] = apis.flatMap((a) =>
		a.roles.map((r) => ({
			...r,
			api: { identifier: a.identifier, name: a.name, builtin: a.builtin },
		})),
	);
	return (
		<DataTable
			data={rows}
			columns={columns}
			filterPlaceholder="搜索角色或 API 资源"
			empty="没有匹配的角色"
		/>
	);
}
