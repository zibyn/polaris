import { revalidateLogic, useForm } from "@tanstack/react-form";
import {
	useMutation,
	useQueryClient,
	useSuspenseQuery,
} from "@tanstack/react-query";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { createColumnHelper } from "@tanstack/react-table";
import { DataTable, type features } from "#/components/data-table";
import { FormError, FormField } from "#/components/form";
import { Badge } from "#/components/ui/badge";
import { Button } from "#/components/ui/button";
import {
	Empty,
	EmptyContent,
	EmptyDescription,
	EmptyHeader,
	EmptyTitle,
} from "#/components/ui/empty";
import { Input } from "#/components/ui/input";
import { apiSchema } from "#/lib/apis";
import { onlyBuiltin } from "#/lib/apps";
import { type APIDef, api, apiPath } from "#/lib/console-api";
import { SectionHeading } from "#/routes/console/-components/section";
import { useCan } from "#/routes/console/route";

export const Route = createFileRoute("/console/apis/")({
	staticData: {
		useHeader: () => ({
			title: "API 资源",
			description:
				"在这里登记你的后端服务，再为它定义权限和角色。用户登录某个应用后，拿到的令牌只带这个应用默认 API 资源上的角色和权限。",
		}),
	},
	loader: ({ context }) => context.queryClient.ensureQueryData(apisQuery),
	component: APIs,
});

export const apisQuery = {
	queryKey: ["apis"],
	queryFn: () => api<{ apis: APIDef[] }>("/apis"),
};

const helper = createColumnHelper<typeof features, APIDef>();
const columns = [
	helper.accessor("name", {
		header: "名称",
		sortFn: "alphanumeric",
		cell: ({ row }) => (
			<>
				<Link
					to="/console/apis/$api"
					params={{ api: row.original.identifier }}
					className="font-medium hover:underline"
				>
					{row.original.name}
				</Link>{" "}
				{row.original.builtin && <Badge variant="secondary">内置</Badge>}
			</>
		),
	}),
	helper.accessor("identifier", {
		header: "API 资源标识符",
		sortFn: "alphanumeric",
		cell: ({ getValue }) => (
			<span className="font-mono text-muted-foreground text-xs">
				{getValue()}
			</span>
		),
	}),
	helper.accessor((a) => a.permissions.length, {
		id: "permissions",
		header: "权限",
		sortFn: "basic",
		cell: ({ getValue }) => <span className="tabular-nums">{getValue()}</span>,
	}),
	helper.accessor((a) => a.roles.length, {
		id: "roles",
		header: "角色",
		sortFn: "basic",
		cell: ({ getValue }) => <span className="tabular-nums">{getValue()}</span>,
	}),
];

function APIs() {
	const can = useCan();
	const { apis } = useSuspenseQuery(apisQuery).data;
	const writable = can("applications:write");
	return (
		<div className="flex flex-col gap-10">
			<div className="flex flex-col gap-6">
				{onlyBuiltin(apis) && (
					<Empty className="border">
						<EmptyHeader>
							<EmptyTitle>还没有你自己的 API 资源</EmptyTitle>
							<EmptyDescription>
								如果你的后端要校验用户能做什么，在这里登记它，再定义权限和角色。只用登录、不需要权限控制的话，可以不建。
							</EmptyDescription>
						</EmptyHeader>
						<EmptyContent>
							{writable ? (
								<Button
									onClick={() =>
										document
											.querySelector<HTMLInputElement>("#new-api input")
											?.focus()
									}
								>
									添加 API 资源
								</Button>
							) : (
								<span className="text-muted-foreground">
									需要「管理员」角色才能创建。
								</span>
							)}
						</EmptyContent>
					</Empty>
				)}
				<DataTable
					data={apis}
					columns={columns}
					filterPlaceholder="搜索 API 资源名称或标识符"
					empty="没有匹配的 API 资源"
				/>
			</div>
			{writable && <CreateForm />}
		</div>
	);
}

function CreateForm() {
	const client = useQueryClient();
	const navigate = useNavigate();
	const create = useMutation({
		mutationFn: (v: { identifier: string; name: string }) =>
			api(apiPath(v.identifier), { method: "PUT", body: { name: v.name } }),
		onSuccess: async (_, v) => {
			await client.invalidateQueries(apisQuery);
			navigate({ to: "/console/apis/$api", params: { api: v.identifier } });
		},
	});
	const form = useForm({
		defaultValues: { identifier: "", name: "" },
		validationLogic: revalidateLogic(),
		validators: { onDynamic: apiSchema },
		onSubmit: ({ value }) =>
			create.mutate({
				identifier: value.identifier.trim(),
				name: value.name.trim(),
			}),
	});
	return (
		<section>
			<SectionHeading
				title="添加 API 资源"
				intro="API 资源标识符是你的后端校验令牌时认的名字，即 access token 的 aud。登记后不能更改。"
			/>
			<form
				id="new-api"
				noValidate
				className="mt-4 flex flex-col gap-3"
				onSubmit={(e) => {
					e.preventDefault();
					form.handleSubmit();
				}}
			>
				<div className="flex flex-wrap items-start gap-2">
					<div className="w-72">
						<form.Field name="identifier">
							{(field) => (
								<FormField field={field} label="API 资源标识符">
									{(control) => (
										<Input
											{...control}
											placeholder="https://api.example.com"
											className="font-mono"
										/>
									)}
								</FormField>
							)}
						</form.Field>
					</div>
					<div className="w-40">
						<form.Field name="name">
							{(field) => (
								<FormField field={field} label="名称">
									{(control) => (
										<Input {...control} placeholder="如：订单 API" />
									)}
								</FormField>
							)}
						</form.Field>
					</div>
				</div>
				<FormError error={create.error} />
				<Button
					type="submit"
					disabled={create.isPending}
					className="self-start"
				>
					添加 API 资源
				</Button>
			</form>
		</section>
	);
}
