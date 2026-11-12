import { revalidateLogic, useForm } from "@tanstack/react-form";
import {
	infiniteQueryOptions,
	useQuery,
	useSuspenseInfiniteQuery,
	useSuspenseQuery,
} from "@tanstack/react-query";
import {
	createFileRoute,
	Link,
	stripSearchParams,
	useNavigate,
} from "@tanstack/react-router";
import { formatDistanceToNow } from "date-fns";
import { zhCN } from "date-fns/locale";
import { Upload } from "lucide-react";
import { useState } from "react";
import { z } from "zod";
import { Alert, AlertDescription } from "#/components/ui/alert";
import { Badge } from "#/components/ui/badge";
import { Button } from "#/components/ui/button";
import {
	Empty,
	EmptyContent,
	EmptyDescription,
	EmptyHeader,
	EmptyTitle,
} from "#/components/ui/empty";
import { Field, FieldError, FieldLabel } from "#/components/ui/field";
import { Input } from "#/components/ui/input";
import {
	Select,
	SelectContent,
	SelectItem,
	SelectTrigger,
	SelectValue,
} from "#/components/ui/select";
import {
	Table,
	TableBody,
	TableCell,
	TableHead,
	TableHeader,
	TableRow,
} from "#/components/ui/table";
import { Tabs, TabsList, TabsTrigger } from "#/components/ui/tabs";
import { UserAvatar } from "#/components/user-avatar";
import { api, type Role, type RoleInfo, type User } from "#/lib/console-api";
import { onlyAdmins, primaryIdentifier, searchSchema } from "#/lib/users";
import { providersQuery } from "#/routes/console/providers/index";
import { useCan } from "#/routes/console/route";
import { CreateUserSheet } from "./-components/create-user-form";
import { ImportUsersSheet } from "./-components/import-users";
import {
	PasswordLoginNotice,
	usePasswordLoginOff,
} from "./-components/password-login";

// statuses is the 状态 filter: 待激活 is the account an admin made that
// nobody has taken over yet, which is what they come here to find.
const statuses = ["any", "active", "pending"] as const;
const statusName: Record<(typeof statuses)[number], string> = {
	any: "全部",
	active: "已激活",
	pending: "待激活",
};

const defaults = {
	q: "",
	api: "",
	role: "",
	provider: "",
	status: "any",
} as const;
const search = z.object({
	q: z.string().default("").catch(""),
	provider: z.string().default("").catch(""),
	api: z.string().default("").catch(""),
	role: z.string().default("").catch(""),
	status: z.enum(statuses).default("any").catch("any"),
});

export const rolesQuery = {
	queryKey: ["roles"],
	queryFn: () => api<{ roles: RoleInfo[] }>("/roles"),
};

export const Route = createFileRoute("/console/users/")({
	staticData: { useHeader: () => ({ title: "用户" }) },
	validateSearch: search,
	search: { middlewares: [stripSearchParams(defaults)] },
	loaderDeps: ({ search }) => search,
	loader: ({ context: { queryClient }, deps }) =>
		Promise.all([
			queryClient.ensureInfiniteQueryData(usersQuery(deps)),
			queryClient.ensureQueryData(rolesQuery),
		]),
	component: Users,
});

const pageSize = 50;

export const usersQuery = ({
	q,
	api: roleAPI,
	role,
	provider,
	status,
}: z.infer<typeof search>) =>
	infiniteQueryOptions({
		queryKey: ["users", q, roleAPI, role, provider, status],
		initialPageParam: 0,
		queryFn: ({ pageParam }) =>
			api<{ users: User[]; hasMore: boolean }>(
				`/users?${new URLSearchParams({ q, api: roleAPI, role, provider, status, limit: `${pageSize}`, offset: `${pageParam}` })}`,
			),
		getNextPageParam: (last, pages) =>
			last.hasMore ? pages.length * pageSize : undefined,
	});

// roleKey names a Role in the filter: Role keys are unique per API only.
const roleKey = (r: Pick<Role, "api" | "key">) => `${r.api}\n${r.key}`;

export const date = (s: string) => new Date(s).toLocaleString("zh-CN");
const ago = (s: string) =>
	formatDistanceToNow(new Date(s), { addSuffix: true, locale: zhCN });

// userName shows a User by their primary Identifier; one with none falls
// back to the first 8 characters of their ID.
export const userName = (u: User) =>
	primaryIdentifier(u.identifiers) ?? (
		<span className="font-mono text-muted-foreground">{u.sub.slice(0, 8)}</span>
	);

function Users() {
	const filters = Route.useSearch();
	const { q, api: roleAPI, role, provider, status } = filters;
	const navigate = useNavigate({ from: Route.fullPath });
	const { roles } = useSuspenseQuery(rolesQuery).data;
	const users = useSuspenseInfiniteQuery(usersQuery(filters));
	const rows = users.data.pages.flatMap((p) => p.users);
	const filter = role ? roleKey({ api: roleAPI, key: role }) : "";
	const can = useCan();
	const providers = useQuery({
		...providersQuery,
		enabled: can("config:read"),
	}).data?.providers;
	const off = usePasswordLoginOff();
	const [creating, setCreating] = useState(false);
	const [importing, setImporting] = useState(false);
	// 创建用户 is a 待激活 account whose password the admin passes on; with
	// 密码登录 off there is no way into it, so the entry is disabled. When
	// the list is admin-only the guide above it carries it instead, as on 应用.
	const create =
		can("users:write") &&
		(off ? (
			<Button disabled>创建用户</Button>
		) : (
			<Button onClick={() => setCreating(true)}>创建用户</Button>
		));
	const empty = onlyAdmins(
		rows,
		users.hasNextPage,
		!!(q || role || provider || status !== "any"),
	);

	return (
		<div className="flex flex-col gap-6">
			<div className="flex flex-wrap gap-2">
				<Search
					key={q}
					q={q}
					onSearch={(value) =>
						navigate({ search: (s) => ({ ...s, q: value || undefined }) })
					}
				/>
				<Select
					value={filter}
					onValueChange={(v) => {
						const [a, r] = `${v ?? ""}`.split("\n");
						navigate({
							search: (s) => ({
								...s,
								api: r ? a : undefined,
								role: r || undefined,
							}),
						});
					}}
				>
					<SelectTrigger className="w-48" aria-label="按角色筛选">
						<SelectValue>
							{(v: string) =>
								roles.find((r) => roleKey(r) === v)?.name ?? "全部角色"
							}
						</SelectValue>
					</SelectTrigger>
					<SelectContent>
						<SelectItem value="">全部角色</SelectItem>
						{roles.map((r) => (
							<SelectItem key={roleKey(r)} value={roleKey(r)}>
								{r.name}
								<span className="text-muted-foreground text-xs">
									{r.apiName}
								</span>
							</SelectItem>
						))}
					</SelectContent>
				</Select>
				{providers && providers.length > 0 && (
					<Select
						value={provider}
						onValueChange={(v) =>
							navigate({
								search: (s) => ({ ...s, provider: `${v ?? ""}` || undefined }),
							})
						}
					>
						<SelectTrigger className="w-40" aria-label="按认证源筛选">
							<SelectValue>
								{(v: string) =>
									providers.find((p) => p.id === v)?.name ?? "全部认证源"
								}
							</SelectValue>
						</SelectTrigger>
						<SelectContent>
							<SelectItem value="">全部认证源</SelectItem>
							{providers.map((p) => (
								<SelectItem key={p.id} value={p.id}>
									{p.name}
								</SelectItem>
							))}
						</SelectContent>
					</Select>
				)}
				<Tabs
					value={status}
					onValueChange={(v) => {
						const s = `${v ?? ""}` as (typeof statuses)[number];
						navigate({
							search: (prev) => ({
								...prev,
								status: s === "any" ? undefined : s,
							}),
						});
					}}
				>
					<TabsList aria-label="按状态筛选">
						{statuses.map((s) => (
							<TabsTrigger key={s} value={s}>
								{statusName[s]}
							</TabsTrigger>
						))}
					</TabsList>
				</Tabs>
				{can("users:write") && (
					<Button variant="outline" onClick={() => setImporting(true)}>
						<Upload />
						导入
					</Button>
				)}
				{!empty && create}
			</div>
			{can("users:write") && off && <PasswordLoginNotice />}
			{empty && (
				<Empty className="border">
					<EmptyHeader>
						<EmptyTitle>
							{rows.length > 0 ? "还没有管理员以外的用户" : "还没有用户"}
						</EmptyTitle>
						<EmptyDescription>
							用户注册或由管理员创建后显示在这里。
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
			{/* Admins are Users too: they stay listed under the guide, as
			    built-in items do on 应用. */}
			{rows.length > 0 && (
				<div className="overflow-hidden rounded-lg border">
					<Table>
						<TableHeader className="bg-muted">
							<TableRow>
								<TableHead>用户</TableHead>
								<TableHead>状态</TableHead>
								<TableHead>角色</TableHead>
								<TableHead>最后登录</TableHead>
								<TableHead>注册时间</TableHead>
							</TableRow>
						</TableHeader>
						<TableBody>
							{rows.map((u) => (
								<TableRow
									key={u.sub}
									className="cursor-pointer hover:bg-muted/50"
									onClick={() =>
										navigate({
											to: "/console/users/$sub",
											params: { sub: u.sub },
										})
									}
								>
									<TableCell>
										<span className="flex items-center gap-3 font-medium">
											<UserAvatar name={primaryIdentifier(u.identifiers)} />
											{/* The row click is the mouse's way in; the name is the
									    keyboard's, and the only thing a screen reader hears. */}
											<Link
												to="/console/users/$sub"
												params={{ sub: u.sub }}
												className="rounded-sm hover:underline"
												onClick={(e) => e.stopPropagation()}
											>
												{userName(u)}
											</Link>
										</span>
										{u.identifiers.length > 1 && (
											<span className="mt-0.5 block pl-11 text-muted-foreground text-xs">
												{u.identifiers.map((i) => i.value).join(" · ")}
											</span>
										)}
									</TableCell>
									<TableCell>
										{u.disabledAt ? (
											<Badge variant="destructive">已禁用</Badge>
										) : u.pending ? (
											<Badge variant="warning">待激活</Badge>
										) : (
											<Badge variant="success">已激活</Badge>
										)}
									</TableCell>
									<TableCell>
										<span className="flex flex-wrap gap-1">
											{u.roles.map((r) => (
												<Badge key={roleKey(r)} variant="secondary">
													{r.name}
												</Badge>
											))}
										</span>
									</TableCell>
									<TableCell
										className="text-muted-foreground"
										title={
											u.lastLoginAt ? undefined : "审计保留期内没有登录记录"
										}
									>
										{u.lastLoginAt ? ago(u.lastLoginAt) : "—"}
									</TableCell>
									<TableCell className="text-muted-foreground">
										{date(u.createdAt)}
									</TableCell>
								</TableRow>
							))}
						</TableBody>
					</Table>
				</div>
			)}
			{!empty && rows.length === 0 && (
				<p className="flex items-center justify-center gap-2 py-4 text-muted-foreground">
					没有符合条件的用户
					<Button
						size="sm"
						variant="outline"
						onClick={() => navigate({ search: {} })}
					>
						清除筛选
					</Button>
				</p>
			)}
			{users.isFetchNextPageError && (
				<Alert variant="destructive">
					<AlertDescription>{users.error?.message}</AlertDescription>
				</Alert>
			)}
			{users.hasNextPage && (
				<Button
					variant="outline"
					disabled={users.isFetchingNextPage}
					onClick={() => users.fetchNextPage()}
				>
					加载更多
				</Button>
			)}
			<CreateUserSheet open={creating} onOpenChange={setCreating} />
			<ImportUsersSheet open={importing} onOpenChange={setImporting} />
		</div>
	);
}

// Search is the user search box; it searches on Enter.
export function Search({
	q,
	onSearch,
}: {
	q: string;
	onSearch: (q: string) => void;
}) {
	const form = useForm({
		defaultValues: { q },
		validationLogic: revalidateLogic(),
		validators: { onDynamic: searchSchema },
		onSubmit: ({ value }) => onSearch(value.q.trim()),
	});
	return (
		<form
			noValidate
			className="flex-1"
			onSubmit={(e) => {
				e.preventDefault();
				form.handleSubmit();
			}}
		>
			<form.Field name="q">
				{(field) => {
					const invalid = !field.state.meta.isValid;
					return (
						<Field data-invalid={invalid}>
							<FieldLabel htmlFor="user-search" className="sr-only">
								搜索用户
							</FieldLabel>
							<Input
								id="user-search"
								type="search"
								value={field.state.value}
								onBlur={field.handleBlur}
								onChange={(e) => field.handleChange(e.target.value)}
								aria-invalid={invalid}
								placeholder="搜索手机号、邮箱、用户名或用户 ID"
							/>
							{invalid && <FieldError errors={field.state.meta.errors} />}
						</Field>
					);
				}}
			</form.Field>
		</form>
	);
}
