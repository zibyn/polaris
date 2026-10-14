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
import { UserAvatar } from "#/components/user-avatar";
import { api, type Role, type RoleInfo, type User } from "#/lib/console-api";
import { onlyAdmins, primaryIdentifier, searchSchema } from "#/lib/users";
import { policyQuery } from "#/routes/console/-settings/policy";
import { useCan } from "#/routes/console/route";

// statuses is the 状态 filter: 待激活 is the account an admin made that
// nobody has taken over yet, which is what they come here to find.
const statuses = ["any", "active", "pending"] as const;
const statusName: Record<(typeof statuses)[number], string> = {
	any: "全部状态",
	active: "已激活",
	pending: "待激活",
};

const defaults = { q: "", api: "", role: "", status: "any" } as const;
const search = z.object({
	q: z.string().default("").catch(""),
	api: z.string().default("").catch(""),
	role: z.string().default("").catch(""),
	status: z.enum(statuses).default("any").catch("any"),
});

export const rolesQuery = {
	queryKey: ["roles"],
	queryFn: () => api<{ roles: RoleInfo[] }>("/roles"),
};

// usePasswordLoginOff: 创建用户 hands over a password, so with 密码登录 off
// there is nothing to create (ADR 0016) and the entry says why. Reading it
// takes config:read, which every built-in Role holding users:write also
// holds; a reader without it gets no answer here, and the server turns the
// create down in words instead.
export function usePasswordLoginOff() {
	const { data, error } = useQuery({ ...policyQuery, retry: false });
	return !error && data?.passwordLogin === "off";
}

// PasswordLoginNotice is why 创建用户 is disabled. detail is the extra
// sentence 创建页 adds: what the account you'd create is missing
// (依赖提示 #21).
export function PasswordLoginNotice({ detail }: { detail?: string }) {
	return (
		<Alert variant="warning">
			<AlertDescription>
				请先在登录方式里开启密码登录。{detail}{" "}
				<Link to="/console/settings" search={{ tab: "login" }}>
					去开启密码登录
				</Link>
			</AlertDescription>
		</Alert>
	);
}

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

const usersQuery = ({
	q,
	api: roleAPI,
	role,
	status,
}: z.infer<typeof search>) =>
	infiniteQueryOptions({
		queryKey: ["users", q, roleAPI, role, status],
		initialPageParam: 0,
		queryFn: ({ pageParam }) =>
			api<{ users: User[]; hasMore: boolean }>(
				`/users?${new URLSearchParams({ q, api: roleAPI, role, status, limit: `${pageSize}`, offset: `${pageParam}` })}`,
			),
		getNextPageParam: (last, pages) =>
			last.hasMore ? pages.length * pageSize : undefined,
	});

// roleKey names a Role in the filter: Role keys are unique per API only.
const roleKey = (r: Pick<Role, "api" | "key">) => `${r.api}\n${r.key}`;

export const date = (s: string) => new Date(s).toLocaleString("zh-CN");

// userName shows a User by their primary Identifier; one with none falls
// back to the first 8 characters of their ID.
const userName = (u: User) =>
	primaryIdentifier(u.identifiers) ?? (
		<span className="font-mono text-muted-foreground">{u.sub.slice(0, 8)}</span>
	);

function Users() {
	const filters = Route.useSearch();
	const { q, api: roleAPI, role, status } = filters;
	const navigate = useNavigate({ from: Route.fullPath });
	const { roles } = useSuspenseQuery(rolesQuery).data;
	const users = useSuspenseInfiniteQuery(usersQuery(filters));
	const rows = users.data.pages.flatMap((p) => p.users);
	const filter = role ? roleKey({ api: roleAPI, key: role }) : "";
	const can = useCan();
	const off = usePasswordLoginOff();
	// 创建用户 is a 待激活 account whose password the admin passes on; with
	// 密码登录 off there is no way into it, so the entry is disabled. When
	// the list is admin-only the empty state carries it instead, as on 应用.
	const create =
		can("users:write") &&
		(off ? (
			<Button disabled>创建用户</Button>
		) : (
			<Button render={<Link to="/console/users/new" />}>创建用户</Button>
		));
	const empty = onlyAdmins(
		rows,
		users.hasNextPage,
		!!(q || role || status !== "any"),
	);

	return (
		<div className="space-y-6">
			<div className="flex gap-2">
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
				<Select
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
					<SelectTrigger className="w-32" aria-label="按状态筛选">
						<SelectValue>
							{(v: string) => statusName[v as (typeof statuses)[number]]}
						</SelectValue>
					</SelectTrigger>
					<SelectContent>
						{statuses.map((s) => (
							<SelectItem key={s} value={s}>
								{statusName[s]}
							</SelectItem>
						))}
					</SelectContent>
				</Select>
				{!empty && create}
			</div>
			{can("users:write") && off && <PasswordLoginNotice />}
			{empty && (
				<Empty className="border">
					<EmptyHeader>
						<EmptyTitle>还没有用户注册</EmptyTitle>
						<EmptyDescription>
							用户在你的应用里第一次登录时会自动注册，之后出现在这里；你也可以直接建一个。
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
			<Table>
				<TableHeader>
					<TableRow>
						<TableHead>用户</TableHead>
						<TableHead>登录标识</TableHead>
						<TableHead>角色</TableHead>
						<TableHead>注册时间</TableHead>
					</TableRow>
				</TableHeader>
				<TableBody>
					{rows.map((u) => (
						<TableRow
							key={u.sub}
							className="cursor-pointer"
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
									{userName(u)}
									{u.disabledAt && <Badge variant="destructive">已禁用</Badge>}
									{u.pending && <Badge variant="warning">待激活</Badge>}
								</span>
							</TableCell>
							<TableCell className="text-muted-foreground">
								{u.identifiers.map((i) => i.value).join(" · ") || "—"}
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
							<TableCell className="text-muted-foreground">
								{date(u.createdAt)}
							</TableCell>
						</TableRow>
					))}
					{rows.length === 0 && !empty && (
						<TableRow>
							<TableCell
								colSpan={4}
								className="space-x-2 text-center text-muted-foreground"
							>
								<span>没有符合条件的用户</span>
								<Button
									size="sm"
									variant="outline"
									onClick={() => navigate({ search: {} })}
								>
									清除筛选
								</Button>
							</TableCell>
						</TableRow>
					)}
				</TableBody>
			</Table>
			{users.isFetchNextPageError && (
				<p className="text-destructive text-sm">{users.error?.message}</p>
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
		</div>
	);
}

// Search is the user search box; it searches on Enter.
function Search({ q, onSearch }: { q: string; onSearch: (q: string) => void }) {
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
