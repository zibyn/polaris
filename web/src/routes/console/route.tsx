import {
	type Mutation,
	type Query,
	queryOptions,
	useQueryClient,
} from "@tanstack/react-query";
import {
	createFileRoute,
	Link,
	Outlet,
	useLocation,
	useMatches,
	useNavigate,
	useRouteContext,
	useSearch,
} from "@tanstack/react-router";
import {
	type ComponentType,
	Fragment,
	type ReactNode,
	useEffect,
	useState,
} from "react";
import { FullPage, RouteError, RoutePending } from "#/components/route-states";
import { Star } from "#/components/star";
import {
	Alert,
	AlertAction,
	AlertDescription,
	AlertTitle,
} from "#/components/ui/alert";
import {
	Breadcrumb,
	BreadcrumbItem,
	BreadcrumbLink,
	BreadcrumbList,
	BreadcrumbPage,
	BreadcrumbSeparator,
} from "#/components/ui/breadcrumb";
import { Button } from "#/components/ui/button";
import {
	DropdownMenu,
	DropdownMenuContent,
	DropdownMenuItem,
	DropdownMenuTrigger,
} from "#/components/ui/dropdown-menu";
import { Tabs, TabsList, TabsTrigger } from "#/components/ui/tabs";
import { UserAvatar } from "#/components/user-avatar";
import { APIError, api, logout, type Me } from "#/lib/console-api";
import { navGroups, needsTwoFactor } from "#/lib/nav";
import { Panel } from "#/routes/console/-components/panel";

export const meQuery = queryOptions({
	queryKey: ["me"],
	queryFn: () => api<Me>("/me"),
	retry: false,
});

// Signing in is api's job: without a token it leaves for the login page
// and never returns, so nothing below renders until there's an admin.
export const Route = createFileRoute("/console")({
	beforeLoad: async ({ context }) => ({
		me: await context.queryClient.ensureQueryData({
			...meQuery,
			revalidateIfStale: true,
		}),
	}),
	pendingComponent: () => (
		<FullPage>
			<RoutePending />
		</FullPage>
	),
	errorComponent: (props) => (
		<FullPage>
			{needsTwoFactor(props.error) ? (
				<TwoFactorFirst />
			) : props.error instanceof APIError && props.error.status === 403 ? (
				<p className="text-center">你不是管理员,无法使用管理端</p>
			) : (
				<RouteError {...props} />
			)}
		</FullPage>
	),
	component: Console,
});

// TwoFactorFirst stands in for the console while 管理员必须启用两步验证或
// Passkey turns the admin away.
function TwoFactorFirst() {
	return (
		<Alert>
			<AlertTitle>需要先开启两步验证或添加 Passkey</AlertTitle>
			<AlertDescription>
				这个实例要求管理员开启两步验证或添加
				Passkey。在账号中心完成后，回来就能继续使用管理端。
			</AlertDescription>
			<AlertAction>
				<Button size="sm" render={<Link to="/account" />}>
					去账号中心
				</Button>
			</AlertAction>
		</Alert>
	);
}

// useTwoFactorLock swaps the console for TwoFactorFirst as soon as any call
// is turned away for want of 两步验证, as when the switch goes on mid-session.
function useTwoFactorLock() {
	const client = useQueryClient();
	const [locked, setLocked] = useState(false);
	useEffect(() => {
		const check = (e: { query?: Query; mutation?: Mutation }) => {
			const error = (e.query ?? e.mutation)?.state.error;
			if (needsTwoFactor(error)) setLocked(true);
		};
		const unsubs = [
			client.getQueryCache().subscribe(check),
			client.getMutationCache().subscribe(check),
		];
		return () => {
			for (const u of unsubs) u();
		};
	}, [client]);
	return locked;
}

export type Header = {
	title: ReactNode;
	badges?: ReactNode;
	actions?: ReactNode;
	description?: ReactNode;
	details?: ReactNode;
	tabs?: readonly (readonly [string, string])[];
};

declare module "@tanstack/react-router" {
	interface StaticDataRouteOption {
		// crumb names a page below its nav group in the console breadcrumb:
		// a label, or a component when the name comes from data (an
		// Application's name).
		crumb?: string | ComponentType;
		// useHeader is a hook giving the page's header, so it can read the
		// page's data; null draws none (still loading, not found).
		useHeader?: () => Header | null;
	}
}

// Every group names its pages, whatever the admin may open.
const allGroups = navGroups([
	"users:read",
	"applications:read",
	"audit:read",
	"config:read",
]);

// Crumbs is the breadcrumb atop every console page: the nav group, then
// each matched route that names itself; the last is the page you're on.
function Crumbs() {
	const path = useLocation({ select: (l) => l.pathname.replace(/\/$/, "") });
	const group = allGroups
		.filter((g) => path === g.to || path.startsWith(`${g.to}/`))
		.at(-1);
	const crumbs = [
		...(group
			? [{ id: group.to, pathname: group.to, crumb: group.label }]
			: []),
		...useMatches().flatMap((m) =>
			m.staticData.crumb ? [{ ...m, crumb: m.staticData.crumb }] : [],
		),
	];
	return (
		<Breadcrumb>
			<BreadcrumbList className="text-[13px]">
				{crumbs.map(({ id, pathname, crumb: C }, i) => {
					const label = typeof C === "string" ? C : <C />;
					return (
						<Fragment key={id}>
							{i > 0 && <BreadcrumbSeparator />}
							<BreadcrumbItem>
								{i < crumbs.length - 1 ? (
									<BreadcrumbLink render={<Link to={pathname} />}>
										{label}
									</BreadcrumbLink>
								) : (
									<BreadcrumbPage className="text-muted-foreground">
										{label}
									</BreadcrumbPage>
								)}
							</BreadcrumbItem>
						</Fragment>
					);
				})}
			</BreadcrumbList>
		</Breadcrumb>
	);
}

const noHeader = () => null;

// Page draws the matched page under its header. With tabs, both sit in
// one <Tabs> driven by the tab search param, the first tab left out of
// the URL; the page renders a TabsContent per tab.
function Page({ useHeader }: { useHeader: () => Header | null }) {
	const header = useHeader();
	const { tab } = useSearch({ strict: false });
	const navigate = useNavigate();
	if (!header?.tabs) {
		return (
			<>
				{header && <PageHeader {...header} />}
				<Outlet />
			</>
		);
	}
	const first = header.tabs[0][0];
	return (
		<Tabs
			value={tab ?? first}
			onValueChange={(v) => navigate({ to: ".", search: { tab: v } })}
			className="gap-6"
		>
			<PageHeader {...header} />
			<Outlet />
		</Tabs>
	);
}

// useMe is the signed-in admin, as the layout's beforeLoad found them.
export const useMe = () => useRouteContext({ from: "/console" }).me;

// useCan reports whether the signed-in admin holds a Permission; actions
// they lack are not shown.
export function useCan() {
	const me = useMe();
	return (permission: string) => me.permissions.includes(permission);
}

function Console() {
	const me = useMe();
	const leaf = useMatches({ select: (m) => m[m.length - 1] });
	const locked = useTwoFactorLock();
	const groups = navGroups(me.permissions);
	if (locked) {
		return (
			<FullPage>
				<TwoFactorFirst />
			</FullPage>
		);
	}
	return (
		<div className="flex min-h-svh bg-canvas p-2 text-sm">
			<aside className="sticky top-2 flex h-[calc(100svh-1rem)] w-60 shrink-0 flex-col p-4">
				{/* Room to switch to other products later; not clickable yet. */}
				<div className="flex items-center gap-3 px-2 py-2">
					<span className="grid size-8 place-items-center rounded-lg bg-primary text-primary-foreground">
						<Star className="size-4" />
					</span>
					<span className="leading-tight">
						<span className="block font-semibold">Polaris</span>
						<span className="block text-muted-foreground text-xs">Auth</span>
					</span>
				</div>
				<nav className="mt-6 space-y-1">
					{groups.map((g) => (
						<Link
							key={g.label}
							to={g.to}
							activeOptions={{ exact: g.to === "/console" }}
							className="flex items-center rounded-lg px-3 py-2"
							inactiveProps={{
								className: "text-muted-foreground hover:text-foreground",
							}}
							activeProps={{
								className: "bg-card font-medium shadow-xs ring-1 ring-border",
							}}
						>
							{g.label}
						</Link>
					))}
				</nav>
				<DropdownMenu>
					<DropdownMenuTrigger className="mt-auto flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left hover:bg-card">
						<UserAvatar name={me.identifier} />
						<span className="truncate" title={me.identifier}>
							{me.identifier}
						</span>
					</DropdownMenuTrigger>
					<DropdownMenuContent side="top">
						<DropdownMenuItem render={<Link to="/account" />}>
							账号中心
						</DropdownMenuItem>
						<DropdownMenuItem onClick={logout}>退出登录</DropdownMenuItem>
					</DropdownMenuContent>
				</DropdownMenu>
			</aside>
			<Panel className="min-w-0 flex-1 px-14 py-11">
				<div className="max-w-4xl space-y-6">
					<Crumbs />
					<Page
						key={leaf.routeId}
						useHeader={leaf.staticData.useHeader ?? noHeader}
					/>
				</div>
			</Panel>
		</div>
	);
}

// PageHeader opens every console page, below the breadcrumb: the title
// with its badges, actions on the right, an optional line on what the page
// is for, then details (notes, the 接入清单) and the tabs last.
function PageHeader({
	title,
	badges,
	actions,
	description,
	details,
	tabs,
}: Header) {
	return (
		<header className="space-y-4">
			<div>
				<div className="flex flex-wrap items-center gap-3">
					<h1 className="flex items-center gap-3 font-semibold text-2xl tracking-tight">
						{title}
					</h1>
					{badges}
					{actions && (
						<div className="ml-auto flex items-center gap-2">{actions}</div>
					)}
				</div>
				{description && (
					<p className="mt-1 text-muted-foreground">{description}</p>
				)}
			</div>
			{details}
			{tabs && (
				<TabsList variant="line">
					{tabs.map(([key, label]) => (
						<TabsTrigger key={key} value={key}>
							{label}
						</TabsTrigger>
					))}
				</TabsList>
			)}
		</header>
	);
}
