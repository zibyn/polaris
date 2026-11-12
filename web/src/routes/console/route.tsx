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
	AppWindow,
	BookOpen,
	KeyRound,
	LayoutDashboard,
	LockKeyhole,
	LogIn,
	type LucideIcon,
	MessageSquareText,
	ScrollText,
	Server,
	Users,
} from "lucide-react";
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
import {
	Sidebar,
	SidebarContent,
	SidebarFooter,
	SidebarGroup,
	SidebarGroupLabel,
	SidebarHeader,
	SidebarInset,
	SidebarMenu,
	SidebarMenuButton,
	SidebarMenuItem,
	SidebarProvider,
	SidebarTrigger,
	useSidebar,
} from "#/components/ui/sidebar";
import { Tabs, TabsList, TabsTrigger } from "#/components/ui/tabs";
import { UserAvatar } from "#/components/user-avatar";
import { APIError, api, logout, type Me } from "#/lib/console-api";
import { navItems, navSections, needsTwoFactor } from "#/lib/nav";

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
				<div className="space-y-4 text-center">
					<p>当前账号不是管理员，无法使用管理端</p>
					<Button size="sm" onClick={logout}>
						退出登录
					</Button>
				</div>
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
				管理员须开启两步验证或添加 Passkey，在账号中心完成设置后即可使用管理端。
			</AlertDescription>
			<AlertAction>
				<Button size="sm" render={<Link to="/account" />}>
					前往账号中心
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
	// ids is a detail page's identifiers (IdLine), the values admins copy
	// into code and config, right under the title.
	ids?: ReactNode;
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

const icons: Record<string, LucideIcon> = {
	"/console": LayoutDashboard,
	"/console/apps": AppWindow,
	"/console/apis": Server,
	"/console/sign-in": LogIn,
	"/console/providers": KeyRound,
	"/console/channels": MessageSquareText,
	"/console/users": Users,
	"/console/audit": ScrollText,
	"/console/security": LockKeyhole,
};

// Every item names its pages, whatever the admin may open.
const all = ["users:read", "applications:read", "audit:read", "config:read"];
const allSections = navSections(all);

// useNavItem is the sidebar item the current page sits under.
function useNavItem() {
	const path = useLocation({ select: (l) => l.pathname.replace(/\/$/, "") });
	return navItems(all)
		.filter((g) => path === g.to || path.startsWith(`${g.to}/`))
		.at(-1);
}

// Crumbs sits in the top bar: the section, the item, then each matched
// route that names itself. The last is the page you're on, bold and not a
// link; a section title is never a link, there is no page behind it.
function Crumbs() {
	const item = useNavItem();
	const section = allSections.find((s) =>
		s.items.some((i) => i.to === item?.to),
	)?.title;
	const crumbs = [
		...(item ? [{ id: item.to, pathname: item.to, crumb: item.label }] : []),
		...useMatches().flatMap((m) =>
			m.staticData.crumb ? [{ ...m, crumb: m.staticData.crumb }] : [],
		),
	];
	return (
		<Breadcrumb className="min-w-0">
			<BreadcrumbList className="flex-nowrap text-[13px]">
				{section && (
					<>
						<BreadcrumbItem className="max-sm:hidden">{section}</BreadcrumbItem>
						<BreadcrumbSeparator className="max-sm:hidden" />
					</>
				)}
				{crumbs.map(({ id, pathname, crumb: C }, i) => {
					const label = typeof C === "string" ? C : <C />;
					return (
						<Fragment key={id}>
							{i > 0 && <BreadcrumbSeparator />}
							<BreadcrumbItem className="min-w-0">
								{i < crumbs.length - 1 ? (
									<BreadcrumbLink render={<Link to={pathname} />}>
										{label}
									</BreadcrumbLink>
								) : (
									<BreadcrumbPage className="truncate font-medium">
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
			<div className="space-y-6">
				{header && <PageHeader {...header} />}
				<Outlet />
			</div>
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
	const leaf = useMatches({ select: (m) => m[m.length - 1] });
	const locked = useTwoFactorLock();
	if (locked) {
		return (
			<FullPage>
				<TwoFactorFirst />
			</FullPage>
		);
	}
	return (
		<SidebarProvider className="text-sm">
			<Nav />
			<SidebarInset className="min-w-0 bg-background">
				<header className="sticky top-0 z-10 flex h-14 items-center gap-3 border-b bg-background/85 px-4 backdrop-blur sm:px-6">
					<SidebarTrigger aria-label="菜单" className="md:hidden" />
					<Crumbs />
					<Button
						variant="ghost"
						size="icon"
						className="ml-auto text-muted-foreground"
						nativeButton={false}
						render={
							// biome-ignore lint/a11y/useAnchorContent: the label is aria-label
							<a
								href="https://github.com/zibyn/polaris/tree/main/docs"
								target="_blank"
								rel="noreferrer"
								aria-label="文档"
							/>
						}
					>
						<BookOpen />
					</Button>
				</header>
				<div className="w-full max-w-[1320px] px-4 pt-6 pb-24 sm:px-8 sm:pt-7">
					{/* Lists use the whole width; form fields stop at a readable width. */}
					<div className="[&_[data-slot=field]]:max-w-[560px]">
						<Page
							key={leaf.routeId}
							useHeader={leaf.staticData.useHeader ?? noHeader}
						/>
					</div>
				</div>
			</SidebarInset>
		</SidebarProvider>
	);
}

// Nav is the console's sidebar: the mark (room to switch to other
// products later, not clickable yet), the sections, and the signed-in
// admin's menu. Below md it opens as a drawer.
function Nav() {
	const me = useMe();
	const { setOpenMobile } = useSidebar();
	const active = useNavItem()?.to;
	return (
		<Sidebar collapsible="offcanvas">
			<SidebarHeader>
				<div className="flex items-center gap-2.5 px-2 pt-2 pb-1">
					<span className="grid size-7 place-items-center rounded-lg bg-primary text-primary-foreground">
						<Star className="size-3.5" />
					</span>
					<span className="font-semibold text-[15px] text-foreground">
						Polaris
					</span>
				</div>
			</SidebarHeader>
			<SidebarContent className="gap-0">
				{navSections(me.permissions).map((s) => (
					<SidebarGroup key={s.title} className="py-1">
						{s.title && <SidebarGroupLabel>{s.title}</SidebarGroupLabel>}
						<SidebarMenu>
							{s.items.map((g) => {
								const Icon = icons[g.to];
								return (
									<SidebarMenuItem key={g.to}>
										<SidebarMenuButton
											isActive={active === g.to}
											className="font-medium data-active:[&_svg]:text-primary"
											render={
												<Link to={g.to} onClick={() => setOpenMobile(false)} />
											}
										>
											{Icon && <Icon />}
											{g.label}
										</SidebarMenuButton>
									</SidebarMenuItem>
								);
							})}
						</SidebarMenu>
					</SidebarGroup>
				))}
			</SidebarContent>
			<SidebarFooter className="border-t">
				<SidebarMenu>
					<SidebarMenuItem>
						<DropdownMenu>
							<DropdownMenuTrigger render={<SidebarMenuButton size="lg" />}>
								<UserAvatar name={me.identifier} />
								<span
									title={me.identifier}
									className="truncate font-medium text-foreground"
								>
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
					</SidebarMenuItem>
				</SidebarMenu>
			</SidebarFooter>
		</Sidebar>
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
	ids,
	details,
	tabs,
}: Header) {
	return (
		<header className="space-y-4">
			<div>
				<div className="flex flex-wrap items-center gap-3">
					<h1 className="flex items-center gap-3 font-semibold text-[22px] tracking-tight">
						{title}
					</h1>
					{badges}
					{actions && (
						<div className="ml-auto flex flex-wrap items-center gap-2">
							{actions}
						</div>
					)}
				</div>
				{ids && (
					<div className="mt-2.5 flex flex-wrap items-center gap-2">{ids}</div>
				)}
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
