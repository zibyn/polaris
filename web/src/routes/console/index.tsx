import {
	queryOptions,
	useQuery,
	useSuspenseQuery,
} from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import {
	AppWindow,
	BookOpen,
	Check,
	Fingerprint,
	KeyRound,
	LogIn,
	type LucideIcon,
	Mail,
	MonitorSmartphone,
	Server,
	Smartphone,
	UserPlus,
	Users,
	X,
} from "lucide-react";
import { useEffect, useState } from "react";
import { Alert, AlertDescription } from "#/components/ui/alert";
import { Badge } from "#/components/ui/badge";
import { Button, buttonVariants } from "#/components/ui/button";
import {
	Card,
	CardAction,
	CardContent,
	CardDescription,
	CardFooter,
	CardHeader,
	CardTitle,
} from "#/components/ui/card";
import {
	Empty,
	EmptyDescription,
	EmptyHeader,
	EmptyTitle,
} from "#/components/ui/empty";
import {
	Tooltip,
	TooltipContent,
	TooltipTrigger,
} from "#/components/ui/tooltip";
import { ownCount } from "#/lib/apps";
import { type AuditEvent, api, type Overview } from "#/lib/console-api";
import { lastRotation } from "#/lib/login";
import { checklist, checklistDone, checklistSummary } from "#/lib/overview";
import { applicationsQuery, channelsQuery, policyQuery } from "#/lib/queries";
import { Section } from "#/routes/console/-components/section";
import { signingKeysQuery } from "#/routes/console/-settings/security";
import { apisQuery } from "#/routes/console/apis/index";
import { EventList } from "#/routes/console/audit";
import { useCan, useMe } from "#/routes/console/route";

const overviewQuery = queryOptions({
	queryKey: ["overview"],
	queryFn: () => api<Overview>("/overview"),
});

export const Route = createFileRoute("/console/")({
	staticData: { useHeader: () => ({ title: "概览" }) },
	loader: ({ context }) => context.queryClient.ensureQueryData(overviewQuery),
	component: Home,
});

type Stat = {
	label: string;
	icon: LucideIcon;
	value?: number;
	hint?: string;
	trend?: { day: string; n: number }[];
};

// Sparkline is a stat's last 7 days: the shape only, no axes; each day
// says its figure on hover.
function Sparkline({ days }: { days: { day: string; n: number }[] }) {
	const max = Math.max(1, ...days.map((d) => d.n));
	const x = (i: number) => (i * 100) / (days.length - 1);
	const y = (n: number) => 30 - (n * 26) / max;
	return (
		<svg
			viewBox="0 0 100 32"
			preserveAspectRatio="none"
			className="h-8 w-full overflow-visible text-primary"
			role="img"
			aria-label={`近 7 天：${days.map((d) => d.n).join("、")}`}
		>
			<polyline
				fill="none"
				stroke="currentColor"
				strokeWidth="1.5"
				vectorEffect="non-scaling-stroke"
				points={days.map((d, i) => `${x(i)},${y(d.n)}`).join(" ")}
			/>
			{days.map((d, i) => (
				<circle key={d.day} cx={x(i)} cy={y(d.n)} r="4" fill="transparent">
					<title>
						{d.day.slice(5).replace("-", "/")}：{d.n}
					</title>
				</circle>
			))}
		</svg>
	);
}

function Home() {
	const can = useCan();
	const o = useSuspenseQuery(overviewQuery).data;
	const apps = useQuery({
		...applicationsQuery,
		enabled: can("applications:read"),
	}).data;
	// 应用 counts only your own, so it needs the list; without
	// applications:read the figure isn't shown.
	const stats: Stat[] = [
		{
			label: "用户",
			icon: Users,
			value: o.users,
			hint: "近 7 天每日新增",
			trend: o.trend.map((d) => ({ day: d.day, n: d.users })),
		},
		{
			label: "今日新登录",
			icon: LogIn,
			value: o.loginsToday,
			hint: "今天新建的会话数，下为近 7 天",
			trend: o.trend.map((d) => ({ day: d.day, n: d.logins })),
		},
		{ label: "活跃会话", icon: MonitorSmartphone, value: o.liveSessions },
	];
	if (can("applications:read")) {
		stats.push({
			label: "应用",
			icon: AppWindow,
			value: apps && ownCount(apps.applications),
			hint: "不含内置应用",
		});
	}
	return (
		<div className="space-y-4">
			{o.sendsLastDay >= o.dailySendLimit && (
				<Alert variant="destructive">
					<AlertDescription>
						过去 24 小时已发送 {o.sendsLastDay} 条验证码，达到每日上限{" "}
						{o.dailySendLimit}，已停止发送。可在「验证码通道」中调整上限。
					</AlertDescription>
				</Alert>
			)}
			<Checklist />
			<section className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
				{stats.map(({ label, icon: Icon, value, hint, trend }) => (
					<Card key={label} className="@container/card">
						<CardHeader>
							<CardDescription>{label}</CardDescription>
							<CardTitle className="font-semibold text-2xl tabular-nums @[250px]/card:text-3xl">
								{value ?? "–"}
							</CardTitle>
							<CardAction>
								<Icon className="size-4 text-muted-foreground" aria-hidden />
							</CardAction>
						</CardHeader>
						{(hint || trend) && (
							<CardFooter className="flex-col items-start gap-2 border-t-0 bg-transparent pt-0 text-muted-foreground text-sm">
								{trend && <Sparkline days={trend} />}
								{hint}
							</CardFooter>
						)}
					</Card>
				))}
			</section>
			<div className="grid items-start gap-4 lg:grid-cols-[minmax(0,1fr)_20rem]">
				{can("audit:read") ? <Recent /> : <div />}
				<div className="space-y-4">
					<QuickActions />
					{can("config:read") && <ConfigStatus />}
				</div>
			</div>
		</div>
	);
}

const quick = buttonVariants({
	variant: "outline",
	className: "h-auto justify-start py-2.5",
});

// QuickActions are the creates an admin may start from here.
function QuickActions() {
	const can = useCan();
	const actions = [
		can("users:write") && (
			<Link key="user" to="/console/users/new" className={quick}>
				<UserPlus />
				创建用户
			</Link>
		),
		can("applications:write") && (
			<Link
				key="app"
				to="/console/apps"
				search={{ create: true }}
				className={quick}
			>
				<AppWindow />
				创建应用
			</Link>
		),
		can("config:write") && (
			<Link
				key="provider"
				to="/console/providers"
				search={{ add: true }}
				className={quick}
			>
				<KeyRound />
				添加认证源
			</Link>
		),
		<a
			key="docs"
			className={quick}
			href="https://github.com/zibyn/polaris/tree/main/docs"
			target="_blank"
			rel="noreferrer"
		>
			<BookOpen />
			接入文档
		</a>,
	].filter(Boolean);
	return (
		<Section title="快捷操作">
			<div className="grid grid-cols-2 gap-2">{actions}</div>
		</Section>
	);
}

// ConfigStatus says how the instance stands now, each row linking to where
// it is changed. It states, it doesn't score.
function ConfigStatus() {
	const channels = useQuery(channelsQuery).data?.channels;
	const policy = useQuery(policyQuery).data;
	const keys = useQuery(signingKeysQuery).data?.keys;
	const on = (kind: "phone" | "email") =>
		channels?.some((c) => c.kind === kind);
	const rotated = keys && lastRotation(keys);
	const rows: {
		icon: LucideIcon;
		label: string;
		to: string;
		state?: boolean;
		text?: string;
	}[] = [
		{
			icon: Smartphone,
			label: "短信通道",
			to: "/console/channels",
			state: on("phone"),
		},
		{
			icon: Mail,
			label: "邮件通道",
			to: "/console/channels",
			state: on("email"),
		},
		{
			icon: Fingerprint,
			label: "Passkey",
			to: "/console/sign-in",
			state: policy?.passkeyLogin,
		},
		{
			icon: Server,
			label: "令牌签名密钥",
			to: "/console/security",
			text:
				rotated === undefined
					? undefined
					: rotated
						? `${new Date(rotated).toLocaleDateString("zh-CN")} 轮换`
						: "尚未轮换",
		},
	];
	return (
		<Section title="配置状态">
			<ul className="-mx-2 -my-1">
				{rows.map(({ icon: Icon, label, to, state, text }) => (
					<li key={label}>
						<Link
							to={to}
							className="flex items-center gap-2.5 rounded-md px-2 py-2 text-sm hover:bg-accent"
						>
							<Icon className="size-4 text-muted-foreground" aria-hidden />
							{label}
							<span className="ml-auto">
								{text !== undefined ? (
									<span className="text-faint text-xs">{text}</span>
								) : state === undefined ? null : state ? (
									<Badge variant="success">已启用</Badge>
								) : (
									<Badge variant="warning">未启用</Badge>
								)}
							</span>
						</Link>
					</li>
				))}
			</ul>
		</Section>
	);
}

// Closing the checklist, or finishing it, is remembered in this browser
// only.
const closedKey = "console.checklist.closed";
const readClosed = () => {
	try {
		return localStorage.getItem(closedKey) === "1";
	} catch {
		return false;
	}
};
const rememberClosed = () => {
	try {
		localStorage.setItem(closedKey, "1");
	} catch {}
};

function Checklist() {
	const can = useCan();
	const me = useMe();
	const [closed, setClosed] = useState(readClosed);
	const channels = useQuery({
		...channelsQuery,
		enabled: can("config:read"),
	}).data;
	const apps = useQuery({
		...applicationsQuery,
		enabled: can("applications:read"),
	}).data;
	const apis = useQuery({
		...apisQuery,
		enabled: can("applications:read"),
	}).data;
	const steps = checklist(me.permissions, {
		channels: channels?.channels,
		apps: apps?.applications,
		apis: apis?.apis,
	});
	const done = checklistDone(steps);
	useEffect(() => {
		if (done) {
			rememberClosed();
		}
	}, [done]);
	const summary = checklistSummary(steps);
	if (!summary || closed) {
		return null;
	}
	const steps_ = steps ?? [];
	return (
		<Card>
			<CardHeader>
				<CardTitle>{summary.title}</CardTitle>
				<CardDescription>
					几步让第一个应用用上统一登录，已完成 {summary.done} / {summary.total}
					。
				</CardDescription>
				<CardAction>
					<Tooltip>
						<TooltipTrigger
							render={
								<Button
									variant="ghost"
									size="icon-sm"
									aria-label="关闭上手清单"
									onClick={() => {
										setClosed(true);
										rememberClosed();
									}}
								/>
							}
						>
							<X />
						</TooltipTrigger>
						<TooltipContent>关闭上手清单</TooltipContent>
					</Tooltip>
				</CardAction>
			</CardHeader>
			<CardContent>
				<ol className="grid gap-3 md:grid-flow-col md:auto-cols-fr">
					{steps_.map((s, i) => (
						<li
							key={s.label}
							className="flex flex-col gap-1.5 rounded-lg border p-4"
						>
							<span className="flex items-center gap-2 font-medium">
								<span
									className={`grid size-6 place-items-center rounded-full text-xs ${s.done ? "bg-primary text-primary-foreground" : "bg-muted text-muted-foreground"}`}
								>
									{s.done ? <Check className="size-3.5" /> : i + 1}
								</span>
								{s.label}
							</span>
							<p className="flex-1 text-muted-foreground text-sm">{s.desc}</p>
							<Link
								to={s.to}
								className={buttonVariants({
									size: "sm",
									variant: s === summary.next ? "default" : "outline",
									className: "mt-1 self-start",
								})}
							>
								{s.done ? "查看" : s.label}
							</Link>
						</li>
					))}
				</ol>
			</CardContent>
		</Card>
	);
}

function Recent() {
	const events = useQuery({
		queryKey: ["audit", "recent"],
		queryFn: () => api<{ events: AuditEvent[] }>("/audit?limit=10"),
	});
	return (
		<Section
			title="最近事件"
			actions={
				<Link
					to="/console/audit"
					className={buttonVariants({ variant: "link", size: "sm" })}
				>
					查看审计日志
				</Link>
			}
		>
			{events.isSuccess && events.data.events.length === 0 ? (
				<Empty className="border">
					<EmptyHeader>
						<EmptyTitle>最近没有事件</EmptyTitle>
						<EmptyDescription>超过保留期的审计记录会被删除。</EmptyDescription>
					</EmptyHeader>
				</Empty>
			) : (
				<EventList events={events.data?.events ?? []} />
			)}
		</Section>
	);
}
