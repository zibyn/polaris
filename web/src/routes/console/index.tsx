import {
	queryOptions,
	useQuery,
	useSuspenseQuery,
} from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import { X } from "lucide-react";
import { useEffect, useState } from "react";
import { Alert, AlertDescription } from "#/components/ui/alert";
import { Button, buttonVariants } from "#/components/ui/button";
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
import { checklist, checklistDone, checklistSummary } from "#/lib/overview";
import { SectionHeading } from "#/routes/console/-components/section";
import { apisQuery } from "#/routes/console/apis/index";
import { applicationsQuery } from "#/routes/console/apps/index";
import { EventList } from "#/routes/console/audit";
import { useCan, useMe } from "#/routes/console/route";
import { channelsQuery } from "./-settings/channels";

const overviewQuery = queryOptions({
	queryKey: ["overview"],
	queryFn: () => api<Overview>("/overview"),
});

export const Route = createFileRoute("/console/")({
	staticData: { useHeader: () => ({ title: "概览" }) },
	loader: ({ context }) => context.queryClient.ensureQueryData(overviewQuery),
	component: Home,
});

type Stat = { label: string; value?: number; hint?: string };

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
		{ label: "用户", value: o.users },
		{
			label: "今日新登录",
			value: o.loginsToday,
			hint: "今天新建的会话数",
		},
		{ label: "活跃会话", value: o.liveSessions },
	];
	if (can("applications:read")) {
		stats.push({ label: "应用", value: apps && ownCount(apps.applications) });
	}
	return (
		<div className="space-y-10 pt-4">
			{o.sendsLastDay >= o.dailySendLimit && (
				<Alert variant="destructive">
					<AlertDescription>
						过去 24 小时已发送 {o.sendsLastDay} 条验证码，达到每日上限{" "}
						{o.dailySendLimit}，已停止发送。可在「通道」中调整上限。
					</AlertDescription>
				</Alert>
			)}
			<Checklist />
			<section className="grid grid-cols-2 gap-6 sm:flex sm:gap-0 sm:divide-x sm:divide-border">
				{stats.map(({ label, value, hint }) => (
					<div
						key={label}
						className="sm:flex-1 sm:px-6 sm:first:pl-0 sm:last:pr-0"
					>
						<div className="text-[13px] text-muted-foreground">{label}</div>
						<div className="mt-2 font-semibold text-3xl tabular-nums tracking-tight">
							{value ?? "–"}
						</div>
						{hint && <div className="mt-1 text-[13px] text-faint">{hint}</div>}
					</div>
				))}
			</section>
			{can("audit:read") && <Recent />}
		</div>
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
	const r = 15;
	const arc = (2 * Math.PI * r * summary.done) / summary.total;
	return (
		<section className="flex flex-wrap items-center gap-4 rounded-xl bg-primary-soft px-6 py-6">
			<div className="relative size-12 shrink-0">
				<svg
					viewBox="0 0 36 36"
					className="-rotate-90 size-12"
					aria-hidden="true"
				>
					<circle
						cx="18"
						cy="18"
						r={r}
						fill="none"
						strokeWidth="3"
						className="stroke-border"
					/>
					{summary.done > 0 && (
						<circle
							cx="18"
							cy="18"
							r={r}
							fill="none"
							strokeWidth="3"
							strokeLinecap="round"
							strokeDasharray={`${arc} ${2 * Math.PI * r}`}
							className="stroke-primary"
						/>
					)}
				</svg>
				<span className="absolute inset-0 grid place-items-center font-semibold text-primary-ink text-xs tabular-nums">
					{summary.done}/{summary.total}
				</span>
			</div>
			<div className="min-w-0 flex-1 basis-48">
				<SectionHeading title={summary.title} intro={summary.next.hint} />
			</div>
			<Link
				to={summary.next.to}
				search={"search" in summary.next ? summary.next.search : undefined}
				className={buttonVariants({ size: "lg" })}
			>
				{summary.next.label}
			</Link>
			<Tooltip>
				<TooltipTrigger
					render={
						<Button
							variant="ghost"
							size="icon"
							aria-label="关闭上手清单"
							className="text-faint hover:bg-transparent"
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
		</section>
	);
}

function Recent() {
	const events = useQuery({
		queryKey: ["audit", "recent"],
		queryFn: () => api<{ events: AuditEvent[] }>("/audit?limit=10"),
	});
	return (
		<section>
			<SectionHeading
				title="最近事件"
				actions={
					<Link
						to="/console/audit"
						className="font-medium text-[13px] text-primary-ink underline-offset-2 hover:underline"
					>
						查看全部
					</Link>
				}
			/>
			<div className="mt-2">
				{events.isSuccess && events.data.events.length === 0 ? (
					<Empty className="border">
						<EmptyHeader>
							<EmptyTitle>最近没有事件</EmptyTitle>
							<EmptyDescription>
								超过保留期的审计记录会被删除。
							</EmptyDescription>
						</EmptyHeader>
					</Empty>
				) : (
					<EventList events={events.data?.events ?? []} />
				)}
			</div>
		</section>
	);
}
