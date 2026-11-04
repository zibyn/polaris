import { revalidateLogic, useForm } from "@tanstack/react-form";
import {
	infiniteQueryOptions,
	useQuery,
	useSuspenseInfiniteQuery,
} from "@tanstack/react-query";
import {
	createFileRoute,
	Link,
	stripSearchParams,
	useNavigate,
} from "@tanstack/react-router";
import { format } from "date-fns";
import { zhCN } from "date-fns/locale";
import { CalendarIcon, Cog } from "lucide-react";
import { type ReactNode, useState } from "react";
import { z } from "zod";
import { failed } from "#/components/form";
import { ItemList } from "#/components/item-list";
import { Avatar, AvatarFallback } from "#/components/ui/avatar";
import { Button } from "#/components/ui/button";
import { Calendar } from "#/components/ui/calendar";
import { Field, FieldError, FieldLabel } from "#/components/ui/field";
import { Input } from "#/components/ui/input";
import {
	Item,
	ItemActions,
	ItemContent,
	ItemMedia,
} from "#/components/ui/item";
import {
	Popover,
	PopoverContent,
	PopoverTrigger,
} from "#/components/ui/popover";
import {
	Select,
	SelectContent,
	SelectGroup,
	SelectItem,
	SelectLabel,
	SelectTrigger,
	SelectValue,
} from "#/components/ui/select";
import { Separator } from "#/components/ui/separator";
import {
	Table,
	TableBody,
	TableCell,
	TableHead,
	TableHeader,
	TableRow,
} from "#/components/ui/table";
import { UserAvatar } from "#/components/user-avatar";
import {
	actor,
	describe,
	doneBy,
	eventGroups,
	eventName,
	findSchema,
	findUser,
	type Part,
} from "#/lib/audit";
import { type AuditEvent, api, type User } from "#/lib/console-api";
import { applicationsQuery } from "#/lib/queries";
import { primaryIdentifier } from "#/lib/users";
import { apisQuery } from "#/routes/console/apis/index";
import { useCan } from "#/routes/console/route";

const text = z.string().default("").catch("");
const search = z.object({
	event: text,
	sub: text,
	q: text, // what was typed to find sub, shown back
	since: text, // yyyy-mm-dd, local
	until: text, // yyyy-mm-dd, local, inclusive
});
const defaults = { event: "", sub: "", q: "", since: "", until: "" };

export const Route = createFileRoute("/console/audit")({
	staticData: { useHeader: () => ({ title: "审计日志" }) },
	validateSearch: search,
	search: { middlewares: [stripSearchParams(defaults)] },
	// q only echoes what was typed: it doesn't change the events.
	loaderDeps: ({ search: { q, ...deps } }) => deps,
	loader: ({ context, deps }) =>
		context.queryClient.ensureInfiniteQueryData(eventsQuery(deps)),
	component: Audit,
});

const pageSize = 50;
const date = (s: string) => new Date(s).toLocaleString("zh-CN");
// day turns a local yyyy-mm-dd into the instant it starts, days later.
const day = (s: string, days = 0) => {
	const d = new Date(`${s}T00:00`);
	d.setDate(d.getDate() + days);
	return d.toISOString();
};

const eventsQuery = ({
	event,
	sub,
	since,
	until,
}: Omit<z.infer<typeof search>, "q">) =>
	infiniteQueryOptions({
		queryKey: ["audit", event, sub, since, until],
		initialPageParam: 0,
		queryFn: ({ pageParam }) =>
			api<{ events: AuditEvent[] }>(
				`/audit?${new URLSearchParams({
					event,
					sub,
					limit: `${pageSize}`,
					...(since && { since: day(since) }),
					...(until && { until: day(until, 1) }),
					...(pageParam && { before: `${pageParam}` }),
				})}`,
			),
		getNextPageParam: (last) =>
			last.events.length === pageSize ? last.events.at(-1)?.id : undefined,
	});

function Audit() {
	const filters = Route.useSearch();
	const { event, sub, since, until } = filters;
	const navigate = useNavigate({ from: Route.fullPath });
	const can = useCan();
	const [choices, setChoices] = useState<User[]>();
	const [finding, setFinding] = useState(false);
	const events = useSuspenseInfiniteQuery(eventsQuery(filters));
	const rows = events.data.pages.flatMap((p) => p.events);
	const set = (k: keyof z.infer<typeof search>, v: string) =>
		navigate({ search: (s) => ({ ...s, [k]: v || undefined }) });
	const filterBy = (q: string, sub: string) => {
		setChoices(undefined);
		navigate({
			search: (s) => ({ ...s, q: q || undefined, sub: sub || undefined }),
		});
	};
	// find looks the typed text up as a User; without users:read it can only
	// be an ID.
	const find = async (q: string) => {
		if (!q) {
			return filterBy("", "");
		}
		setFinding(true);
		try {
			const users = can("users:read")
				? (
						await api<{ users: User[] }>(
							`/users?${new URLSearchParams({ q, limit: "20" })}`,
						)
					).users
				: [];
			const found = findUser(q, users);
			if ("sub" in found) {
				filterBy(q, found.sub);
			} else {
				setChoices(found.choices);
			}
		} catch (e) {
			failed("查找用户失败")(e as Error);
		} finally {
			setFinding(false);
		}
	};
	const filtered = !!(event || sub || since || until);

	return (
		<div className="flex flex-col gap-6">
			<div className="flex flex-wrap gap-2">
				<Select value={event} onValueChange={(v) => set("event", `${v ?? ""}`)}>
					<SelectTrigger className="w-56">
						<SelectValue>
							{(v: string) => (v ? eventName(v) : "全部事件")}
						</SelectValue>
					</SelectTrigger>
					<SelectContent>
						<SelectItem value="">全部事件</SelectItem>
						{eventGroups.map(([group, list]) => (
							<SelectGroup key={group}>
								<SelectLabel>{group}</SelectLabel>
								{list.map(([k, name]) => (
									<SelectItem key={k} value={k}>
										{name}
									</SelectItem>
								))}
							</SelectGroup>
						))}
					</SelectContent>
				</Select>
				<FindUser
					key={filters.q}
					q={filters.q}
					canReadUsers={can("users:read")}
					disabled={finding}
					onFind={find}
				/>
				<div className="flex items-center gap-2">
					<DatePicker
						label="开始日期"
						value={since}
						onChange={(v) => set("since", v)}
					/>
					<span className="text-[13px] text-muted-foreground">至</span>
					<DatePicker
						label="结束日期"
						value={until}
						onChange={(v) => set("until", v)}
					/>
				</div>
			</div>
			<Separator />
			{choices && (
				<div className="space-y-2 rounded-xl bg-primary-soft px-4 py-3 text-sm">
					<p>找到 {choices.length} 个用户，请选择要查看的用户：</p>
					<ul className="flex flex-wrap gap-2">
						{choices.map((u) => (
							<li key={u.sub}>
								<Button
									size="sm"
									variant="outline"
									onClick={() =>
										filterBy(primaryIdentifier(u.identifiers) ?? u.sub, u.sub)
									}
								>
									{primaryIdentifier(u.identifiers) ?? (
										<span className="font-mono">{u.sub.slice(0, 8)}</span>
									)}
								</Button>
							</li>
						))}
					</ul>
				</div>
			)}
			<EventTable
				events={rows}
				empty={
					filtered && (
						<>
							<span>没有符合条件的事件</span>
							<Button
								size="sm"
								variant="outline"
								onClick={() => {
									setChoices(undefined);
									navigate({ search: {} });
								}}
							>
								清除筛选
							</Button>
						</>
					)
				}
			/>
			{events.isFetchNextPageError && (
				<p className="text-destructive text-sm">{events.error?.message}</p>
			)}
			{events.hasNextPage && (
				<Button
					variant="outline"
					disabled={events.isFetchingNextPage}
					onClick={() => events.fetchNextPage()}
				>
					加载更多
				</Button>
			)}
		</div>
	);
}

function Sentence({ parts }: { parts: Part[] }) {
	return parts.map((p, i) => {
		const key = `${i}`;
		if (typeof p === "string") {
			return p;
		}
		const className = p.mono ? "font-mono text-xs" : undefined;
		if (p.user) {
			return (
				<Link
					key={key}
					to="/console/users/$sub"
					params={{ sub: p.user }}
					className="underline-offset-2 hover:underline"
				>
					{p.text}
				</Link>
			);
		}
		if (p.app) {
			return (
				<Link
					key={key}
					to="/console/apps/$clientId"
					params={{ clientId: p.app }}
					className="underline-offset-2 hover:underline"
				>
					{p.text}
				</Link>
			);
		}
		return (
			<span key={key} className={className}>
				{p.text}
			</span>
		);
	});
}

// DatePicker picks a local yyyy-mm-dd, "" when none; picking the chosen
// day again clears it.
function DatePicker({
	label,
	value,
	onChange,
}: {
	label: string;
	value: string;
	onChange: (v: string) => void;
}) {
	const [open, setOpen] = useState(false);
	const selected = value ? new Date(`${value}T00:00`) : undefined;
	return (
		<Popover open={open} onOpenChange={setOpen}>
			<PopoverTrigger
				render={
					<Button
						variant="outline"
						aria-label={label}
						className="w-36 justify-start font-normal tabular-nums"
					/>
				}
			>
				<CalendarIcon data-icon="inline-start" />
				{selected ? (
					format(selected, "yyyy/M/d")
				) : (
					<span className="text-muted-foreground">{label}</span>
				)}
			</PopoverTrigger>
			<PopoverContent className="w-auto p-0" align="start">
				<Calendar
					mode="single"
					locale={zhCN}
					selected={selected}
					defaultMonth={selected}
					onSelect={(d) => {
						onChange(d ? format(d, "yyyy-MM-dd") : "");
						setOpen(false);
					}}
				/>
			</PopoverContent>
		</Popover>
	);
}

// FindUser is the box that filters by a User; it looks them up on Enter.
function FindUser({
	q,
	canReadUsers,
	disabled,
	onFind,
}: {
	q: string;
	canReadUsers: boolean;
	disabled: boolean;
	onFind: (q: string) => void;
}) {
	const form = useForm({
		defaultValues: { q },
		validationLogic: revalidateLogic(),
		validators: { onDynamic: findSchema(canReadUsers) },
		onSubmit: ({ value }) => onFind(value.q.trim()),
	});
	return (
		<form
			noValidate
			className="min-w-56 flex-1"
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
							<FieldLabel htmlFor="audit-user" className="sr-only">
								按用户筛选
							</FieldLabel>
							<Input
								id="audit-user"
								value={field.state.value}
								onBlur={field.handleBlur}
								onChange={(e) => field.handleChange(e.target.value)}
								aria-invalid={invalid}
								disabled={disabled}
								placeholder={
									canReadUsers ? "手机号、邮箱、用户名或用户 ID" : "用户 ID"
								}
							/>
							{invalid && <FieldError errors={field.state.meta.errors} />}
						</Field>
					);
				}}
			</form.Field>
		</form>
	);
}

// EventTable is the audit log as 时间 / 操作人 / 事件描述, shared by the
// audit page and the overview. empty is what a row says when there are
// no events.
export function EventTable({
	events,
	empty,
}: {
	events: AuditEvent[];
	empty?: ReactNode;
}) {
	const { names, naming } = useNames();
	return (
		<Table>
			<TableHeader>
				<TableRow>
					<TableHead className="w-24 sm:w-44">时间</TableHead>
					<TableHead className="w-20 sm:w-40">操作人</TableHead>
					<TableHead>事件描述</TableHead>
				</TableRow>
			</TableHeader>
			<TableBody>
				{(naming ? [] : events).map((ev) => {
					const { parts, title } = describe(ev, names);
					return (
						<TableRow key={ev.id}>
							<TableCell className="whitespace-normal text-muted-foreground text-xs tabular-nums sm:whitespace-nowrap">
								{date(ev.at)}
							</TableCell>
							<TableCell className="max-w-40 truncate">
								<Sentence parts={actor(ev, names)} />
							</TableCell>
							<TableCell className="whitespace-normal" title={title}>
								<Sentence parts={parts} />
							</TableCell>
						</TableRow>
					);
				})}
				{empty && !naming && events.length === 0 && (
					<TableRow>
						<TableCell
							colSpan={3}
							className="text-center text-muted-foreground"
						>
							<span className="inline-flex items-center gap-2">{empty}</span>
						</TableCell>
					</TableRow>
				)}
			</TableBody>
		</Table>
	);
}

// useNames fetches the Application and API resource names events refer
// to; naming is true until they're in.
function useNames() {
	const can = useCan();
	const readApps = can("applications:read");
	const apps = useQuery({ ...applicationsQuery, enabled: readApps });
	const apis = useQuery({ ...apisQuery, enabled: readApps });
	return {
		names: {
			apps: readApps ? apps.data?.applications : undefined,
			apis: apis.data?.apis,
		},
		// Wait for the names, or every ID would show raw as if deleted.
		naming: readApps && (apps.isPending || apis.isPending),
	};
}

// EventList is the overview's recent events: one line each, who did it
// and what, then when. The system has no name to show: its icon stands
// in, and the sentence names its own subject (用户 a 用密码登录了 …).
export function EventList({ events }: { events: AuditEvent[] }) {
	const { names, naming } = useNames();
	return (
		<ItemList>
			{(naming ? [] : events).map((ev) => {
				const { parts, title } = describe(ev, names);
				const who = actor(ev, names);
				const [first] = who;
				const system = !doneBy(ev);
				return (
					<Item key={ev.id} size="sm" className="py-2">
						<ItemMedia>
							{system ? (
								<Avatar size="sm">
									<AvatarFallback className="bg-canvas text-faint">
										<Cog className="size-3.5" />
									</AvatarFallback>
								</Avatar>
							) : (
								<UserAvatar
									name={
										doneBy(ev) === ev.sub
											? ev.user // 用户本人
											: typeof first === "string"
												? undefined
												: first.text
									}
								/>
							)}
						</ItemMedia>
						<ItemContent className="min-w-0">
							<p title={title}>
								{system ? (
									<span className="sr-only">系统：</span>
								) : (
									<>
										<span className="font-medium">
											<Sentence parts={who} />
										</span>{" "}
									</>
								)}
								<Sentence parts={parts} />
							</p>
						</ItemContent>
						<ItemActions className="text-faint text-xs tabular-nums">
							{date(ev.at)}
						</ItemActions>
					</Item>
				);
			})}
		</ItemList>
	);
}
