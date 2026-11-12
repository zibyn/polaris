import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { AppWindow, KeyRound, Search, Server, User } from "lucide-react";
import { useEffect, useState } from "react";
import { Button } from "#/components/ui/button";
import {
	Command,
	CommandDialog,
	CommandEmpty,
	CommandGroup,
	CommandInput,
	CommandItem,
	CommandList,
} from "#/components/ui/command";
import { api, type User as UserT } from "#/lib/console-api";
import { navItems } from "#/lib/nav";
import { applicationsQuery } from "#/lib/queries";
import { primaryIdentifier } from "#/lib/users";
import { apisQuery } from "#/routes/console/apis/index";
import { providersQuery } from "#/routes/console/providers/index";
import { useCan, useMe } from "#/routes/console/route";

const has = (q: string, ...texts: (string | undefined)[]) =>
	texts.some((t) => t?.toLowerCase().includes(q));

// useDebounced is value once it has stopped changing for ms.
function useDebounced<T>(value: T, ms: number) {
	const [v, setV] = useState(value);
	useEffect(() => {
		const id = setTimeout(() => setV(value), ms);
		return () => clearTimeout(id);
	}, [value, ms]);
	return v;
}

// GlobalSearch is the top bar's search box and its ⌘K dialog: pages,
// users, applications, API resources and providers the admin may read,
// per consoles.md「导航」. Users are looked up on the server; the rest are
// filtered here from lists the console already loads.
export function GlobalSearch() {
	const [open, setOpen] = useState(false);
	const [q, setQ] = useState("");
	const term = q.trim().toLowerCase();
	const navigate = useNavigate();
	const can = useCan();
	const me = useMe();

	useEffect(() => {
		const down = (e: KeyboardEvent) => {
			if (e.key === "k" && (e.metaKey || e.ctrlKey)) {
				e.preventDefault();
				setOpen((o) => !o);
			}
		};
		document.addEventListener("keydown", down);
		return () => document.removeEventListener("keydown", down);
	}, []);

	const apps = useQuery({
		...applicationsQuery,
		enabled: open && can("applications:read"),
	}).data?.applications;
	const apis = useQuery({
		...apisQuery,
		enabled: open && can("applications:read"),
	}).data?.apis;
	const providers = useQuery({
		...providersQuery,
		enabled: open && can("config:read"),
	}).data?.providers;
	const userTerm = useDebounced(q.trim(), 200);
	const users = useQuery({
		queryKey: ["users", "search", userTerm],
		queryFn: () =>
			api<{ users: UserT[]; hasMore: boolean }>(
				`/users?${new URLSearchParams({ q: userTerm, limit: "5" })}`,
			),
		enabled: open && !!userTerm && can("users:read"),
	}).data;

	const go = (to: () => unknown) => {
		setOpen(false);
		setQ("");
		to();
	};
	const pages = navItems(me.permissions).filter((p) => has(term, p.label));
	const pick = <T,>(list: T[] | undefined, text: (t: T) => string[]) =>
		term ? (list ?? []).filter((t) => has(term, ...text(t))).slice(0, 5) : [];
	const appHits = pick(apps, (a) => [a.name, a.clientId]);
	const apiHits = pick(apis, (a) => [a.name, a.identifier]);
	const providerHits = pick(providers, (p) => [p.name, p.id]);

	return (
		<>
			<Button
				variant="outline"
				className="ml-auto h-8 w-full max-w-64 justify-start gap-2 px-2.5 font-normal text-muted-foreground"
				onClick={() => setOpen(true)}
			>
				<Search />
				<span className="truncate">搜索用户、应用、API 资源…</span>
				<kbd className="ml-auto hidden rounded border bg-muted px-1.5 font-mono text-[10px] sm:inline">
					⌘K
				</kbd>
			</Button>
			<CommandDialog
				open={open}
				onOpenChange={setOpen}
				title="全局搜索"
				description="搜索页面、用户、应用、API 资源和认证源"
			>
				{/* Filtering is ours: users come back already matched by the server. */}
				<Command shouldFilter={false}>
					<CommandInput
						placeholder="搜索页面、用户、应用、API 资源…"
						value={q}
						onValueChange={setQ}
					/>
					<CommandList>
						<CommandEmpty>没有符合条件的结果</CommandEmpty>
						{pages.length > 0 && (
							<CommandGroup heading="页面">
								{pages.map((p) => (
									<CommandItem
										key={p.to}
										value={`page ${p.to}`}
										onSelect={() => go(() => navigate({ to: p.to }))}
									>
										{p.label}
									</CommandItem>
								))}
							</CommandGroup>
						)}
						{userTerm && users && users.users.length > 0 && (
							<CommandGroup heading="用户">
								{users.users.map((u) => (
									<CommandItem
										key={u.sub}
										value={`user ${u.sub}`}
										onSelect={() =>
											go(() =>
												navigate({
													to: "/console/users/$sub",
													params: { sub: u.sub },
												}),
											)
										}
									>
										<User />
										{primaryIdentifier(u.identifiers) ?? u.sub.slice(0, 8)}
									</CommandItem>
								))}
								{users.hasMore && (
									<CommandItem
										value="user more"
										onSelect={() =>
											go(() =>
												navigate({
													to: "/console/users",
													search: { q: userTerm },
												}),
											)
										}
									>
										在用户列表中查看全部
									</CommandItem>
								)}
							</CommandGroup>
						)}
						{appHits.length > 0 && (
							<CommandGroup heading="应用">
								{appHits.map((a) => (
									<CommandItem
										key={a.clientId}
										value={`app ${a.clientId}`}
										onSelect={() =>
											go(() =>
												navigate({
													to: "/console/apps/$clientId",
													params: { clientId: a.clientId },
												}),
											)
										}
									>
										<AppWindow />
										{a.name}
										<span className="ml-auto font-mono text-muted-foreground text-xs">
											{a.clientId}
										</span>
									</CommandItem>
								))}
							</CommandGroup>
						)}
						{apiHits.length > 0 && (
							<CommandGroup heading="API 资源">
								{apiHits.map((a) => (
									<CommandItem
										key={a.identifier}
										value={`api ${a.identifier}`}
										onSelect={() =>
											go(() =>
												navigate({
													to: "/console/apis/$api",
													params: { api: a.identifier },
												}),
											)
										}
									>
										<Server />
										{a.name}
										<span className="ml-auto font-mono text-muted-foreground text-xs">
											{a.identifier}
										</span>
									</CommandItem>
								))}
							</CommandGroup>
						)}
						{providerHits.length > 0 && (
							<CommandGroup heading="认证源">
								{providerHits.map((p) => (
									<CommandItem
										key={p.id}
										value={`provider ${p.id}`}
										onSelect={() =>
											go(() =>
												navigate({
													to: "/console/providers/$id",
													params: { id: p.id },
												}),
											)
										}
									>
										<KeyRound />
										{p.name}
										<span className="ml-auto font-mono text-muted-foreground text-xs">
											{p.id}
										</span>
									</CommandItem>
								))}
							</CommandGroup>
						)}
					</CommandList>
				</Command>
			</CommandDialog>
		</>
	);
}
