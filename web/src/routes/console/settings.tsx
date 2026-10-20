import {
	createFileRoute,
	Link,
	stripSearchParams,
	useSearch,
} from "@tanstack/react-router";
import { z } from "zod";
import { ChannelsTab, channelsQuery } from "./-settings/channels";
import { LoginTab } from "./-settings/login";
import { policyQuery } from "./-settings/policy";
import { SecurityTab, signingKeysQuery } from "./-settings/security";

const defaults = { tab: "login" } as const;
const search = z.object({
	tab: z
		.enum(["login", "channels", "security"])
		.default(defaults.tab)
		.catch(defaults.tab),
});

// categories is the settings rail, in the order the spec gives them.
const categories = [
	{
		tab: "login",
		label: "登录方式",
		hint: "密码、Passkey、验证码和用户协议",
	},
	{
		tab: "channels",
		label: "验证码通道",
		hint: "短信、邮件的服务商与发送上限",
	},
	{
		tab: "security",
		label: "安全",
		hint: "令牌签名密钥和审计保留期",
	},
] as const;

export const Route = createFileRoute("/console/settings")({
	staticData: {
		useHeader: () => ({
			title: "设置",
			description: "用户怎么登录、验证码从哪发出去，以及实例本身的安全。",
		}),
	},
	validateSearch: search,
	search: { middlewares: [stripSearchParams(defaults)] },
	loader: ({ context: { queryClient } }) =>
		Promise.all([
			queryClient.ensureQueryData(policyQuery),
			queryClient.ensureQueryData(channelsQuery),
			queryClient.ensureQueryData(signingKeysQuery),
		]),
	component: Settings,
});

// Settings picks one category from a rail on the left, so the three areas
// stay in view instead of turning into tabs that hide each other.
function Settings() {
	const { tab } = useSearch({ from: "/console/settings" });
	return (
		<div className="grid gap-8 lg:grid-cols-[15rem_minmax(0,1fr)] lg:gap-12">
			<nav
				aria-label="设置分类"
				className="-mx-1 flex gap-1 overflow-x-auto pb-1 lg:mx-0 lg:flex-col lg:overflow-visible lg:pb-0"
			>
				{categories.map((c) => {
					const active = c.tab === tab;
					return (
						<Link
							key={c.tab}
							to="/console/settings"
							search={{ tab: c.tab }}
							aria-current={active ? "page" : undefined}
							className={
								active
									? "shrink-0 rounded-lg bg-card px-3 py-2 font-medium shadow-xs ring-1 ring-border lg:block"
									: "shrink-0 rounded-lg px-3 py-2 text-muted-foreground hover:text-foreground lg:block"
							}
						>
							<span className="block whitespace-nowrap">{c.label}</span>
							<span className="hidden text-[13px] font-normal text-muted-foreground lg:block">
								{c.hint}
							</span>
						</Link>
					);
				})}
			</nav>
			<div className="max-w-3xl min-w-0">
				{tab === "login" && <LoginTab />}
				{tab === "channels" && <ChannelsTab />}
				{tab === "security" && <SecurityTab />}
			</div>
		</div>
	);
}
