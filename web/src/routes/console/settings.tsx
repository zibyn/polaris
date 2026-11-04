import {
	createFileRoute,
	stripSearchParams,
	useNavigate,
	useSearch,
} from "@tanstack/react-router";
import { z } from "zod";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "#/components/ui/tabs";
import { channelsQuery, policyQuery } from "#/lib/queries";
import { BrandTab } from "./-settings/brand";
import { ChannelsTab } from "./-settings/channels";
import { LoginTab } from "./-settings/login";
import { SecurityTab, signingKeysQuery } from "./-settings/security";

const defaults = { tab: "login" } as const;
const search = z.object({
	tab: z
		.enum(["login", "brand", "channels", "security"])
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
		tab: "brand",
		label: "品牌",
		hint: "登录页的品牌名、Logo 和主色",
	},
	{
		tab: "channels",
		label: "验证码通道",
		hint: "短信、邮件供应商与发送上限",
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
			description: "登录方式、品牌、验证码通道和安全设置。",
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

// Settings picks one category from a rail on the left, so the areas
// stay in view instead of turning into tabs that hide each other. The
// rail scrolls sideways below lg, where it sits on top.
function Settings() {
	const { tab } = useSearch({ from: "/console/settings" });
	const navigate = useNavigate();
	return (
		<Tabs
			orientation="vertical"
			value={tab}
			onValueChange={(v) => navigate({ to: ".", search: { tab: v } })}
			className="grid gap-8 lg:grid-cols-[15rem_minmax(0,1fr)] lg:gap-12"
		>
			<TabsList
				aria-label="设置分类"
				className="-mx-1 w-auto items-stretch justify-start gap-1 overflow-x-auto rounded-none bg-transparent p-0 pb-1 max-lg:flex-row! lg:mx-0 lg:overflow-visible lg:pb-0"
			>
				{categories.map((c) => (
					<TabsTrigger
						key={c.tab}
						value={c.tab}
						className="h-auto flex-none shrink-0 flex-col items-start gap-0 rounded-lg border-0 px-3 py-2 font-normal text-muted-foreground text-sm not-data-active:hover:bg-muted hover:text-foreground data-active:hover:text-primary-ink max-lg:w-auto! data-active:bg-primary-soft data-active:font-medium data-active:text-primary-ink group-data-[variant=default]/tabs-list:data-active:shadow-none dark:data-active:bg-primary-soft dark:data-active:text-primary-ink"
					>
						<span className="block whitespace-nowrap">{c.label}</span>
						<span className="mt-0.5 hidden w-full truncate text-left font-normal text-muted-foreground text-xs lg:block">
							{c.hint}
						</span>
					</TabsTrigger>
				))}
			</TabsList>
			<TabsContent value="login" className="max-w-3xl min-w-0">
				<LoginTab />
			</TabsContent>
			<TabsContent value="brand" className="max-w-3xl min-w-0">
				<BrandTab />
			</TabsContent>
			<TabsContent value="channels" className="max-w-3xl min-w-0">
				<ChannelsTab />
			</TabsContent>
			<TabsContent value="security" className="max-w-3xl min-w-0">
				<SecurityTab />
			</TabsContent>
		</Tabs>
	);
}
