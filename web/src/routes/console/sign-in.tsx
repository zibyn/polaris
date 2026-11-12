import { createFileRoute, stripSearchParams } from "@tanstack/react-router";
import { z } from "zod";
import { TabsContent } from "#/components/ui/tabs";
import { channelsQuery, policyQuery } from "#/lib/queries";
import { BrandTab } from "./-settings/brand";
import { LoginTab } from "./-settings/login";
import { TermsTab } from "./-settings/terms";

const defaults = { tab: "login" } as const;
const search = z.object({
	tab: z
		.enum(["login", "brand", "terms"])
		.default(defaults.tab)
		.catch(defaults.tab),
});

// 登录体验 is what every Application's hosted pages show by default: the
// ways to sign in, the brand, and the terms the User agrees to.
export const Route = createFileRoute("/console/sign-in")({
	staticData: {
		useHeader: () => ({
			title: "登录体验",
			description: "所有应用的托管登录页默认使用这里的配置。",
			tabs: [
				["login", "登录方式"],
				["brand", "品牌"],
				["terms", "用户协议"],
			],
		}),
	},
	validateSearch: search,
	search: { middlewares: [stripSearchParams(defaults)] },
	loader: ({ context: { queryClient } }) =>
		Promise.all([
			queryClient.ensureQueryData(policyQuery),
			queryClient.ensureQueryData(channelsQuery),
		]),
	component: SignIn,
});

function SignIn() {
	return (
		<>
			<TabsContent value="login" className="max-w-3xl min-w-0">
				<LoginTab />
			</TabsContent>
			<TabsContent value="brand" className="max-w-3xl min-w-0">
				<BrandTab />
			</TabsContent>
			<TabsContent value="terms" className="max-w-3xl min-w-0">
				<TermsTab />
			</TabsContent>
		</>
	);
}
