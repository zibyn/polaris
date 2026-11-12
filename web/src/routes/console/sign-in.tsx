import { useQuery, useSuspenseQuery } from "@tanstack/react-query";
import { createFileRoute, stripSearchParams } from "@tanstack/react-router";
import { Fingerprint } from "lucide-react";
import { z } from "zod";
import { Star } from "#/components/star";
import { Button } from "#/components/ui/button";
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "#/components/ui/card";
import { Checkbox } from "#/components/ui/checkbox";
import { Input } from "#/components/ui/input";
import { TabsContent } from "#/components/ui/tabs";
import { hasChannel, identifierLabel } from "#/lib/login";
import { channelsQuery, policyQuery } from "#/lib/queries";
import { BrandTab } from "./-settings/brand";
import { LoginTab } from "./-settings/login";
import { TermsTab } from "./-settings/terms";
import { providersQuery } from "./providers/index";

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
		<div className="grid items-start gap-6 xl:grid-cols-[minmax(0,1fr)_22rem]">
			<div className="min-w-0">
				<TabsContent value="login">
					<LoginTab />
				</TabsContent>
				<TabsContent value="brand">
					<BrandTab />
				</TabsContent>
				<TabsContent value="terms">
					<TermsTab />
				</TabsContent>
			</div>
			<Preview />
		</div>
	);
}

// Preview draws the hosted login page's first step from the saved
// settings, so a flip on the left shows on the right. It only illustrates:
// nothing in it does anything.
function Preview() {
	const policy = useSuspenseQuery(policyQuery).data;
	const { channels } = useSuspenseQuery(channelsQuery).data;
	const providers = useQuery(providersQuery).data?.providers ?? [];
	const kinds = (["phone", "email"] as const).filter((k) =>
		hasChannel(channels, k),
	);
	const password = policy.passwordLogin === "on";
	const label = identifierLabel(kinds, password);
	const brand = policy.brand;
	const branded = !!(brand?.name || brand?.logo || brand?.color);
	const primary = brand?.color ? { background: brand.color } : undefined;
	return (
		<Card className="xl:sticky xl:top-6">
			<CardHeader className="border-b">
				<CardTitle>预览</CardTitle>
				<CardDescription>
					托管登录页第一步，按已保存的配置示意。
				</CardDescription>
			</CardHeader>
			<CardContent>
				<div
					inert
					aria-hidden
					className="flex flex-col gap-4 rounded-lg bg-muted p-6 select-none"
				>
					<div className="flex items-center gap-2 font-medium text-sm">
						{brand?.logo ? (
							<img
								src={`/brand-logos/${brand.logo}`}
								alt=""
								className="size-6 rounded object-contain"
							/>
						) : (
							<span className="flex size-6 items-center justify-center rounded-md bg-primary text-primary-foreground">
								<Star className="size-3.5" />
							</span>
						)}
						{brand?.name || "Polaris"}
					</div>
					<Card size="sm">
						<CardHeader className="text-center">
							<CardTitle className="text-lg">登录</CardTitle>
							<CardDescription>继续前往 示例应用</CardDescription>
						</CardHeader>
						<CardContent className="flex flex-col gap-3">
							{label ? (
								<>
									<Input readOnly placeholder={label} tabIndex={-1} />
									{policy.termsUrl && (
										<span className="flex items-start gap-2 text-muted-foreground text-xs">
											<Checkbox tabIndex={-1} className="mt-0.5" />
											我已阅读并同意《用户协议》和《隐私政策》
										</span>
									)}
									<Button tabIndex={-1} style={primary}>
										继续
									</Button>
									{password && kinds.length > 0 && (
										<span className="text-center text-sm underline underline-offset-4">
											使用密码登录
										</span>
									)}
								</>
							) : (
								<p className="text-center text-muted-foreground text-sm">
									没有可用的登录方式
								</p>
							)}
							{(policy.passkeyLogin || providers.some((p) => p.enabled)) && (
								<>
									<span className="flex items-center gap-2 text-muted-foreground text-xs before:h-px before:flex-1 before:bg-border after:h-px after:flex-1 after:bg-border">
										或
									</span>
									{policy.passkeyLogin && (
										<Button variant="outline" tabIndex={-1}>
											<Fingerprint />
											使用 Passkey 登录
										</Button>
									)}
									{providers
										.filter((p) => p.enabled)
										.map((p) => (
											<Button key={p.id} variant="outline" tabIndex={-1}>
												{p.name}
											</Button>
										))}
								</>
							)}
						</CardContent>
					</Card>
					{!branded && (
						<p className="text-center text-muted-foreground text-xs">
							由 Polaris 提供安全登录
						</p>
					)}
				</div>
			</CardContent>
		</Card>
	);
}
