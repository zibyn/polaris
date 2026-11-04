import { useQueryClient } from "@tanstack/react-query";
import type { Policy } from "#/lib/console-api";
import { BrandSection } from "#/routes/console/-components/brand-section";
import { policyQuery, usePolicy, useSavePolicy } from "./policy";

// BrandTab is the instance's 品牌: every Application's login pages show it
// unless they override an item (ADR 0028).
export function BrandTab() {
	const { policy, editable } = usePolicy();
	const save = useSavePolicy();
	const client = useQueryClient();
	return (
		<BrandSection
			intro="登录页默认显示 Polaris 和「星云」配色。设了任何一项，登录页就换成你的品牌：品牌区去掉星云，底部不再写「由 Polaris 提供安全登录」。应用可以在自己的登录标签里逐项覆盖。"
			brand={policy.brand}
			editable={editable}
			follows="Polaris"
			logoPath="/settings/brand/logo"
			onLogo={(logo) => {
				// The next save sends the Logo back; it must be this one.
				client.setQueryData<Policy>(
					policyQuery.queryKey,
					(p) => p && { ...p, brand: { ...p.brand, logo } },
				);
				return client.invalidateQueries(policyQuery);
			}}
			save={{
				...save,
				mutate: (brand, o) => save.mutate({ brand }, o),
			}}
		/>
	);
}
