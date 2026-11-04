import { useQueryClient } from "@tanstack/react-query";
import type { Policy } from "#/lib/console-api";
import { policyQuery, useSavePolicy } from "#/lib/queries";
import { BrandSection } from "#/routes/console/-components/brand-section";
import { usePolicy } from "./policy";

// BrandTab is the instance's 品牌: every Application's login pages show it
// unless they override an item (ADR 0028).
export function BrandTab() {
	const { policy, editable } = usePolicy();
	const save = useSavePolicy();
	const client = useQueryClient();
	return (
		<BrandSection
			intro="设置任一项后，登录页品牌区不再显示星云，底部不再显示「由 Polaris 提供安全登录」。应用可在登录标签中逐项覆盖。"
			brand={policy.brand}
			editable={editable}
			follows="Polaris"
			followsColor="#7048e8"
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
