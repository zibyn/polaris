import { createFileRoute } from "@tanstack/react-router";
import { policyQuery } from "#/lib/queries";
import { SecurityTab, signingKeysQuery } from "./-settings/security";

export const Route = createFileRoute("/console/security")({
	staticData: {
		useHeader: () => ({
			title: "安全",
			description: "令牌签名密钥与审计保留期。",
		}),
	},
	loader: ({ context: { queryClient } }) =>
		Promise.all([
			queryClient.ensureQueryData(policyQuery),
			queryClient.ensureQueryData(signingKeysQuery),
		]),
	component: () => (
		<div className="max-w-3xl">
			<SecurityTab />
		</div>
	),
});
