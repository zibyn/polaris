import { createFileRoute } from "@tanstack/react-router";
import { channelsQuery, policyQuery } from "#/lib/queries";
import { ChannelsTab } from "./-settings/channels";

export const Route = createFileRoute("/console/channels")({
	staticData: {
		useHeader: () => ({
			title: "验证码通道",
			description: "短信、邮件供应商与每日发送上限。",
		}),
	},
	loader: ({ context: { queryClient } }) =>
		Promise.all([
			queryClient.ensureQueryData(policyQuery),
			queryClient.ensureQueryData(channelsQuery),
		]),
	component: () => (
		<div className="max-w-3xl">
			<ChannelsTab />
		</div>
	),
});
