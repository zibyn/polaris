import { createFileRoute, redirect } from "@tanstack/react-router";
import { z } from "zod";

// The old 设置 page, split per consoles.md「导航」; links into it still land.
export const Route = createFileRoute("/console/settings")({
	validateSearch: z.object({ tab: z.string().optional().catch(undefined) }),
	beforeLoad: ({ search: { tab } }) => {
		if (tab === "channels") throw redirect({ to: "/console/channels" });
		if (tab === "security") throw redirect({ to: "/console/security" });
		throw redirect({
			to: "/console/sign-in",
			search: { tab: tab === "brand" || tab === "terms" ? tab : "login" },
		});
	},
});
