import { createFileRoute } from "@tanstack/react-router";
import { polaris } from "../../polaris";

export const Route = createFileRoute("/auth/$")({
	server: {
		handlers: {
			GET: ({ request }) => polaris.handler(request),
			POST: ({ request }) => polaris.handler(request),
		},
	},
});
