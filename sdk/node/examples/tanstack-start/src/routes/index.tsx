import { createFileRoute } from "@tanstack/react-router";
import { createServerFn } from "@tanstack/react-start";
import { getRequest, setResponseHeader } from "@tanstack/react-start/server";
import { polaris } from "../polaris";

const me = createServerFn().handler(async () => {
	const { session, headers } = await polaris.getSession(getRequest());
	// A refresh rotated the refresh token: the new cookie must reach the browser.
	const cookies = headers.getSetCookie();
	if (cookies.length) setResponseHeader("set-cookie", cookies);
	return session && { sub: session.user.sub };
});

export const Route = createFileRoute("/")({
	loader: () => me(),
	component: function Home() {
		const user = Route.useLoaderData();
		if (!user) return <a href="/auth/login">Sign in</a>;
		return (
			<main>
				<p>Signed in as {user.sub}</p>
				<form action="/auth/logout" method="post">
					<button type="submit">Sign out</button>
				</form>
			</main>
		);
	},
});
