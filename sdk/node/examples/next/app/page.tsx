import { headers } from "next/headers";
import { polaris } from "../lib/polaris";

export default async function Home() {
	// Read-only: a Server Component cannot write the rotated cookie back; proxy.ts refreshed it.
	const { session } = await polaris.getSession(await headers(), {
		readOnly: true,
	});
	if (!session) return <a href="/auth/login">Sign in</a>;
	return (
		<main>
			<p>Signed in as {session.user.sub}</p>
			<a href={polaris.accountUrl()}>Account</a>
			<form action="/auth/logout" method="post">
				<button type="submit">Sign out</button>
			</form>
		</main>
	);
}
