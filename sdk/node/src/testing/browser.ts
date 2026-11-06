// A browser for the tests: keeps cookies and walks redirects between the
// app's handler (called in process) and the fake OP (over HTTP).
export const appURL = "https://app.example.com";

export class Browser {
	cookies = new Map<string, string>();

	app: (req: Request) => Promise<Response>;
	base: string;

	constructor(app: (req: Request) => Promise<Response>, base = appURL) {
		this.app = app;
		this.base = base;
	}

	cookieHeader() {
		return [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ");
	}

	/** Applies the Set-Cookie headers of a response, as a browser would. */
	store(headers: Headers) {
		for (const c of headers.getSetCookie()) {
			const [pair, ...attrs] = c.split(";");
			const i = pair.indexOf("=");
			const name = pair.slice(0, i).trim();
			const expired = attrs.some((a) => /^\s*max-age=0\s*$/i.test(a));
			if (expired) this.cookies.delete(name);
			else this.cookies.set(name, pair.slice(i + 1));
		}
	}

	request(path: string, init: RequestInit = {}) {
		const headers = new Headers(init.headers);
		if (this.cookies.size) headers.set("cookie", this.cookieHeader());
		return new Request(new URL(path, this.base), { ...init, headers });
	}

	/** Fetches url, following redirects until one leaves both the app and the OP. */
	async go(url: string, init: RequestInit = {}): Promise<Response> {
		for (;;) {
			let res: Response;
			if (url.startsWith(this.base)) {
				res = await this.app(this.request(url, init));
				this.store(res.headers);
			} else if (url.startsWith("http://127.0.0.1")) {
				res = await fetch(url, { redirect: "manual" });
			} else
				return new Response(null, { status: 302, headers: { location: url } });
			const loc = res.headers.get("location");
			if (res.status < 300 || res.status >= 400 || !loc) return res;
			url = new URL(loc, url).href;
			// Back on the app's own pages: the flow is done.
			if (
				url.startsWith(this.base) &&
				!new URL(url).pathname.startsWith("/auth/")
			)
				return res;
			init = {};
		}
	}
}
