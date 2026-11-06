// The web-standard handler on node:http, and so on Express.
import type { IncomingMessage, ServerResponse } from "node:http";
import { Readable } from "node:stream";

export function toNodeHandler(
	handler: (request: Request) => Promise<Response>,
) {
	return async (
		req: IncomingMessage & { originalUrl?: string },
		res: ServerResponse,
	) => {
		try {
			const headers = new Headers();
			for (const [k, v] of Object.entries(req.headers)) {
				if (v !== undefined)
					for (const one of [v].flat()) headers.append(k, one);
			}
			const hasBody = req.method !== "GET" && req.method !== "HEAD";
			// The routes are found by path; the host is only a placeholder.
			const request = new Request(
				new URL(req.originalUrl ?? req.url ?? "/", "http://localhost"),
				{
					method: req.method,
					headers,
					body: hasBody ? (Readable.toWeb(req) as ReadableStream) : undefined,
					// @ts-expect-error Node's fetch needs this for a streamed body; not yet in the DOM types.
					duplex: hasBody ? "half" : undefined,
				},
			);
			const response = await handler(request);
			const out: Record<string, string | string[]> = {};
			response.headers.forEach((v, k) => {
				if (k !== "set-cookie") out[k] = v;
			});
			const setCookies = response.headers.getSetCookie();
			if (setCookies.length) out["set-cookie"] = setCookies;
			res.writeHead(response.status, out);
			res.end(Buffer.from(await response.arrayBuffer()));
		} catch (err) {
			if (!res.headersSent)
				res.writeHead(500, { "content-type": "text/plain" });
			res.end("internal error");
			console.error("polaris:", err);
		}
	};
}
