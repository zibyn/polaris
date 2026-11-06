// A fake Polaris for the tests: just enough of discovery, JWKS, /authorize
// and /token, issuing tokens shaped like Polaris's (docs/spec/protocol.md, 令牌).
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

export const clientId = "web-app";
export const clientSecret = "s3cret";
export const api = "https://api.example.com";

type Grant = { sub: string; nonce: string; scope: string };

export async function startFakeOP(port = 0) {
	const { privateKey, publicKey } = await generateKeyPair("RS256");
	const jwk = {
		...(await exportJWK(publicKey)),
		kid: "k1",
		alg: "RS256",
		use: "sig",
	};
	const codes = new Map<
		string,
		Grant & { challenge: string; redirectURI: string }
	>();
	const refreshTokens = new Map<string, Grant>(); // only the current one of each chain
	let n = 0;
	const op = {
		issuer: "",
		/** Seconds an access token lives. */
		accessTTL: 600,
		/** Whether the token endpoint hands out refresh tokens. */
		issueRefreshTokens: true,
		/** Claims added to the next ID tokens, as a profile change would. */
		profile: { name: "Ada" } as Record<string, unknown>,
		refreshRequests: 0,
		/** The last /authorize query. */
		authorizeParams: new URLSearchParams(),
		/** Ends every Session: their refresh tokens stop working. */
		endSessions: () => refreshTokens.clear(),
		accessToken: (
			claims: Record<string, unknown>,
			opts: { typ?: string; aud?: string; key?: CryptoKey } = {},
		) =>
			new SignJWT({ client_id: clientId, ...claims })
				.setProtectedHeader({
					alg: "RS256",
					kid: "k1",
					typ: opts.typ ?? "at+jwt",
				})
				.setIssuer(op.issuer)
				.setAudience(opts.aud ?? api)
				.setIssuedAt()
				.setExpirationTime(Math.floor(Date.now() / 1000) + op.accessTTL)
				.sign(opts.key ?? privateKey),
		close: () => new Promise<void>((resolve) => server.close(() => resolve())),
	};

	const tokens = async (g: Grant) => {
		const body: Record<string, unknown> = {
			token_type: "Bearer",
			expires_in: op.accessTTL,
			access_token: await op.accessToken({
				sub: g.sub,
				entitlements: ["read"],
			}),
			id_token: await new SignJWT({
				nonce: g.nonce,
				sid: "sess-1",
				...op.profile,
			})
				.setProtectedHeader({ alg: "RS256", kid: "k1" })
				.setIssuer(op.issuer)
				.setSubject(g.sub)
				.setAudience(clientId)
				.setIssuedAt()
				.setExpirationTime("1h")
				.sign(privateKey),
			scope: g.scope,
		};
		if (op.issueRefreshTokens) {
			const rt = `rt-${++n}`;
			refreshTokens.set(rt, g);
			body.refresh_token = rt;
		}
		return body;
	};

	const server = createServer(async (req, res) => {
		const url = new URL(req.url ?? "/", op.issuer);
		const json = (status: number, body: unknown) => {
			res
				.writeHead(status, { "content-type": "application/json" })
				.end(JSON.stringify(body));
		};
		switch (url.pathname) {
			case "/.well-known/openid-configuration":
				return json(200, {
					issuer: op.issuer,
					authorization_endpoint: `${op.issuer}/authorize`,
					token_endpoint: `${op.issuer}/token`,
					jwks_uri: `${op.issuer}/jwks`,
					end_session_endpoint: `${op.issuer}/logout`,
					id_token_signing_alg_values_supported: ["RS256"],
					code_challenge_methods_supported: ["S256"],
				});
			case "/jwks":
				return json(200, { keys: [jwk] });
			case "/authorize": {
				// The User is already signed in: straight back with a code.
				op.authorizeParams = url.searchParams;
				const q = url.searchParams;
				const code = `code-${++n}`;
				codes.set(code, {
					sub: "user-1",
					nonce: q.get("nonce") ?? "",
					scope: q.get("scope") ?? "",
					challenge: q.get("code_challenge") ?? "",
					redirectURI: q.get("redirect_uri") ?? "",
				});
				const back = new URL(q.get("redirect_uri") ?? "");
				back.searchParams.set("code", code);
				back.searchParams.set("state", q.get("state") ?? "");
				back.searchParams.set("iss", op.issuer);
				res.writeHead(302, { location: back.href }).end();
				return;
			}
			case "/token": {
				// Each half is form-urlencoded first (RFC 6749 §2.3.1).
				const [id, secret] = Buffer.from(
					(req.headers.authorization ?? "").replace(/^Basic /, ""),
					"base64",
				)
					.toString()
					.split(":")
					.map(decodeURIComponent);
				if (id !== clientId || secret !== clientSecret)
					return json(401, { error: "invalid_client" });
				let raw = "";
				for await (const chunk of req) raw += chunk;
				const form = new URLSearchParams(raw);
				if (form.get("grant_type") === "authorization_code") {
					const c = codes.get(form.get("code") ?? "");
					codes.delete(form.get("code") ?? "");
					const challenge = createHash("sha256")
						.update(form.get("code_verifier") ?? "")
						.digest("base64url");
					if (
						!c ||
						c.challenge !== challenge ||
						c.redirectURI !== form.get("redirect_uri")
					) {
						return json(400, { error: "invalid_grant" });
					}
					return json(200, await tokens(c));
				}
				if (form.get("grant_type") === "refresh_token") {
					op.refreshRequests++;
					const rt = form.get("refresh_token") ?? "";
					const g = refreshTokens.get(rt);
					if (!g) return json(400, { error: "invalid_grant" });
					refreshTokens.delete(rt); // rotated (ADR 0019)
					return json(200, await tokens(g));
				}
				return json(400, { error: "unsupported_grant_type" });
			}
		}
		res.writeHead(404).end();
	});
	await new Promise<void>((resolve) =>
		server.listen(port, "127.0.0.1", resolve),
	);
	op.issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
	return op;
}

export type FakeOP = Awaited<ReturnType<typeof startFakeOP>>;
