# Polaris Node SDK

`@zibyn/polaris`:给有后端的 Web Application 做登录(OIDC 授权码 + PKCE,登录状态存在 SDK 的会话 cookie 里),给 API 后端校验 access token。底层是 `openid-client` 和 `jose`。范围见 [ADR 0035](../../docs/adr/0035-node-and-go-sdk-scope.md)。

SDK 0.x 支持服务端 API v1。Node 20+。

```sh
pnpm add @zibyn/polaris
```

## 在 Polaris 里登记 Application

- 类型:Web Application(confidential),认证方式 `client_secret_basic`;
- **开启 refresh token**:SDK 靠它续期,回调时拿不到 refresh token 会直接报配置错误;
- redirect URI:`{baseURL}/auth/callback`;
- post logout redirect URI:`{baseURL}`(与 `baseURL` 配置逐字相同);
- 配好默认 API:`getSession()` 拿到的 access token 就是给它的。

## Web 登录

```ts
// lib/polaris.ts
import { createPolaris } from "@zibyn/polaris";

export const polaris = createPolaris({
  issuer: "https://auth.example.com",
  clientId: process.env.POLARIS_CLIENT_ID!,
  clientSecret: process.env.POLARIS_CLIENT_SECRET!,
  baseURL: "https://app.example.com",
  secret: process.env.POLARIS_SECRET!, // 至少 32 个随机字符,加密会话 cookie
  // scope 默认 "openid profile email phone"
});
```

挂上 handler,得到四个路由:

| 路由 | 作用 |
|---|---|
| `GET /auth/login?returnTo=/path` | 跳 Polaris 登录;`returnTo` 只接受本站路径 |
| `GET /auth/callback` | 换令牌、写会话 cookie,跳回 `returnTo` |
| `POST /auth/logout` | 清 cookie,跳 Polaris 退出(RP-Initiated Logout;只收 POST,别的站点不能用一个链接让 User 退出),Polaris 请 User 确认后回到 `baseURL` |
| `GET /auth/session` | 给前端的 JSON:`{ user }` 或 `null`;access token 不出服务端 |

```ts
// Next.js:app/auth/[...polaris]/route.ts
export const { GET, POST } = polaris.handler;

// Hono
app.on(["GET", "POST"], "/auth/*", (c) => polaris.handler(c.req.raw));

// TanStack Start:src/routes/auth/$.ts
export const Route = createFileRoute("/auth/$")({
  server: { handlers: { GET: ({ request }) => polaris.handler(request), POST: ({ request }) => polaris.handler(request) } },
});

// Express、node:http
import { toNodeHandler } from "@zibyn/polaris";
app.all("/auth/*splat", toNodeHandler(polaris.handler));
```

### 读取 session

```ts
const { session, headers } = await polaris.getSession(request);
// session: { user, accessToken } | null
// 把 headers 里的 Set-Cookie 加到响应上(有就必须加)
```

- `user` 是 ID token 里关于 User 的 claim(`sub`、`name`、`email`……),每次刷新时更新,不调 `/userinfo`。
- `accessToken` 只有一个,`aud` 是 Application 的默认 API。快过期(剩不到 60 秒)时自动刷新;Polaris 拒绝刷新(Session 已终止)就清掉 cookie、返回 `null`。网络错误会抛出,cookie 保留,下次再试。
- **刷新后的 cookie 必须写回浏览器**:refresh token 每次刷新都轮换,旧的超过 60 秒宽限期再用就算重用,整个 Session 会被终止(ADR 0019)。所以 `getSession` 一旦刷新,`headers` 里就带着新的 `Set-Cookie`,调用方要把它加到响应上。

不能写 cookie 的地方(Next 的 Server Component)用只读模式,它绝不刷新:

```ts
import { headers } from "next/headers";
const { session } = await polaris.getSession(await headers(), { readOnly: true }); // 过期即 null
```

Next.js 配 `proxy.ts`,在 Server Component 之前刷新,新 cookie 同时写进响应和转发给后续处理的请求:

```ts
// proxy.ts
import type { NextRequest } from "next/server";
export const proxy = (request: NextRequest) => polaris.middleware(request);
export const config = { matcher: ["/((?!auth/|_next/|favicon.ico).*)"] };
```

账号中心链接:`polaris.accountUrl()`,即 `{issuer}/account?client_id=<id>`(ADR 0034)。

### 会话 cookie

`polaris.session`:用 `secret` 加密(A256GCM),存 access token、refresh token 和 user claims,不存 ID token;超过约 3.8 KB 自动拆成 `polaris.session.0`、`.1`……;`HttpOnly`、`SameSite=Lax`,`baseURL` 为 https 时带 `Secure`;30 天有效,每次刷新重新计时。登录途中另有一个 10 分钟的 `polaris.tx`。换 `secret` 等于让所有人退出。

不实现 Back-Channel Logout:Polaris 的 Session 终止后,SDK 要等 access token 过期去刷新时才发现,所以最多滞后 10 分钟(ADR 0035)。

## API 后端:校验 access token

```ts
import { accessTokenVerifier, PolarisAuthError, requireEntitlements } from "@zibyn/polaris";

const verifyAccessToken = accessTokenVerifier({
  issuer: "https://auth.example.com",
  audience: "api://orders", // API 标识符
});

try {
  const claims = await verifyAccessToken(req.headers.authorization?.replace(/^Bearer /, ""));
  requireEntitlements(claims, "orders:read", "orders:write"); // 全部持有才通过
  // claims.sub、claims.client_id、claims.entitlements
} catch (err) {
  if (err instanceof PolarisAuthError) return new Response(null, { status: err.status }); // 401 或 403
  throw err;
}
```

按 JWKS 本地验签,检查 `iss`、`aud`、`typ: at+jwt`、过期时间;权限只看 `entitlements`,不看 `roles`。M2M Application 的 token(`client_credentials`)照常通过,`sub` 就是它的 `client_id`。

## 示例

`examples/` 下有 Next.js(App Router + proxy)和 TanStack Start 的最小应用;Hono 与 Express 的用法由 `src/` 下的测试覆盖。冒烟测试会起一个假的 Polaris,走一遍登录 → 刷新 → 读 session → 退出:

```sh
pnpm build
cd examples/next && pnpm install && pnpm dev   # 或 examples/tanstack-start,端口 3001
node ../smoke.ts http://localhost:3000
```

本地 issuer 允许 `http://localhost` / `127.0.0.1`,其余必须 https。
