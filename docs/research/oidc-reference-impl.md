# OIDC 协议层参考实现选型：并入 `luikyv/go-oidc`，还是以 panva `oidc-provider` 为蓝本自写

- 调研日期：2026-10-06
- 对应 issue：[#16](https://github.com/zibyn/stars-auth/issues/16)（map：#1）
- 背景：[ADR 0001](../adr/0001-self-owned-oidc-layer.md)。协议层是自有代码，从一份已获认证的实现起步；必须通过 Basic OP + Config OP 认证，RP-Initiated Logout 可选；JOSE 与密码学用成熟库；不引入 AGPL 代码。
- 对照的版本：`luikyv/go-oidc` v0.25.0（main @ 2026-07-22），`panva/node-oidc-provider` v9.12.2（main @ 2026-10-01）。两个仓库都浅克隆到本地实测。
- 写法约定：每条事实都附一手来源（仓库源码、GitHub API、openid.net、IETF datatracker）；我自己的判断标 **【推断】**；没能核实的标 **未验证**。

## 1. 结论

**建议：把 `luikyv/go-oidc` v0.25.0 并入仓库，先裁剪再自维护。panva `oidc-provider` 不作为翻译蓝本，只在两件事上当对照：一是行为与边界情况（看它的测试），二是 RP-Initiated Logout（它在这项上有认证）。**

理由（展开见第 2–6 节）：

1. **认证起点**：两者都在 openid.net 的认证列表里，都覆盖 Basic OP 和 Config OP。go-oidc 的认证更新（2025-08，对应 v0.11.0+），panva 是 2020-07。RP-Initiated Logout 只有 panva 拿到了认证；go-oidc 实现了这项，也在自己的 CI 里跑这套测试，但没有提交认证。
2. **语言与依赖**：go-oidc 本来就是 Go，只依赖 `go-jose/v4`、`google/uuid` 和 `go-cmp`（其中 `go-cmp` 只用于测试）。panva 是 Node/Koa 加 `jose`。拿 panva 当蓝本，等于把约 2 万行 JS 翻译成 Go，而且要到翻译基本完成，才能第一次跑通 conformance suite。
3. **first-party 的 `authorization_challenge_endpoint`**：go-oidc 里的 authorization code 就是存储层里一条 `Grant` 记录，带 `AuthCode` 字段；存储接口由使用方实现。所以自有端点完成认证后，只要写入这样一条 Grant，标准 token 端点就能原样兑换，token 端点的代码不用改（第 4 节）。
4. **短板与对策**：go-oidc 是单一作者、v0.x，单元测试覆盖率 65.1%（panva 是 96.5%）；还带着大量本项目用不上的功能（Federation、VC、CIBA、FAPI 等）。【推断】并入后删掉这些功能，目标规模在 1 万行上下。删完以后，conformance suite 加 panva 测试用例里的边界情况，一起补上覆盖率缺口。上游频繁改名、破坏 API（v0.22、v0.23 都有），这在并入之后不再影响我们，但也意味着以后不能指望从上游轻松合并修复。

## 2. 认证 profile 覆盖（openid.net 实查）

来源：
- [Certified OpenID Providers & Profiles](https://openid.net/certification/certified-openid-providers-profiles/)
- [Certified OpenID Providers for Logout Profiles](https://openid.net/certification/certified-openid-providers-for-logout-profiles/)
- [Certified OpenID Connect Implementations（开发者页）](https://openid.net/developers/certified-openid-connect-implementations/)

以上三页均于 2026-10-06 抓取 HTML，并解析其中的表格。

| Profile | panva `node oidc-provider` | `luikyv/go-oidc` |
|---|---|---|
| Basic OP | ✅ 29-Jul-2020 | ✅ 10-Aug-2025（"go-oidc >= 0.11.0"）；更早还有一条 23-Oct-2024（"go-oidc 0.4.0"，仅 Basic OP） |
| Config OP | ✅ 29-Jul-2020 | ✅ 10-Aug-2025 |
| Implicit / Hybrid OP | ✅ / ✅ 2020-07 | ✅ / ✅ 11-Aug-2025 |
| Dynamic OP | — 表中为空 | ✅ 10-Aug-2025 |
| Form Post OP / 3rd Party-Init OP | ✅ / ✅ 2020-07 | — / — |
| RP-Initiated OP | ✅ 29-Jul-2020（另有一条 11-Nov-2019） | — **未认证** |
| Back-Channel OP | ✅ 2020-07 / 2019-11 | — |
| FAPI | FAPI 1 Adv.、FAPI CIBA、FAPI 2.0 SP/MS（开发者页上有 "node oidc-provider >= 9.2.0"） | FAPI 1 Adv.（"go-oidc >= 0.11.0"），README 另外声称有 FAPI 2.0 |

补充说明：

- 上表与两边 README 的 Certification 小节一致：[go-oidc README](https://github.com/luikyv/go-oidc#certification) 写的是 "Basic OP, Implicit OP, Hybrid OP, Config OP and Dynamic OP / FAPI 1.0 / FAPI 2.0"；[oidc-provider README](https://github.com/panva/node-oidc-provider#certification) 写的是 "Basic, Implicit, Hybrid, Config, Form Post, and 3rd Party-Init / Back-Channel Logout and RP-Initiated Logout / FAPI 1.0 / FAPI CIBA / FAPI 2.0"。
- panva 那条 2020 年 Basic OP 记录没有标版本号，对应哪个大版本 **未验证**。按 OIDF FAQ，"[Certifications] do not expire. The date that the certification was performed is part of the certification."（[FAQ](https://openid.net/certification/what-is-self-certification-faq/)）。所以它至今仍是有效认证，只是年代较早。
- go-oidc 虽然没有 RP-Initiated 认证，但它的 [Makefile](https://github.com/luikyv/go-oidc/blob/main/Makefile) 里 `cs-oidc-tests` 包含 `oidcc-rp-initiated-logout-certification-test-plan`，而 [`examples/oidc/failures.json`](https://github.com/luikyv/go-oidc/blob/main/examples/oidc/failures.json) 只把 `oidcc-userinfo-post-body`（warning）和 `oidcc-server-rotate-keys`（CI 无法触发轮换）列为预期失败。也就是说，logout 测试计划在它的 CI 里是通过的。
- go-oidc 在 main 上最近一次 conformance workflow（2026-07-23，run 29971459357）的 17 个 profile 全部成功；见 `gh run list -R luikyv/go-oidc -w conformance.yml -b main`。
- **认证不随代码转移**：提交认证时要填 "Deployment Name & Version identifies the actual software version that is being declared conformant"（[提交流程](https://openid.net/certification/how-to-submit-your-certification-request/)）。【推断】不论选哪条路，Polaris 都得用自己的部署和版本号重新认证。"起步于已认证实现"降低的是通过测试的难度，并不能直接带来认证。

## 3. 代码量、结构、测试、一人维护负担

### 3.1 量化（本地实测）

| | go-oidc v0.25.0 | oidc-provider v9.12.2 |
|---|---|---|
| 生产代码 | 24 k 行 Go（`pkg/` + `internal/` ≈ 21 k，`examples/` ≈ 2.9 k） | 20.5 k 行 JS（`lib/`，183 个文件） |
| 测试代码 | 31.5 k 行 | 46 k 行（3415 个用例通过） |
| 单元测试覆盖率 | **65.1%**（语句覆盖，`go test -coverprofile`，排除 `internal/oidctest`，与其 Makefile 的 `test-coverage` 目标一致） | **96.5%**（语句覆盖；分支覆盖 94.1%；在 `npm test` 外面套 `c8 --include 'lib/**'`） |
| 运行时依赖 | `go-jose/v4` v4.1.4、`google/uuid`（另有 `go-cmp`，只在测试中使用） | `jose` ^6.2.12、`koa` ^3.2.1、`debug` |
| 许可证 | MIT | MIT |
| 贡献者 | luikyv 519 次提交；其余人合计约 10 次（不含 dependabot） | 维护者为 Filip Skokan（panva） |
| 近一年提交数（自 2025-10-06 起） | 55 | 274 |
| Stars | 115 | 3826 |

go-oidc 各目录的生产 / 测试行数：`internal/federation` 4396 / 5472，`internal/vc` 1098 / 1581，`internal/token` 2647 / 6810，`internal/authorize` 2446 / 4485，`internal/client` 1823 / 2944，`pkg/provider` 3074 / 3773，`pkg/goidc` 1931 / 766，`internal/logout` 283 / 529，`internal/discovery` 199 / 284。

### 3.2 结构与可读性

- **go-oidc**：分层清楚。`pkg/provider` 用 functional options 组装（共 164 个 `With*` 选项）；`pkg/goidc` 放公共类型和存储接口（`GrantManager`、`AuthManager`、`LogoutManager` 等，每个只有 2–5 个方法）；`internal/<endpoint>` 每个端点一个包，各包都分 `api.go`（HTTP）、`model.go`、`validation.go` 和逐 grant 的文件。本项目用不上的功能都集中在独立的包或文件里（`internal/federation`、`internal/vc`、`internal/authorize/{ciba,device,par,jar}.go`、`internal/token/{ciba,device,exchange,jwt_bearer,pre_auth_code}.go`）。【推断】因此可以按目录整块删除，不用逐行剥离。
- **oidc-provider**：Koa 中间件链，加上 `lib/helpers/defaults.js`（3919 行，配置与文档同源）。它的模型（`AuthorizationCode`、`Grant`、`Session` 等）是基于 `BaseToken` 的动态类，适配器只有一个通用的 `upsert/find/consume/destroy` 接口。文档（`docs/README.md` 5230 行）质量很高。【推断】它的结构深度依赖 JS 的动态特性和 Koa 的 ctx，译成 Go 后几乎要重新设计，很难逐文件对照。

### 3.3 一人维护负担 【推断】

- **并入 go-oidc**：第一天就有一份能跑通 Basic、Config 和 RP-Initiated conformance 计划的 Go 代码，以及现成的 CI（见第 6 节）。之后的工作是裁剪、补测试、改造存储接口去对接自己的数据层，每一步都可以用 conformance suite 回归。风险在于覆盖率偏低，以及作者的代码风格（例如 `Grant` 结构体里平铺着各种 grant 的字段）以后要由我们自己消化。
- **以 panva 为蓝本自写**：要按 OIDC Core、Discovery、RFC 6749/7636/9700 加 RP-Initiated Logout，逐项重新实现 authorize、token、userinfo、discovery、client 认证、logout。panva 的测试只能人工转写成 Go 测试；而 conformance suite 只有在主干流程基本完成后才能开始提供反馈。对一个业余维护者来说，前期投入明显更高，"写出来但没认证"的风险也更大。
- 上游跟进：go-oidc 是 v0.x，近几个版本都有破坏性改名（v0.23.0 release notes 里列了 `WithHandleGrantFunc` → `WithGrantHandler` 等一串改名；v0.22.0 删掉了 `WithTokenAuthnMethods`）。并入后我们不再跟着它的 API 走，只需人工关注安全修复。panva 的 [`SECURITY.md`](https://github.com/panva/node-oidc-provider/blob/main/SECURITY.md) 和 GitHub advisories 也值得订阅，因为同类漏洞往往两边都会有（**未验证**是否存在共通的历史漏洞）。

## 4. 能否自然加入 `authorization_challenge_endpoint`

### 4.1 草案要求（一手）

[draft-ietf-oauth-first-party-apps](https://datatracker.ietf.org/doc/draft-ietf-oauth-first-party-apps/) 当前版本为 -04，状态 "WG Consensus: Waiting for Write-Up"，尚非 RFC，过期日 2027-01-02（datatracker API）。从 [-04 正文](https://www.ietf.org/archive/id/draft-ietf-oauth-first-party-apps-04.txt) 看：

- 客户端向 `authorization_challenge_endpoint` POST 凭据，可带 `auth_session`、`code_challenge` 和 `code_challenge_method`；成功时返回 `authorization_code`（§5.2），失败时返回 `insufficient_authorization` 加 `auth_session`，或者 `redirect_to_web` 等错误（§5.3）。
- §6：客户端用这个 code 走标准 token 请求（RFC 6749 §4.1.3）。"notably, the redirect_uri parameter will not be included in this request"。token 响应 **MAY** 带 `auth_session`（§6.1）。
- §9.6.1 建议把 `auth_session` 绑定到 DPoP 密钥。

### 4.2 go-oidc：只需写入一条 Grant，token 端点不改

- authorization code 就是 `goidc.Grant` 上的 `AuthCode`、`AuthCodeExpiresAt` 和 `AuthCodeConsumedAt` 字段（[`pkg/goidc/grant.go`](https://github.com/luikyv/go-oidc/blob/main/pkg/goidc/grant.go)）。授权端点认证成功后，也是这样生成 code 的（`internal/authorize/authorize.go` 约 280–320 行：先构造 Grant，再 `AuthCode: ctx.AuthCode()`）。
- token 端点按 `ctx.GrantByAuthCode(code)` 查 Grant（[`internal/token/auth_code.go`](https://github.com/luikyv/go-oidc/blob/main/internal/token/auth_code.go)），之后依次校验：未撤销、未消费、client 匹配、未过期、`req.redirectURI != grant.AuthParams.RedirectURI`、PKCE 和 DPoP/mTLS 绑定。`GrantByAuthCode` 由使用方实现的 `goidc.AuthManager` 提供（[`pkg/goidc/model.go`](https://github.com/luikyv/go-oidc/blob/main/pkg/goidc/model.go)）。
- 由此推出的做法：自有的 `/authorization-challenge` handler 完成认证（短信 OTP、密码、微信 code 等），然后写入一条 Grant，`AuthParams.RedirectURI` 留空，`AuthParams.CodeChallenge` 填客户端传来的值，`JWKThumbprint` 取 DPoP 的 thumbprint。客户端兑换时不带 `redirect_uri`，空串等于空串，校验通过，正好满足草案 §6。PKCE 校验（`internal/token/validation.go` 的 `validatePKCE`）只在 Grant 里有 `CodeChallenge` 时才强制，也与草案一致。
- 需要改库的地方只有一处：token 响应结构 `internal/token/model.go` 的 `response` 里没有扩展字段，所以要在 token 响应里返回 `auth_session`（MAY 级别），就得给它加字段。并入仓库后，这只是一处小改动。
- **未验证**：没有实际写代码跑通。ID Token 的 `auth_time`、`acr` 和 `amr` 要从 Grant 或 session 里取，具体字段映射也还没有逐一核对。

### 4.3 oidc-provider：可行，但对我们没有直接意义

- 它没有实现这份草案：`lib/actions/challenge.js` 是 DPoP、attestation 和 c_nonce 的 challenge 端点，与 first-party 无关；在 `lib/` 和文档里 grep `authorization_challenge` 也查不到。
- 它可以 `new provider.AuthorizationCode({...}).save()`（模型通过 `provider.AuthorizationCode` 暴露，见 `lib/provider.js:374`；授权端点自己就是这样签发 code 的，见 `lib/helpers/process_response_types.js:80`），也可以 `registerGrantType`（[docs](https://github.com/panva/node-oidc-provider/blob/main/docs/README.md#custom-grant-types)）。但 code 需要关联 `grantId`（即 Grant 模型），还涉及 `sessionUid` 绑定检查（`checkSessionBinding`）。【推断】机制上可行；但我们不会在运行时用 Node，所以它在这里只能帮我们参考"code 应该带哪些字段"。

## 5. JOSE / 加密依赖

- **go-oidc**：JOSE 全部交给 [`github.com/go-jose/go-jose/v4`](https://github.com/go-jose/go-jose)（v4.1.4，见 `go.mod`）。自己只写了一层很薄的 `internal/joseutil`（205 行，覆盖率 90.5%）和 `internal/hashutil`（37 行，用于 `at_hash`/`c_hash` 之类的哈希）。签名器可以通过 `WithSigner` 注入，例如接 KMS 或 HSM。这与 ADR "JOSE 依赖成熟库" 一致，也与市场调研 4.1 节"JOSE 跟随 OP 库，避免两套"的建议一致。
- **oidc-provider**：JOSE 用同一作者的 [`jose`](https://github.com/panva/jose)（^6.2.12）。如果以它为蓝本自写，Go 侧仍要另选 JOSE 库，【推断】大概率也是 go-jose v4，那么从 panva 能借鉴的只有调用的位置，而不是 API 的形状。
- 两边都没有手写密码学原语（就源码目录结构和依赖清单而言；没有逐行审计）。

## 6. 认证费用、流程，以及 conformance suite 能否在 CI 自托管

### 6.1 费用（[Fee Schedule](https://openid.net/certification/fees/)）

- OpenID Connect 认证：OIDF 会员 **$700**，非会员 **$3,500**，按 "per new deployment" 计。同一自然年内，这一笔费用可以认证任意多个 profile（原文举例：先认证 Basic OP + Config OP，同年再加 Implicit/Hybrid/Dynamic 不再收费）。OP 和 RP 分开收费。
- FAPI、FAPI-CIBA 另计（会员 $1,000，非会员 $5,000），与本项目无关。
- **开源费用减免**（[Open Source Project Certification Policy](https://openid.net/certification/open-source-project-certification-policy/)）：可以发邮件到 certification@oidf.org 申请。条件是申请人与该部署相关，并声明 "none of the primary maintainers of the open source project are being compensated by an employer for their work on the project"；OIDF 逐案审批，"Not all open source projects will qualify"。【推断】Polaris 是个人业余维护的开源项目，符合申请条件，但能否获批 **未验证**。
- OIDF 个人会员的会费 **未验证**（本次没有查）。

### 6.2 流程（[How to submit](https://openid.net/certification/how-to-submit-your-certification-request/)）

1. 在 conformance suite 里跑完目标 profile 的测试计划。每个计划用 "Publish for certification" 导出一个 zip 文件，里面是测试日志。
2. 在 Certification Payment 页付费（PayPal 或开发票，开票最多需要 2 天），拿到 payment code。
3. 到 <https://submissions.openid.net/> 填表，填写实体名、带版本号的部署名、payment code 和联系人，然后电子签署 Declaration of Conformance。
4. 认证不会过期（[FAQ](https://openid.net/certification/what-is-self-certification-faq/)）。

### 6.3 能否在 CI 自托管

- **能，两个参考实现都在这样做**：
  - go-oidc 的 [`.github/workflows/conformance.yml`](https://github.com/luikyv/go-oidc/blob/main/.github/workflows/conformance.yml) 克隆 `gitlab.com/openid/conformance-suite` 的 `release-v5.1.45` 分支，用 Maven 容器构建，再用仓库里的 [`docker-compose.yml`](https://github.com/luikyv/go-oidc/blob/main/docker-compose.yml)（mongodb + nginx + suite server，`extra_hosts` 把 `auth.localhost` 指到宿主机）起服务，最后用 suite 自带的 `scripts/run-test-plan.py` 加 `--expected-failures-file` 跑计划。整套流程在 GitHub Actions 的 ubuntu-latest 上运行。
  - panva 的 [`conformance.yml`](https://github.com/panva/node-oidc-provider/blob/main/.github/workflows/conformance.yml) 每个 profile 一个 matrix 项，含 `oidcc-basic-certification-test-plan` 和 `oidcc-rp-initiated-logout-certification-test-plan`，每周定时运行。它调用的复合 action（`panva/.github/.github/actions/conformance-suite`）使用 suite 仓库里的 `docker-compose-prebuilt.yml`，并缓存 Docker 镜像。
- Suite 本身是 MIT 许可（GitLab API），活跃：最新 tag `release-v5.3.1`，2026-09-18。
- **限制：本地实例的结果不能用于认证**。OIDF 在 [FAPI RP 测试页](https://openid.net/certification/fapi_rp_testing/) 上明确写着 "you can use a local instance … for your internal purposes but you must use https://www.certification.openid.net/ for certification submissions. You cannot certify with results obtained from a local instance." 这句话出自 FAPI RP 页面；【推断】OIDC OP 认证同样适用，因为认证列表里每条记录都链接到 `www.certification.openid.net/plan-detail.html?...&public=true`。所以正式认证时，需要把一个公网可达的部署接到官方托管实例上跑一遍，CI 里的自托管实例只做回归。

## 7. 对后续工作的含义 【推断】

1. 把 go-oidc v0.25.0 原样导入仓库（例如放到 `internal/oidc/`），保留 MIT 版权声明，并记录上游 commit。第一步先把它的 conformance CI 搬过来跑绿，再开始裁剪。
2. 按目录删除 federation、vc、ciba、device、par、jar、jarm、exchange、jwt_bearer、pre_auth_code、DCR 和 mTLS 相关代码。每删一块都跑一遍 Basic、Config 和 RP-Initiated 三个计划。
3. 在 `Grant` 上实现 `authorization_challenge_endpoint`（第 4.2 节），并给 token 响应补上 `auth_session` 字段。
4. 补单元测试时，以 panva 的测试用例为清单，优先补 authorize 和 token 的边界情况。
5. 认证时先申请开源费用减免，再在官方托管 suite 上跑 Basic OP + Config OP（可以加上 RP-Initiated OP，同一笔费用内不另收费）。
