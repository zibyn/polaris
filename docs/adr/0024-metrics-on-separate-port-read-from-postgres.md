# 指标走单独端口,能查库的就查库

Polaris 用 `prometheus/client_golang` 暴露 Prometheus 指标。`/metrics` 只开在 `POLARIS_METRICS_LISTEN` 指定的单独端口上,不设就不开,也不做鉴权,网络隔离交给部署方。指标优先在抓取时从 PG 读出来,做成 gauge:库里已经有记录的(发码、登录、锁定、webhook 积压与丢弃、每日上限)一律查库,计数类统一取最近 24 小时;只有库里没有记录的(渠道发送失败、令牌签发)才用进程内 counter。label 不带 `client_id`。

## Considered Options

- **挂在主端口上,加 bearer token 或走 RBAC**:主端口对公网开放,指标会被扫到;Prometheus 抓取时带 token 也麻烦。Keycloak 也是把指标放在单独的管理端口上。
- **全部用进程内 counter**:这是 Prometheus 的惯常做法,也能直接配 `rate()`。但每个副本各算各的,重启就清零,还要在发码、登录、投递多处埋点。这些数据 PG 里本来就有一份全局准确的(ADR 0005),再在进程里另算一遍,两边的数会对不上。
- **OpenTelemetry SDK**:依赖重,还要配 exporter 或 collector。Prometheus 文本格式 OTel collector 也能直接抓。

## Consequences

- 查库类 gauge 每个副本报的值都一样,聚合要用 `max`;进程内 `_total` 才用 `sum`。
- 每次抓取都会跑几条带索引的 count。抓取间隔照常设(15–60 秒)就没有问题。
- 登录类指标依赖审计日志,窗口受 `audit_retention_days` 限制:保留期短于 1 天时,数会偏小。
- 对应不到 User 的登录失败不进审计,所以不计入登录失败数;撞库要看 IP 锁定数。
- 24 小时滑动窗口对突发反应慢,告警用 `delta(...[15m])` 近似。
