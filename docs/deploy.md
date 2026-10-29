# 部署

用 `compose.yaml` 起 Polaris + PostgreSQL + Caddy(自动签发 HTTPS 证书),从零到完成首次引导大约 10 分钟。

> [!CAUTION]
> **备份主密钥 `POLARIS_MASTER_KEY`。** OIDC 签名私钥、TOTP 密钥、Channel 与 Provider 的密钥都用它加密入库。
> 丢了它,这些数据**无法还原**,数据库备份也救不回来。把它存进密码管理器或离线介质,和数据库备份**分开**保管。

## 准备

- 一台 Linux 主机(amd64 或 arm64),装好 Docker 与 Compose 插件(`docker compose version` 能输出)。
- 一个域名,如 `auth.example.com`,A/AAAA 记录指向这台主机。
- 80 与 443 端口对公网开放(Caddy 用 80 端口签发证书)。

## 安装

```bash
mkdir polaris && cd polaris
curl -fLO https://raw.githubusercontent.com/zibyn/polaris/main/compose.yaml
curl -fLO https://raw.githubusercontent.com/zibyn/polaris/main/Caddyfile

cat > .env <<END
POLARIS_DOMAIN=auth.example.com
POLARIS_VERSION=0.1.0
POLARIS_MASTER_KEY=$(openssl rand -base64 32)
POSTGRES_PASSWORD=$(openssl rand -hex 16)
END
chmod 600 .env

docker compose up -d
```

`POLARIS_VERSION` 填 [Releases](https://github.com/zibyn/polaris/releases) 中的版本号(不带 `v`)。现在就把 `.env` 里的主密钥抄去备份。

## 首次引导

```bash
docker compose logs polaris | grep setup
# WARN no admin yet: open the setup page to create the owner url="https://auth.example.com/setup?token=..."
```

打开这个链接,设置「所有者」的用户名和密码。完成后引导页永久关闭,浏览器直接跳到管理端(`/console`)的登录页,用刚才设置的账号登录。

## 环境变量

Polaris 只从环境变量读启动参数,其余配置都在管理端里、存在数据库中。

| 变量 | 说明 |
|---|---|
| `POLARIS_DATABASE_URL` | 必填。PostgreSQL 15+ 连接串。 |
| `POLARIS_ISSUER` | 必填。对外的 https 地址,如 `https://auth.example.com`。上线后**不要改**:改了以后已签发的令牌和各 Application 的配置都会失效。 |
| `POLARIS_MASTER_KEY` | 主密钥:32 个随机字节的 base64(`openssl rand -base64 32`)。与下一项二选一。 |
| `POLARIS_MASTER_KEY_FILE` | 从文件读主密钥,适合 Docker/Kubernetes secret。 |
| `POLARIS_TRUSTED_PROXIES` | 反向代理的 IP 或 CIDR,逗号分隔。只信任它们的 `X-Forwarded-For`;限流与失败锁定按客户端 IP 计数,填错会把所有人算成同一个 IP。 |
| `POLARIS_LISTEN` | 监听地址,默认 `:8080`。 |
| `POLARIS_METRICS_LISTEN` | Prometheus 指标的监听地址,如 `:9090`。不设就不开。见[指标](#指标)。 |

`compose.yaml` 另外读 `.env` 中的 `POLARIS_DOMAIN`(域名,不填就是 `https://localhost`,证书由 Caddy 本地 CA 签发,只适合试用)、`POLARIS_VERSION`(镜像版本,不填是 `latest`)、`POSTGRES_PASSWORD`。

不用容器时,从 Releases 下载对应平台的单个二进制,设好上面的变量直接运行,前面放一个反向代理终结 TLS。

## 指标

设了 `POLARIS_METRICS_LISTEN` 后,Polaris 在这个地址上单独起一个 HTTP 服务,只提供 `GET /metrics`(Prometheus 文本格式)。它**不鉴权**,也不出现在主端口上:别把这个端口暴露到公网,只让 Prometheus 能访问到。它不能和 `POLARIS_LISTEN` 相同,否则启动失败。

除 `go_*`、`process_*` 外,还有下面这些。前一组在每次抓取时从 PostgreSQL 现查(ADR 0024),数据库不可用时这次抓取返回 500,不会报 0。

| 指标 | 类型 | 含义 |
|---|---|---|
| `polaris_code_sends_last_24h` | gauge | 最近 24 小时发出的验证码和邀请邮件,和每日上限、控制台概览同一个口径 |
| `polaris_daily_send_limit` | gauge | 每日发送上限,0 表示不限 |
| `polaris_logins_succeeded_last_24h` | gauge | 最近 24 小时的 `login.succeeded` 审计事件数 |
| `polaris_logins_failed_last_24h` | gauge | 最近 24 小时的 `login.failed` 审计事件数。对应不到 User 的失败不在其中,撞库看 IP 锁定数 |
| `polaris_lockouts_last_24h{kind="ip"\|"password"}` | gauge | 最近 24 小时的 IP 锁定 / 密码锁定次数 |
| `polaris_webhook_deliveries_pending` | gauge | 待投递的 webhook |
| `polaris_webhook_deliveries_retrying` | gauge | 其中至少失败过一次的 |
| `polaris_webhook_dropped_last_24h` | gauge | 最近 24 小时重试用尽、放弃投递的 webhook |
| `polaris_code_send_failures_total{kind="sms"\|"email"}` | counter | 渠道发送返回错误的次数(验证码和邀请邮件)。被每日上限或频率限制拒绝的不算 |
| `polaris_tokens_issued_total{grant_type}` | counter | 签发的访问令牌数,按 `authorization_code`、`refresh_token`、`client_credentials` 分 |

`_last_24h` 是滑动窗口,告警用 `delta(...[15m])` 近似。登录类指标来自审计日志,审计保留期短于 1 天时数会偏小。

多副本时:查库类 gauge 每个副本报的值一样,聚合用 `max`;`_total` 是各副本进程内的计数,重启清零,聚合用 `sum`(配 `rate()`)。

## 备份

```bash
docker compose exec -T postgres pg_dump -U polaris -Fc polaris > polaris-$(date +%F).dump
```

恢复到一个重建的空库(现有数据全部丢弃,需要**同一把**主密钥;升级后回退也走这一步,换回旧版本镜像再启动):

```bash
docker compose stop polaris
docker compose exec -T postgres dropdb -U polaris polaris
docker compose exec -T postgres createdb -U polaris polaris
docker compose exec -T postgres pg_restore -U polaris -d polaris < polaris-2026-10-07.dump
docker compose start polaris
```

头像存在 PG 里(`blobs` 表,每个 512×512 JPEG 约几十 KB),会让 `pg_dump` 随用户数变大。`/avatars/` 的响应可以永久缓存(地址随每次上传改变),用户多时建议在 Caddy 或 CDN 上缓存这一路径。

## 升级

迁移脚本永不删除、永不合并,任何旧版本都能直接升到最新版。**不支持降级**,也**不支持滚动升级**。

1. 先按上一节 `pg_dump`。想回退,只能用这份备份恢复到旧版本。
2. 把 `.env` 中的 `POLARIS_VERSION` 改成新版本。
3. 停掉全部副本,再启动新版本(启动时自动迁移数据库):

   ```bash
   docker compose pull polaris
   docker compose stop polaris
   docker compose up -d polaris
   ```

4. 跑了多个副本的,确认新版本正常后再扩容。

## 所有管理员都无法登录时

Polaris 没有后门,只能直接改数据库。先进 psql:

```bash
docker compose exec postgres psql -U polaris
```

- **只是被锁定**(连续输错密码,或 IP 失败太多):等 15 分钟 / 1 小时,或者立即解除:

  ```sql
  DELETE FROM lockouts;
  ```

- **丢了验证器和全部恢复码,但还有别的管理员能登录**:请对方线下核实身份后,在管理端的用户详情里点「重置两步验证」(需要 `users:write`;对方是管理员时还需要 `admin-roles:assign`)。重置不会让任何设备下线;之后只用验证码或密码就能登录,再到账号中心重新开启两步验证。

- **其他情况**(忘了密码、丢了两步验证且没有别的管理员、被禁用、管理员 Role 被撤掉):重新打开引导页,建一个新的所有者:

  ```sql
  UPDATE settings SET setup_done = false;
  -- 密码登录被设成了"关闭"的话,改回开启:
  UPDATE settings SET password_login = 'on' WHERE password_login = 'off';
  ```

  然后 `docker compose restart polaris`,按「首次引导」拿新链接,用一个**没被占用的用户名**创建所有者。登录管理端后,在用户详情里为原来的管理员重置两步验证、恢复禁用或重新分配 Role。打开了"管理员必须启用两步验证"的话,新所有者会先被拦下,按提示到账号中心开启两步验证后再进管理端。引导完成后引导页再次自动关闭。

## 已知风险与合规提醒

- **运营商二次放号**:手机号停用后会被运营商重新放出。新号主用验证码就能登录前一个人的账号。Polaris 不专门处理;开了 2FA 或 Passkey 的 User 不受影响。重要账号建议引导用户开启。
- **以下事项由运营方自己负责,Polaris 不提供相应功能**:
  - **未成年人保护**:年龄识别、防沉迷、监护人同意等。
  - **数据出境**:服务器或备份放在境外,或者向境外提供个人信息,须自行完成相应的评估、认证或标准合同。
  - **等保测评**:按系统定级自行备案和测评。
  - **实名**:管理端只有"必须绑定手机号"开关;是否需要打开,按你的 Application 是否属于信息发布、即时通讯类服务自己判断。
