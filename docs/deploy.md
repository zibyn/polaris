# 部署

用 `compose.yaml` 起 Stars Auth + PostgreSQL + Caddy(自动签发 HTTPS 证书),从零到完成首次引导大约 10 分钟。

> [!CAUTION]
> **备份主密钥 `STARS_AUTH_MASTER_KEY`。** OIDC 签名私钥、TOTP 密钥、Channel 与 Provider 的密钥都用它加密入库。
> 丢了它,这些数据**无法还原**,数据库备份也救不回来。把它存进密码管理器或离线介质,和数据库备份**分开**保管。

## 准备

- 一台 Linux 主机(amd64 或 arm64),装好 Docker 与 Compose 插件(`docker compose version` 能输出)。
- 一个域名,如 `auth.example.com`,A/AAAA 记录指向这台主机。
- 80 与 443 端口对公网开放(Caddy 用 80 端口签发证书)。

## 安装

```bash
mkdir stars-auth && cd stars-auth
curl -fLO https://raw.githubusercontent.com/zibyn/stars-auth/main/compose.yaml
curl -fLO https://raw.githubusercontent.com/zibyn/stars-auth/main/Caddyfile

cat > .env <<END
STARS_AUTH_DOMAIN=auth.example.com
STARS_AUTH_VERSION=0.1.0
STARS_AUTH_MASTER_KEY=$(openssl rand -base64 32)
POSTGRES_PASSWORD=$(openssl rand -hex 16)
END
chmod 600 .env

docker compose up -d
```

`STARS_AUTH_VERSION` 填 [Releases](https://github.com/zibyn/stars-auth/releases) 中的版本号(不带 `v`)。现在就把 `.env` 里的主密钥抄去备份。

## 首次引导

```bash
docker compose logs stars-auth | grep setup
# WARN no admin yet: open the setup page to create the owner url="https://auth.example.com/setup?token=..."
```

打开这个链接,设置「所有者」的用户名和密码。完成后引导页永久关闭;所有者在 `https://auth.example.com/console` 登录管理端。

## 环境变量

Stars Auth 只从环境变量读启动参数,其余配置都在管理端里、存在数据库中。

| 变量 | 说明 |
|---|---|
| `STARS_AUTH_DATABASE_URL` | 必填。PostgreSQL 15+ 连接串。 |
| `STARS_AUTH_ISSUER` | 必填。对外的 https 地址,如 `https://auth.example.com`。上线后**不要改**:改了以后已签发的令牌和各 Application 的配置都会失效。 |
| `STARS_AUTH_MASTER_KEY` | 主密钥:32 个随机字节的 base64(`openssl rand -base64 32`)。与下一项二选一。 |
| `STARS_AUTH_MASTER_KEY_FILE` | 从文件读主密钥,适合 Docker/Kubernetes secret。 |
| `STARS_AUTH_TRUSTED_PROXIES` | 反向代理的 IP 或 CIDR,逗号分隔。只信任它们的 `X-Forwarded-For`;限流与失败锁定按客户端 IP 计数,填错会把所有人算成同一个 IP。 |
| `STARS_AUTH_LISTEN` | 监听地址,默认 `:8080`。 |

`compose.yaml` 另外读 `.env` 中的 `STARS_AUTH_DOMAIN`(域名,不填就是 `https://localhost`,证书由 Caddy 本地 CA 签发,只适合试用)、`STARS_AUTH_VERSION`(镜像版本,不填是 `latest`)、`POSTGRES_PASSWORD`。

不用容器时,从 Releases 下载对应平台的单个二进制,设好上面的变量直接运行,前面放一个反向代理终结 TLS。

## 备份

```bash
docker compose exec -T postgres pg_dump -U stars -Fc stars > stars-$(date +%F).dump
```

恢复到一个重建的空库(现有数据全部丢弃,需要**同一把**主密钥;升级后回退也走这一步,换回旧版本镜像再启动):

```bash
docker compose stop stars-auth
docker compose exec -T postgres dropdb -U stars stars
docker compose exec -T postgres createdb -U stars stars
docker compose exec -T postgres pg_restore -U stars -d stars < stars-2026-10-07.dump
docker compose start stars-auth
```

## 升级

迁移脚本永不删除、永不合并,任何旧版本都能直接升到最新版。**不支持降级**,也**不支持滚动升级**。

1. 先按上一节 `pg_dump`。想回退,只能用这份备份恢复到旧版本。
2. 把 `.env` 中的 `STARS_AUTH_VERSION` 改成新版本。
3. 停掉全部副本,再启动新版本(启动时自动迁移数据库):

   ```bash
   docker compose pull stars-auth
   docker compose stop stars-auth
   docker compose up -d stars-auth
   ```

4. 跑了多个副本的,确认新版本正常后再扩容。

## 所有管理员都无法登录时

Stars Auth 没有后门,只能直接改数据库。先进 psql:

```bash
docker compose exec postgres psql -U stars
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

  然后 `docker compose restart stars-auth`,按「首次引导」拿新链接,用一个**没被占用的用户名**创建所有者。登录管理端后,在用户详情里为原来的管理员重置两步验证、恢复禁用或重新分配 Role。打开了"管理员必须启用两步验证"的话,新所有者会先被拦下,按提示到账号中心开启两步验证后再进管理端。引导完成后引导页再次自动关闭。

## 已知风险与合规提醒

- **运营商二次放号**:手机号停用后会被运营商重新放出。新号主用验证码就能登录前一个人的账号。Stars Auth 不专门处理;开了 2FA 或 Passkey 的 User 不受影响。重要账号建议引导用户开启。
- **以下事项由运营方自己负责,Stars Auth 不提供相应功能**:
  - **未成年人保护**:年龄识别、防沉迷、监护人同意等。
  - **数据出境**:服务器或备份放在境外,或者向境外提供个人信息,须自行完成相应的评估、认证或标准合同。
  - **等保测评**:按系统定级自行备案和测评。
  - **实名**:管理端只有"必须绑定手机号"开关;是否需要打开,按你的 Application 是否属于信息发布、即时通讯类服务自己判断。
