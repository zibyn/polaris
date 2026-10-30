# 头像由 Polaris 上传和提供,存进 blob 存储适配层,一期只有 PG 后端

头像由 Polaris 自己接收上传、重新编码,经 `GET /avatars/{key}` 对外提供,`picture` claim 就是 `issuer + /avatars/{key}`。字节存进一层通用的 blob 存储适配层(`Put`/`Get`/`Delete`,不含头像逻辑),一期只实现 PG 后端(独立的 `blobs` 表,bytea),所以头像在每个部署里都能用,ADR 0005「只依赖 PG」不变。理由是头像不该依赖 Application 侧各自有存储;而 Polaris 量级(约一万 User,每张 512×512 JPEG 约 50 KB)下 PG 完全装得下。S3 兼容后端(已有 RustFS)等访问量需要时再加,对外地址不变。

## Considered Options

- **只存 URL,图片由 Application 自存**:Polaris 零存储,但每个接入方都得自备存储,账号中心也改不了头像。
- **直接接 RustFS,`picture` 指向公开 bucket**:要多跑一个服务、bucket 公开读;没配存储的部署要么关闭头像,要么退回填 URL,两条路径都得维护。
- **预签名 PUT 直传存储**:省 Polaris 带宽,但无法校验内容,EXIF(含 GPS)原样保留。

## Consequences

- 上传经过 Polaris:只收 JPEG/PNG/WebP、≤ 5 MB,按内容嗅探,解码后居中裁成 512×512 再编码为 JPEG,去掉 EXIF 和伪装文件。
- `/avatars/{key}` 不鉴权:`picture` 要给别的 User、别的 App 展示。key 至少 128 位随机,内容写入后不变,返回 `Cache-Control: public, max-age=31536000, immutable`;前面挂 Caddy/CDN 就能挡掉大部分回源。未知 key 返回 404。
- 每次上传换新 key,`picture` 随之变化,缓存自然失效;换头像与删除 User 时,旧 blob 在同一事务内删除,不留孤儿。
- 看头像的流量会到 Polaris 和 PG,`pg_dump` 会从几 MB 涨到几百 MB。这是加 S3 后端的触发条件。
- 将来加 S3 后端时:`/avatars/{key}` 由 Polaris 中转,bucket 保持私有;每个 blob 记下自己在哪个后端,读走它所在的后端,新写入走当前配置的后端,不做批量迁移(届时加列,存量默认 PG)。S3 上的删除只能尽力而为。
- 一期不从上游 Provider 取头像:那要服务端抓取任意外部 URL,还要改 Provider 接口。
