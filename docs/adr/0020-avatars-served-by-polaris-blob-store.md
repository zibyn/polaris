# 头像存进可选的 S3 兼容对象存储,由 Polaris 上传

头像由 Polaris 自己接收上传,重新编码后写进 S3 兼容的对象存储(现成的 RustFS),`picture` claim 是存储的公开地址。这放宽了 ADR 0005「只依赖 PG」:对象存储是**可选**依赖,没配置时头像功能整体关闭(不发 `picture`、不显示上传入口),只用昵称的部署不必多跑一个服务。理由是头像不该依赖 Application 侧各自有存储,而已有 RustFS 可以直接接。

## Considered Options

- **只存 URL,图片由 Application 自存**:Polaris 零新增依赖,但每个接入方都得自备存储,账号中心也改不了头像。
- **存进 PG bytea、Polaris 托管**:不加依赖,但备份体积膨胀,所有图片流量经过 Polaris。
- **对象存储可选,不配时退回填 URL**:两条路径都要实现和测试,正是 ADR 0005 否决「Redis 可选」的理由。不配时直接关闭功能,头像始终只有一条路径。
- **预签名 PUT 直传存储**:省 Polaris 带宽,但无法校验内容,EXIF(含 GPS)原样保留。

## Consequences

- 上传经过 Polaris:只收 JPEG/PNG/WebP、≤ 5 MB,解码后居中裁成 512×512 再编码为 JPEG,去掉 EXIF 和伪装文件。
- `picture` 不能用预签名 URL(会过期):头像所在 bucket/前缀公开读,对象 key 随机不可猜,地址由 `public_base_url` 拼出。
- 每次上传换新 key、删旧对象,URL 变化即缓存失效;User 删除时头像对象一并删除。
- 一期不从上游 Provider 取头像:那要服务端抓取任意外部 URL,还要改 Provider 接口。
