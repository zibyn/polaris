# 客户端认证方式二选一,Application 公钥只按值登记

M2M 与 confidential Application 的客户端认证方式在共享密钥(`client_secret_basic`)和私钥签名(`private_key_jwt`)之间严格二选一,同一时刻只认一种。切到私钥签名时 secret 立即作废;切回共享密钥时当场生成新 secret,只显示这一次。Application 公钥由管理员按值登记一份 JWKS,与当前认证方式分开保存,可以先登记、后切换;轮换就是让新旧公钥在 JWKS 里并存一段时间。不支持 JWKS URI。

## Considered Options

- **secret 与公钥并存,客户端用哪种都行**:迁移平滑,但"关掉 secret"变成没人做的一步,泄露的 secret 继续有效;go-oidc 每个 client 也只有一个认证方式。
- **切换时留过渡期,两种短暂都可用**:先登记公钥、待客户端部署后再切换,已经覆盖了平滑迁移;过渡期只多出一段两种都能用的含糊状态。
- **支持 JWKS URI,由 Polaris 去拉公钥**(Keycloak 等支持):轮换不用管理员动手,但 Polaris 要向管理员填的任意地址发请求(SSRF),还要自己做缓存与超时。真有需要时可在本方案上增量加入。

## Consequences

- 轮换公钥要管理员手动更新 JWKS;一份 JWKS 可放多把公钥,所以不必停机。
- 创建 Application 时仍一律生成 secret,切换后才作废;从未有过 secret 的 Application 不存在。
