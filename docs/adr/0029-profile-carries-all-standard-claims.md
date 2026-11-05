# 用户资料补全 OIDC 标准 claim,额外字段存成一列 jsonb

用户资料原先只有昵称和头像(ADR 0020)。现在补全 OIDC Core 5.1 的标准 claim:`profile` scope 下还有 `name`、`given_name`、`family_name`、`middle_name`、`profile`、`website`、`gender`、`birthdate`、`zoneinfo`、`locale`、`updated_at`,以及 `preferred_username`(取自用户名 Identifier);另外支持 `address` scope 和 `address` claim。这样接入方按标准拿 claim 就能用，不必为了姓名、生日、地址再自己维护一套资料表。昵称和头像沿用原来的列;其余字段按 claim 原名存在 `users.profile`(jsonb)里，下发时原样输出。`updated_at` 取 `users.profile_updated_at`,任何一项用户资料真的变了才更新。

## Considered Options

- **每个 claim 一列**:约束可以写在 SQL 里，但要加 16 列，以后每加一个字段都得写迁移，下发时还要逐列映射回 claim 名。校验本来就在 Go 里做(时区、语言标签、日期 SQL 不好查)。
- **继续只发昵称和头像**:接入方只能自己维护资料表，同一个 User 在每个 App 里各存一份。

## Consequences

- 用户资料仍然不是身份(ADR 0018):不唯一、不验证、不能登录。所有字段都由 User 自己填写，管理员也能改(和昵称一样用于内容治理)。
- `PATCH` 用户资料改为部分更新：请求体里出现的字段才改，空串清除;`address` 整体替换,`{}` 清除。旧请求体 `{"nickname": "..."}` 照常可用。
- 校验：文本去掉首尾空白、不能含控制字符(地址的两个多行字段允许换行),各有长度上限;`profile` 和 `website` 只收 http(s) URL(接入方会把它当链接展示，挡掉 `javascript:`);`birthdate` 只收 `YYYY-MM-DD`、`0000-MM-DD`、`YYYY`;`zoneinfo` 必须是 IANA 时区，二进制内嵌 tzdata;`locale` 是 BCP 47,存规范形式;`gender` 是自由文本。
- 任何一项变了都发 `user.updated`,`changed` 里是 `profile`;`address` 不单列一项。
- `preferred_username` 跟着用户名 Identifier 变，但不更新 `updated_at`:它属于 Identifier,改了会以 `changed: username` 通知。
- 没有同意页(授权时把请求的 scope 全部授予),所以请求了 `address` 的 Application 都能拿到地址。以后如果加同意页或按 Application 限制 scope,这一点要重新评估。
