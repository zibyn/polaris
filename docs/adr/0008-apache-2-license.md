# 采用 Apache-2.0 许可证

Polaris 以 Apache-2.0 发布。并入的 go-oidc 是 MIT 许可,两者兼容,仓库内保留其版权声明。

## Considered Options

- **MIT**:最简单,与 go-oidc 一致,但没有专利授权条款。
- **AGPL-3.0**:可以阻止闭源 SaaS 化,但会吓退部分企业自托管用户,与"让人放心自部署"的定位冲突;而且 Out of scope 已排除多租户 SaaS,AGPL 防的那种情形本来就不是本项目的形态。

## Consequences

- 任何人都可以闭源修改后部署,包括商用。
- 贡献者的专利授权随贡献自动生效。
