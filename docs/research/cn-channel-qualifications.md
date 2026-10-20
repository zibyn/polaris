# 各登录渠道的主体资质门槛与配置面（中国大陆）

调研日期：2026-10-06。范围：每个认证渠道要求 Operator 具备什么主体资质、需要在管理后台填什么参数、个人主体与企业主体的能力差异。不含 IdP 产品调研和免密登录技术可行性（见同目录其他调研）。

**阅读须知**

- 来源均为厂商官方文档、平台规则、价格页或政府文件，链接紧跟在结论后面。
- 多数页面由抓取工具的摘要模型转述，引号内文字可能有轻微出入；数字和日期在写入 ADR 前请点开原页复核一次。其中三条关键结论做过二次核对，文中标「已复核」。
- 标「未验证」的条目没有从一手页面确认，不要当事实使用。
- 标「推断」的是本文作者的判断，不是来源原话。
- 这些规则变动频繁（短信签名规则在 2025-03 至 2026-04 之间改了四次），本文只代表调研当日的状态。

## 1. 短信验证码

### 1.1 结论

个人 Operator 已经不能以自己的名义在阿里云短信或腾讯云短信申请签名。个人唯一不需要企业资质的验证码通道，是阿里云号码认证服务里的「短信认证」：签名和模板由阿里云赠送，短信里不显示 Operator 的品牌。

### 1.2 阿里云短信服务（国内）

- **个人自用资质已停**：2025-06-06 公告称运营商不再接纳个人身份的自用资质，存量个人自用资质不能编辑、不能关联新签名。个人只剩两条路：升级企业认证，或申请「他用」资质（借用某个企业主体并提交委托授权书）。[公告](https://help.aliyun.com/zh/sms/product-overview/announcement-on-sms-not-supporting-application-for-personal-use-qualification)
- **签名来源持续收窄**：
  - 2025-03-17 起停止：公众号/小程序、电商店铺名、已备案网站、测试或学习、线上试用。[公告](https://help.aliyun.com/zh/sms/product-overview/about-sms-signature-application-rule-change-notice)
  - 2026-04-27 起停止：已上线 App，以及一切基于 ICP 备案信息申请的签名。[公告](https://help.aliyun.com/zh/sms/product-overview/domestic-sms-signatures-no-longer-support-launched-app-as-a-source)（已复核）
  - 现在只剩两种：企事业单位名（营业执照全称或规范简称）、已注册商标名。[签名规范](https://help.aliyun.com/zh/sms/user-guide/signature-specifications-1)
- **个人账号的其他限制**：只支持验证码和通知，不支持推广短信、多媒体短信、国际/港澳台短信；每自然日只能申请 1 个签名；不能通过 API 提交资质；不能调整流控。[使用须知](https://help.aliyun.com/zh/sms/user-guide/usage-notes)
- **资质材料**：企业证件、法定代表人姓名和证件、经办人姓名/证件照/手机号；他用另需委托授权书。经办人须满足「一人一企」。[资质说明](https://help.aliyun.com/zh/sms/user-guide/qualification-application-description)
- **审核时长**：资质约 2 个工作日，签名约 2 小时，运营商实名报备平均 5–7 个工作日、部分 7–10 个工作日。
- **实名制时间线**：2025-04 签名实名制报备与存量核查；2025-05 至 07 三大运营商先后新增模板报备管控。[公告目录](https://help.aliyun.com/zh/sms/product-overview/announcements-and-updates-1/)（两条 2025-04 公告的正文未抓取，只取了标题和日期）
- **模板**：验证码模板须含「验证码/注册码/校验码/动态码」之一，变量 4–6 位，审核约 2 小时。[模板规范](https://help.aliyun.com/zh/sms/user-guide/verification-code-template-specifications)
- **流控**：验证码同签名同号码 1 条/分钟、5 条/小时、10 条/天；同号码全平台 40 条/天。[发送规则](https://help.aliyun.com/zh/sms/user-guide/message-rules)
- **价格**：验证码/通知按量 0.045 元/条起，阶梯降到 0.038；套餐包 1000 条 50 元，有效期 2 年；回执失败不计费。[计费](https://help.aliyun.com/zh/sms/product-overview/billing-of-messages-sent-to-chinese-mainland)
- **配置参数**：AccessKeyId、AccessKeySecret、endpoint `dysmsapi.aliyuncs.com`、SignName、TemplateCode。[SendSms](https://help.aliyun.com/zh/sms/developer-reference/api-dysmsapi-2017-05-25-sendsms)

### 1.3 阿里云号码认证服务「短信认证」（个人可用）

- **准入**：官方指南标题即「个人开发者免资质快速上手」。前提只有三条：个人实名认证、在号码认证控制台开通短信认证、有 AccessKey。不需要资质、签名或模板申请。[指南](https://help.aliyun.com/zh/pnvs/use-cases/sms-verify-for-individual-developers)（已复核）
- **限制**：
  - 只能用系统赠送的签名和模板，两者必须配套，不能新增或修改。原文：「因运营商政策管控，不支持自定义创建签名和模板。」
  - 赠送模板覆盖 5 个场景：登录/注册、修改绑定手机、重置密码、绑定新手机、验证绑定手机。[用户指南](https://help.aliyun.com/zh/pnvs/user-guide/sms-authentication-service)
  - 只支持中国大陆号码（+86）。
  - 赠送签名和模板只能用于 `SendSmsVerifyCode`，不能用于短信服务的 `SendSms`。
- **API**：`SendSmsVerifyCode` 和 `CheckSmsVerifyCode`，endpoint `dypnsapi.aliyuncs.com`。验证码可以由阿里云生成并核验；如果自带验证码，`CheckSmsVerifyCode` 不能核验，要自己比对。可选参数含 CodeLength、ValidTime（默认 300 秒）、Interval（默认 60 秒）。[API](https://help.aliyun.com/zh/pnvs/developer-reference/api-dypnsapi-2017-05-25-sendsmsverifycode)
- **价格**：按回执成功计费，核验免费。每月 1000 次以内 0.06 元/次，阶梯降到 0.04；无免费额度，不能用短信服务套餐包抵扣。[价格](https://help.aliyun.com/zh/pnvs/product-overview/product-pricing)
- **未验证**：同号码的小时级和天级流控数值；赠送签名的完整列表（文档示例为「恒创联众」，实际可选项要在控制台看）。

### 1.4 腾讯云短信

- **个人自用资质已停**：2025-09-18 起不再支持新增个人认证自用资质，存量不可修改、不可关联新签名。[公告 2025-09-12](https://cloud.tencent.com/announce/detail/2127)
- **个人账号**：支持验证码、通知、国际/港澳台，不支持国内营销短信；个人签名无法做运营商实名报备，须以企业证件加授权委托书申请他用资质，或升级企业认证；签名和模板只能在控制台管理。[个人与企业差异（2026-08-31 更新）](https://cloud.tencent.com/document/product/382/13444)
- **签名类型**：2025-04-09 停止网站、公众号、小程序类签名（[公告](https://cloud.tencent.com/document/product/382/116397)）；2026-04-20 版审核标准只列公司、政府/机构、商标（[审核标准](https://cloud.tencent.com/document/product/382/39022)）。App 类是否已取消未验证。
- **频率限制**：默认同号码同内容 30 秒 1 条、同号码每自然日 2 条（可调）；个人认证可设置的上限为 1 条/30 秒、5 条/小时、10 条/天。[FAQ](https://cloud.tencent.com/document/faq/382/13303)
- **价格**：只有预付费套餐包。1 万条 470 元（0.047 元/条），最高档 0.041 元/条，有效期 2 年；个人和企业同价。个人首次开通赠 100 条。[计费](https://cloud.tencent.com/document/product/382/36132)
- **配置参数**：SecretId、SecretKey、Region、SmsSdkAppId（短信应用 ID，不是账号 AppId）、SignName、TemplateId。[SendSms](https://cloud.tencent.com/document/product/382/55981)

### 1.5 其他

- 华为云消息&短信：个人用户和个体工商户都不能使用，须企业实名认证。[FAQ（2024-08-05）](https://support.huaweicloud.com/msgsms_faq/sms_faq_0012.html)
- 容联云等：未调研。

## 2. 微信小程序登录

### 2.1 结论

个人主体小程序可以用 `wx.login` + `code2Session` 登录，但只能拿到 openid：拿不到 unionid，也拿不到手机号。

### 2.2 登录接口

- `GET https://api.weixin.qq.com/sns/jscode2session`，参数 `appid`、`secret`、`js_code`；返回 `openid`、`session_key`，小程序已绑定开放平台账号时才返回 `unionid`。[code2Session](https://developers.weixin.qq.com/miniprogram/dev/server/API/user-login/api_code2session.html)
- 接口文档没有列主体或认证限制。个人可用是由「文档无限制」得出的推断，没有正面声明。
- 配置参数：AppID、AppSecret。

### 2.3 手机号组件：个人不可用

- 手机号快速验证组件：「目前该接口针对非个人主体，且完成了认证的小程序开放」；0.03 元/次，每个小程序 1000 次体验额度，2023-08-28 起收费。[getPhoneNumber](https://developers.weixin.qq.com/miniprogram/dev/framework/open-ability/getPhoneNumber.html)
- 手机号实时验证组件：同样限非个人且已认证，0.04 元/次。[实时验证](https://developers.weixin.qq.com/miniprogram/dev/framework/open-ability/getRealtimePhoneNumber.html)

### 2.4 备案、认证、类目

- **备案**：个人可以备案小程序，上限 5 个，不得选经营性或企业性质的内容。[备案指引](https://developers.weixin.qq.com/miniprogram/product/record/record_guidelines.html)
- **微信认证**：个人类型小程序认证前可以发布上架，认证后才有「被搜索、分享」能力；企业和个体工商户须认证后才能发布。认证有效期 365 天，需年审。[认证说明](https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/2.0/product/weapp_wxverify.html)
- **类目**：个人主体可选的一级类目为物流、教育、交通、生活、餐饮、旅游、工具、商业服务、体育。「社交」（社区、论坛、问答、交友、直播）只在非个人表里，且都要额外资质。[服务类目](https://developers.weixin.qq.com/miniprogram/product/material/)
- 个人做不了带 UGC 或社区性质的小程序；纯登录或工具型可以挂在「工具」下（推断）。
- **未验证**：个人小程序认证费（社区流传 30 元/次，官方页面没有金额）。

### 2.5 小程序码（登录桥用）

- `POST https://api.weixin.qq.com/wxa/getwxacodeunlimit`，`scene` 最多 32 个可见字符，数量不限，5000 次/分钟。[getUnlimitedQRCode](https://developers.weixin.qq.com/miniprogram/dev/server/API/qrcode-link/qr-code/api_getunlimitedqrcode.html)
- 文档没有列主体限制，推断个人小程序可用。没有找到官方文档认可或禁止用小程序给网站或 App 做登录桥。
- 未验证：未认证的个人小程序，其小程序码扫码进入是否受「被搜索、分享」限制影响。

## 3. 微信开放平台：移动应用微信登录与 UnionID

### 3.1 结论

个人 Operator 已经无法新接入 App 微信登录，也无法取得 unionid。

### 3.2 依据

- **个人不能新建应用**：腾讯客服《移动应用创建流程》写明「自2026年9月14日起，不再支持个人主体类型的账号创建新的应用」。[原文](https://kf.qq.com/faq/170824EnUNRJ170824bYnEJr.html)（已复核）没有找到对应公告，存量个人应用如何处理没有说明。
- **个人不能绑定小程序**：「未认证（个人类型）账号不支持绑定小程序及小程序测试号」，公众号同理。[绑定规则调整](https://kf.qq.com/faq/180104uY7r2a180104ziqumu.html)（已复核）unionid 的前提就是绑定到同一开放平台账号，所以个人小程序拿不到 unionid。
- **绑定上限**（已认证的组织账号）：移动应用 50 个；小程序同主体 50 个、异主体 5 个；网站应用每账号 10 个。[绑定说明](https://developers.weixin.qq.com/doc/oplatform/developers/product/open/bind.html)
- **接入前提**：拥有已审核通过的移动应用，并「申请微信登录且通过审核」。[开发指南](https://developers.weixin.qq.com/doc/oplatform/Mobile_App/WeChat_Login/Development_Guide.html)
- **创建移动应用要填**：应用官网（含用户协议和备案信息，主体须与开放平台认证主体一致）、已上架时的 App 备案号、iOS 的 Bundle ID 和 Universal Links、Android 的包名和应用签名；审核 1–7 个工作日。[审核说明](https://developers.weixin.qq.com/doc/oplatform/Mobile_App/operation.html)
- **配置参数**：AppID、AppSecret。服务端接口为 `sns/oauth2/access_token`、`sns/userinfo`。

### 3.3 未验证

- 开发者资质认证的费用（社区流传 300 元/年）及其是否为微信登录权限的前置条件。
- 2026-09-14 新规是否同样适用于网站应用（原文只出现在移动应用页，措辞是「新的应用」）。

## 4. 公众号网页授权与网站应用扫码登录

- **公众号网页授权**：只对已认证的服务号开放。「个人主体类型公众号/服务号不支持申请微信认证」，所以个人用不了。[网页授权](https://developers.weixin.qq.com/doc/service/guide/h5/auth.html)、[认证限制](https://kf.qq.com/faq/161220eya2Ev161220B32E7r.html)
  - 配置参数：AppID、AppSecret，并在公众平台登记「网页授权域名」（填域名，子域名不通用）。
  - `snsapi_base` 静默、只给 openid；`snsapi_userinfo` 需用户同意。
  - 未验证：登记网页授权域名时的 `MP_verify_*.txt` 校验文件和 ICP 备案要求，当前文档页没有提到。
- **网站应用扫码登录**：需要一个已审核通过的网站应用并申请微信登录；审核要交官网和《网站信息登记表》（含备案号）。[网站应用登录](https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html)
  - 配置参数：AppID、AppSecret、授权回调域（每月最多改 5 次）。
  - 个人能否新建：未验证，见 3.3。按「新的应用」的字面理解，个人大概率也建不了（推断）。

## 5. 运营商本机号码一键登录 / 号码认证

### 5.1 结论

一键登录并非全行业「仅限企业」：阿里云和极光的文档都写明个人实名认证可以开通。腾讯云号码认证已不接受新客户。没有找到任何一手来源规定一键登录只能由企业使用；厂商只写「因运营商要求」需要实名。

### 5.2 各厂商

| 厂商 | 主体要求 | 需登记的应用信息 | 价格 |
|---|---|---|---|
| 阿里云号码认证 | 「完成企业实名认证或个人实名认证」（已复核） | Android：包名、包签名；iOS：Bundle ID；H5：页面地址、源地址。方案创建后不可修改 | 后付费 0.05 元/次起，阶梯降到 0.026；套餐包 1 万次 440 元 |
| 腾讯云号码认证 | 「仅支持已开通的存量白名单，其余场景不支持新接入」 | 不适用 | 0.04 元/次起 |
| 极光认证 | 「需要完成个人实名认证或企业资质认证」 | 包名、应用签名、Bundle ID；Web 填集成页面地址和请求来源；需提交审核 | 未验证 |
| DCloud uni一键登录 | 「需要完成实名认证」，未区分个人/企业 | DCloud AppId、包名、签名；审核 1–3 个工作日 | 0.02 元/次，预付费 |
| 创蓝闪验 | 文档只提「认证公司资质」 | Android、iOS、H5 分别申请 appid | 未验证 |
| 运营商直连 | 未验证 | 走商务或客户经理 | 未验证 |

来源：阿里云 [前提条件](https://help.aliyun.com/zh/pnvs/use-cases/best-practices-for-user-authentication)、[方案管理](https://help.aliyun.com/zh/pnvs/user-guide/number-certification-program-management)、[价格](https://help.aliyun.com/zh/pnvs/product-overview/product-pricing)；腾讯云 [购买指南（2026-04-27）](https://cloud.tencent.com/document/product/1415/53475)、[快速入门（2026-05-11）](https://cloud.tencent.com/document/product/1415/53463)；极光 [开通指南](https://docs.jiguang.cn/jverification/guideline/provisioning)；DCloud [univerify](https://uniapp.dcloud.net.cn/univerify.html)、[开通](https://doc.dcloud.net.cn/uniCloud/uni-login/service)；创蓝 [文档](https://doc.chuanglan.com/document/6CXESBI5BTWCITTL)。

### 5.3 阿里云的配置与计费细节

- **服务端 API**：App 用 `GetMobile`（一键登录取号）和 `VerifyMobile`（本机号码校验）；H5 用 `GetPhoneWithToken` 和 `VerifyPhoneWithToken`。
- **配置参数**：AccessKey ID/Secret、方案 Code。客户端 SDK 秘钥随方案生成（未验证其确切名称）。
- **计费口径**：一键登录在成功返回号码时计费；本机号码校验无论结果是否一致都计费。
- **H5**：支持，但用户要输入手机号中间 4 位；中国移动方向要在方案创建后的第 2 个工作日才能调用。[H5 接入](https://help.aliyun.com/zh/pnvs/getting-started/h5-page-integration)
- **上架和 App 备案**：已抓取的阿里云文档没有把应用上架或 App 备案号列为创建方案的条件。

### 5.4 未验证

- 阿里云个人认证账号在控制台或运营商报备环节是否有文档未写的隐性限制。文档没写不等于没有，建议项目作者用自己的个人账号实测一次。
- 三大运营商开放平台是否接受个人开发者、资质清单和直连价格（官方站点抓取失败）。
- 极光、闪验、友盟、个推、MobTech 的价格。

## 6. Sign in with Apple

- **主体**：Apple Developer Program 个人和组织都能注册，年费 99 美元；组织需 D-U-N-S。Sign in with Apple 对两者都开放，只是配额不同：个人最多登记 10 个网站 URL，组织 100 个。[注册](https://developer.apple.com/programs/enroll/)、[环境配置](https://developer.apple.com/documentation/signinwithapple/configuring-your-environment-for-sign-in-with-apple)
- **配置参数**：
  - Team ID
  - Bundle ID（原生流程的 `aud`）
  - Services ID（Web 流程的 `client_id`，须关联一个已启用该能力的 primary App ID，并登记域名和 return URL）
  - 私钥 `.p8` 和 Key ID
- **client_secret**：服务端用私钥签发的 ES256 JWT，有效期不超过 6 个月，需要定期自动重签。[创建 client secret](https://developer.apple.com/documentation/accountorganizationaldatasharing/creating-a-client-secret)
- **回调约束**：`redirect_uri` 必须是域名，不能是 IP 或 `localhost`；请求了 scope 时 `response_mode` 必须为 `form_post`，即 Apple 用 POST 回调。[Web 接入](https://developer.apple.com/documentation/signinwithapple/incorporating-sign-in-with-apple-into-other-platforms)
- **其他义务**：
  - 隐私邮箱中继要求登记外发邮件域名并通过 SPF 或 DKIM。
  - 可登记一个 server-to-server 通知地址，接收 `consent-revoked`、`account-deleted` 等事件。[处理变更](https://developer.apple.com/documentation/signinwithapple/processing-changes-for-sign-in-with-apple-accounts)
  - App 支持注册就必须支持删除账号；删除时应调用 revoke 接口，所以服务端要保存 refresh token。[账号删除](https://developer.apple.com/support/offering-account-deletion-in-your-app/)
- **Guideline 4.8**（[原文](https://developer.apple.com/app-store/review/guidelines/)，已对照原始 HTML）：
  - 触发条件：App 用第三方或社交登录建立或认证用户主账号。条文示例里点名了 「WeChat Login」。
  - 义务：必须同时提供一个「等效的」登录服务，满足三条隐私属性（只收集姓名和邮箱、可隐藏邮箱、未经同意不收集广告用途的交互数据）。条文没有点名 Sign in with Apple，但它是现成满足条件的选项。
  - 豁免：只用自有账号体系；教育/企业类 App 用既有账号；政府或行业背书的公民身份系统；特定第三方服务的客户端。
  - 推断：支付宝、抖音、QQ 登录同样属于「第三方或社交登录」而触发；只提供手机号验证码等自有登录则豁免。
- **未验证**：return URL 是否明文要求 HTTPS；免费 Apple 账号能否使用；中国大陆的人民币定价。

## 7. 支付宝、抖音、QQ、邮箱

### 7.1 支付宝登录

- 网站支付宝登录「对支付宝企业账号和支付宝个人账号（含个体工商户）均开放」；个人账号不能申请扩展用户信息（如手机号）。[产品介绍](https://opendocs.alipay.com/open/009ys3)、[接入准备](https://opendocs.alipay.com/open/009ys5)
- 应用需提交上线审核并签约开通后才能在生产环境使用。
- 配置参数：APPID、授权回调地址；应用私钥和支付宝公钥（或证书模式）未取到正文，属未验证。
- 未验证：App 支付宝登录是否对个人开放；个人能否创建支付宝小程序。

### 7.2 抖音登录

- 个人身份只能创建小程序、小游戏、小玩法；移动应用和网站应用仅企业身份可建。所以 App 和网站的抖音授权登录个人做不了，抖音小程序的 `tt.login` 个人可用。[入驻说明](https://developer.open-douyin.com/docs/resource/zh-CN/developer/join/join-into-developer-platform/)
- 配置参数：`client_key`、`client_secret`、授权回调 URL（必须 https）。[网站应用授权](https://developer.open-douyin.com/docs/resource/zh-CN/dop/develop/sdk/web-app/web/permission)

### 7.3 QQ 登录

- QQ互联 WIKI 仍写公司或个人均可提交资料成为开发者。[成为开发者](https://wiki.connect.qq.com/成为开发者)
- 网站应用要求网站地址和回调地址已完成 ICP 备案，且填写的备案信息与工信部一致。[审核规范](https://wiki.connect.qq.com/网站审核规范)
- 配置参数：APP ID、APP Key、`redirect_uri`。unionid 需在应用管理里单独申请并过审。[unionid](https://wiki.connect.qq.com/unionid介绍)
- 未验证：个人当前能否实际通过审核、是否需要手持证件照。connect.qq.com 现为需登录的页面，注册表单看不到。

### 7.4 邮箱

- 阿里云邮件推送：「阿里云实名认证用户才可以购买和开通」，不区分个人和企业。[开通说明](https://help.aliyun.com/document_detail/29422.html)
- 需要一个发信域名并配置 SPF、DKIM、DMARC、MX 四项 DNS 记录，再创建发信地址并设置 SMTP 密码。[域名配置](https://help.aliyun.com/zh/direct-mail/user-guide/how-to-configure-sending-domain-names)
- SMTP：`smtpdm.aliyun.com`，端口 25、80、465（SSL）。[SMTP 地址](https://help.aliyun.com/zh/direct-mail/smtp-endpoints)
- 免费共 2000 封、每天最多 200 封；按量 2 元/千封；初始信誉等级日额度 2000 封。[计费](https://help.aliyun.com/zh/direct-mail/billing-methods)、[限制](https://help.aliyun.com/zh/direct-mail/product-overview/limits)
- 通用 SMTP 没有主体门槛，填 host、port、user、password、from 即可（推断，协议层面无资质概念）。
- 未验证：发信域名是否要求 ICP 备案。

## 8. 通用前置条件

### 8.1 ICP 备案

- 网站托管在中国内地服务器时必须先备案才能对外服务；未备案域名解析到内地服务器会被阻断，HTTPS 同样拦截。[阿里云](https://help.aliyun.com/zh/icp-filing/basic-icp-service/product-overview/limits)、[腾讯云（2025-05-23）](https://cloud.tencent.com/document/product/243/18907)
- 个人可以备案，但有内容和名称限制：
  - 内容涉及行业或企业的，备案性质不能为个人。
  - 名称不得含「博客、论坛、平台、社区、交流」及商业类词汇。[阿里云填写说明](https://help.aliyun.com/zh/icp-filing/basic-icp-service/user-guide/fill-in-website-information)、[腾讯云（2024-05-24）](https://cloud.tencent.com/document/product/243/11740)
- 对 Polaris 的含义：个人 Operator 的认证域名和站点名称要避开「平台/社区」等字样（推断）。

### 8.2 App 备案

- 依据：工信部信管〔2023〕105 号。「未履行备案手续的，不得从事APP互联网信息服务」；接入服务商和分发平台不得为未备案 App 提供接入和分发。存量 App 备案期为 2023-09 至 2024-03。[通知原文](https://www.gov.cn/zhengce/zhengceku/202308/content_6897341.htm)
- 个人和单位都可以备案。需填包名、公钥、证书 MD5 指纹（Android），或 Bundle ID、公钥、SHA-1（iOS），以及后台域名。[腾讯云 FAQ](https://cloud.tencent.com/document/product/243/97691)、[阿里云个人 App](https://help.aliyun.com/zh/icp-filing/basic-icp-service/getting-started/quick-sta-rt-for-icp-filing-for-personal-app)
- 在服务所在的网络接入服务商处备案；小程序在微信等小程序平台备案。

### 8.3 哪个渠道需要什么

| 前置条件 | 需要它的渠道 |
|---|---|
| 认证域名已 ICP 备案 + HTTPS | 小程序服务器域名（[网络](https://developers.weixin.qq.com/miniprogram/dev/framework/ability/network.html)）；QQ 登录的网站和回调地址；微信网站应用审核；内地部署的一切 Web 回调 |
| 小程序备案 | 小程序登录、小程序码登录桥 |
| App 备案 | App 上架；微信移动应用创建（已上架时必填备案号） |
| 包名、签名、Bundle ID 登记 | 微信移动应用、一键登录、App 备案 |
| iOS Universal Links | 微信移动应用 |
| 业务域名校验 | 仅小程序 web-view；「暂不开放给个人类型账号」（[业务域名](https://developers.weixin.qq.com/miniprogram/dev/framework/ability/domain.html)） |
| 服务器 IP 白名单 | 公众号和小程序取 access_token 都列有错误码 40164「IP 不在白名单中」；小程序是强制还是可选未验证 |
| 发信域名 DNS 记录 | 邮件（SPF、DKIM、DMARC、MX）；Apple 隐私邮箱中继（SPF 或 DKIM） |
| 公安联网备案 | 站点或 App 主办者的义务（开通 30 日内）；没有任何渠道把它列为开通条件 |

## 9. 汇总矩阵

「个人」指个人实名认证、有 ICP 备案域名、无企业主体的 Operator。

| 渠道 | 个人可用？ | Operator 填写的参数 | 限制与成本 |
|---|---|---|---|
| 阿里云短信认证（号码认证服务） | 可以 | AccessKeyId、AccessKeySecret、赠送 SignName、赠送 TemplateCode | 不能自定义签名和模板；仅 +86；0.06 元/次起 |
| 阿里云短信服务 | 不可以（除非借企业主体做「他用」资质） | AccessKeyId、AccessKeySecret、SignName、TemplateCode | 签名仅企事业单位名或商标；1/分钟、5/小时、10/天；0.045 元/条起 |
| 腾讯云短信 | 不可以（同上） | SecretId、SecretKey、Region、SmsSdkAppId、SignName、TemplateId | 签名仅公司、机构、商标；仅预付费，0.047 元/条起 |
| 华为云短信 | 不可以 | — | 仅企业 |
| 微信小程序登录 | 可以（仅 openid） | AppID、AppSecret | 无 unionid；需小程序备案；类目受限 |
| 小程序手机号组件 | 不可以 | 同上 | 非个人且已认证；0.03 元/次 |
| 微信 App 登录 | 不可以（2026-09-14 起不能新建应用） | AppID、AppSecret、Universal Link | 需移动应用审核和微信登录权限审核 |
| UnionID | 不可以 | 开放平台绑定关系 | 个人类型账号不能绑定小程序和公众号 |
| 公众号网页授权 | 不可以 | AppID、AppSecret、网页授权域名 | 仅已认证服务号 |
| 微信网站扫码登录 | 大概率不可以（未验证） | AppID、AppSecret、授权回调域 | 需网站应用审核 |
| 阿里云一键登录 | 文档写明可以 | AccessKeyId、AccessKeySecret、方案 Code；控制台登记包名、签名、Bundle ID | 0.05 元/次起；隐性限制未验证 |
| 极光认证 | 文档写明可以 | AppKey、Master Secret、RSA 私钥（参数名未验证） | 价格未验证 |
| 腾讯云号码认证 | 不可以 | — | 仅存量白名单客户 |
| Sign in with Apple | 可以 | Team ID、Bundle ID、Services ID、Key ID、`.p8` 私钥 | 99 美元/年；个人最多 10 个网站 URL |
| 支付宝网站登录 | 可以 | APPID、回调地址；应用私钥和支付宝公钥（密钥参数未验证） | 个人拿不到手机号等扩展信息 |
| 抖音 App/网站登录 | 不可以 | client_key、client_secret、回调 URL | 仅企业身份可建应用 |
| 抖音小程序登录 | 可以 | AppID、AppSecret（参数名未验证） | — |
| QQ 登录 | 文档写可以，实际未验证 | APP ID、APP Key、redirect_uri | 网站和回调须已 ICP 备案 |
| 邮箱（阿里云邮件推送或任意 SMTP） | 可以 | host、port、user、password、from；发信域名 DNS | 阿里云邮件推送：免费共 2000 封、每天最多 200 封，之后 2 元/千封 |

## 10. 个人 Operator 今天能开通的渠道

**能开通**

- 短信验证码：仅阿里云号码认证的「短信认证」，短信显示阿里云的赠送签名。
- 微信小程序登录：只有 openid。
- 小程序码扫码登录桥：给网站和 App 用（推断可用，见 2.5）。
- 运营商一键登录：阿里云或极光（文档写明个人实名可开通，建议实测确认）。
- Sign in with Apple。
- 支付宝网站登录、抖音小程序登录、邮箱验证码。
- QQ 登录：文档上可以，实际审核情况未验证。

**仅企业**

- 自有品牌签名的短信（阿里云短信、腾讯云短信、华为云）。
- 微信手机号组件、App 微信登录、UnionID、公众号网页授权、微信网站扫码登录。
- 抖音 App 和网站登录。

## 11. 对认证服务器设计的含义（均为推断）

### 11.1 身份模型

- 微信身份不能假设有 unionid。个人 Operator 只有 `(appid, openid)`；数据模型应以它为主键，unionid 为可选的合并线索。
- 手机号不能假设来自微信。个人 Operator 要拿手机号，只能走短信认证或一键登录。

### 11.2 渠道配置结构

每个渠道一条配置记录，通用字段加渠道专属字段：

- **通用**：`enabled`、显示名、凭据（加密存储）、适用的客户端（哪个 App 或小程序）。
- **短信**：`provider`（`aliyun_pnvs_sms`、`aliyun_sms`、`tencent_sms`）、凭据、`sign_name`、按场景的 `template_code`（登录、绑定、重置密码等，因为阿里云赠送模板按场景区分）、region/endpoint、腾讯的 `sms_sdk_app_id`、本地频率限制。
  - 验证码建议由认证服务器自己生成和比对，各 provider 行为才一致；阿里云的 `CheckSmsVerifyCode` 不必依赖。
- **微信小程序**：`app_id`、`app_secret`。需要集中缓存 access_token（小程序码接口要用）。
- **微信开放平台应用 / 公众号**：`app_id`、`app_secret`、类型（移动、网站、服务号）、回调域。
- **一键登录**：`provider`、凭据、每个平台一个方案 Code（Android、iOS、H5 各自独立，且创建后不可改）。
- **Apple**：`team_id`、`key_id`、私钥、`bundle_ids`（可多个）、`services_id`。服务器要自动重签 client_secret，并保存 refresh token 供删除账号时撤销。
- **支付宝 / 抖音 / QQ**：标准 OAuth 三件套（client id、secret 或密钥对、回调地址）；支付宝是 RSA 密钥对而不是共享密钥。
- **邮箱**：通用 SMTP 字段即可，不需要为阿里云邮件推送单独建模。

### 11.3 认证服务器需要对外提供的端点和文件

- OAuth 回调：微信网页授权、微信扫码、支付宝、抖音、QQ（回调域要在各平台登记；QQ 要求该域名已备案）。
- Apple 回调必须能接收 `form_post` 的 POST 请求；另需一个 server-to-server 通知端点。
- 域名校验文件：建议提供一个通用的「在根路径托管 Operator 上传的校验文件」功能，覆盖微信网页授权域名和业务域名校验（两者的现行要求未验证，且都只对企业开放）。
- iOS Universal Links 的 `apple-app-site-association`：微信移动应用需要，可以由认证域名托管，也可以留给 App 自己的域名。
- 认证域名本身要 HTTPS 且已 ICP 备案，才能作为小程序服务器域名。

### 11.4 个人 Operator 的替代方案

| 企业专属能力 | 个人可用的替代 |
|---|---|
| 自有签名短信 | 阿里云短信认证（赠送签名）；邮箱验证码 |
| 微信手机号 | 短信认证；一键登录（阿里云或极光） |
| App 微信登录 | 小程序码登录桥：App 展示小程序码或拉起小程序，小程序内 `wx.login` 后回传 |
| 微信网站扫码登录 | 同上，网页展示小程序码 |
| UnionID 跨应用打通 | 以单个小程序的 openid 为锚点，所有端都通过这个小程序登录 |
| 无外部依赖的兜底 | 邮箱验证码、TOTP、passkey（后者见免密登录调研） |

### 11.5 管理后台应提示的事项

- iOS App 一旦启用微信等第三方登录，就必须同时启用一个满足 Guideline 4.8 的登录方式（实际上就是 Sign in with Apple）。
- 每个渠道旁标注主体要求和本文日期，因为规则变动频繁。
- 短信认证的短信不显示 Operator 的品牌，用户可能会困惑；登录页应提示验证码短信的签名。

## 12. 最值得补做的验证

1. 用个人实名的阿里云账号实际开通一次一键登录，确认运营商报备环节不会拒绝个人。
2. 用个人主体登录微信开放平台，确认网站应用是否也已不能新建。
3. 确认未认证的个人小程序，其小程序码能否被任意用户扫码打开。
4. 确认 QQ互联当前是否仍受理个人开发者。

