[中文](origin-tls_zh.md) | [English](origin-tls_en.md)

# 回源 TLS：CloudFront → 内部 ALB 全程 HTTPS

本文说明私有源站架构中的一项可选安全增强：让 CloudFront 到内部 ALB 这一跳也走 HTTPS。整体架构和其他控制点见 [安全设计 · 私有源站](security_zh.md#私有源站cloudfront--vpc-origin--内部-alb)。

## 它解决什么问题

```
客户端 ──HTTPS──▶ CloudFront ──(这一跳)──▶ 内部 ALB ──Lambda API──▶ OAuth / Middleware Lambda
         *.cloudfront.net 默认证书     VPC origin 私有链路
```

VPC origin 已经保证这一跳不经过公网：CloudFront 只能经由你 VPC 内的 VPC origin ENI 连到内部 ALB，ALB 没有公网地址。但如果不开回源 TLS，这一跳在应用层是**明文 HTTP**，其中包括：

- `/mcp` 请求头里的 Bearer MCP Token，以及 MCP 工具调用返回的飞书业务数据（消息、文档、日历等）
- OAuth 的授权码、PKCE `code_verifier`、`/token` 请求体里的 `client_secret`、`/register`（DCR）的请求和响应

开启后，这些数据在 CloudFront 与 ALB 之间都由 TLS 加密并做完整性保护，满足"传输全程加密"这类合规要求。

| | 不设置（默认） | 设置 `ORIGIN_DOMAIN_NAME`（推荐） |
|---|---|---|
| CloudFront → ALB | HTTP :80，VPC origin `http-only` | HTTPS :443，VPC origin `https-only`，Origin SSL 协议仅 TLSv1.2 |
| ALB 监听器 | HTTP :80 | HTTPS :443，ACM 证书，安全策略 `ELBSecurityPolicy-TLS13-1-2-2021-06` |
| ALB 安全组 | 仅放行 CloudFront origin-facing 前缀列表的 80 端口 | 仅放行 CloudFront origin-facing 前缀列表的 443 端口 |
| 额外依赖 | 无 | 本账号内一个 Route 53 **公有**托管区 |
| 客户端入口 | `*.cloudfront.net`（不变） | `*.cloudfront.net`（不变） |

## 为什么必须有一个自有域名

CloudFront 用 HTTPS 回源时会校验源站证书：证书必须由受信 CA 签发（不接受自签证书），且必须匹配回源时使用的域名（[AWS 文档](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-cloudfront-to-custom-origin.html)）。内部 ALB 的 DNS 名形如 `internal-xxx.<region>.elb.amazonaws.com`，任何人都无法为它申请证书，所以需要一个**专用于回源**的主机名，由 ACM 签发证书。

这个主机名**不是客户端访问域名**：客户端、飞书重定向 URL、Quick Connector 继续使用 `*.cloudfront.net`。CloudFront 的源请求策略是 `ALL_VIEWER_EXCEPT_HOST_HEADER`，不转发客户端 Host，而是以回源主机名作为 SNI 和 Host 连接 ALB，正好与证书匹配。

## 前提条件

- 本账号内有一个 Route 53 **公有**托管区，并且已经完成 NS 委派、能被公网解析（ACM 的 DNS 验证依赖它）。
- 回源主机名位于该托管区之下，只能使用小写字母、数字、`.` 和 `-`，例如 `lark-mcp-origin.example.com`。
- 如果该域名配置了 CAA 记录，需要允许 Amazon 签发（`amazon.com` / `amazontrust.com` 等）。
- 多应用部署时，每个 app 有独立的 ALB 和 `deploy-config`，**每个 app 要用不同的回源主机名**。

## 配置

通过环境变量或 `.local/deploy-config`（多应用为对应 app 目录下的 `deploy-config`）设置，然后重新部署：

```bash
ORIGIN_DOMAIN_NAME=lark-mcp-origin.example.com
ORIGIN_HOSTED_ZONE_ID=<HOSTED_ZONE_ID>     # 可带或不带 /hostedzone/ 前缀
```

```bash
./scripts/deploy.sh --yes
```

`deploy.sh` 在调用 CDK 之前会先校验：两个变量必须同时设置，托管区存在且是公有区，主机名位于该区之下。任何一项不满足都会报错退出，不会部署出一个半配置的状态。校验通过后会打印 `CloudFront → 内部 ALB：HTTPS（源站域名 …）`；两个变量都未设置时打印 HTTP 模式的提示。两个值会写回 `deploy-config`，之后重新部署会沿用。

CDK 会创建或修改：

1. ACM 公有证书（DNS 验证，验证记录自动写入该托管区）
2. ALB 的 HTTPS :443 监听器，挂载该证书，默认动作是固定 404，只把声明过的路径转发给 Lambda
3. 该主机名指向内部 ALB 的 Route 53 别名 A 记录（解析结果是 ALB 的私网 IP）
4. VPC origin 的协议改为 `https-only`，并限制为 TLSv1.2；分配的源站域名设为回源主机名
5. ALB 安全组的入站规则改为前缀列表的 443 端口

## 验证

用 CloudFront 域名访问，应当正常：

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://<CloudFront 域名>/.well-known/oauth-authorization-server   # 200
curl -s -o /dev/null -w '%{http_code}\n' https://<CloudFront 域名>/not-a-route                             # 404（ALB 默认动作）
```

回源主机名在公网能解析，但只解析出私网 IP，从公网直连应当超时：

```bash
dig +short <ORIGIN_DOMAIN_NAME>                                    # 只有 10.x 等私网地址
curl -s -m 5 https://<ORIGIN_DOMAIN_NAME>/ ; echo "exit=$?"        # exit=28（超时）
```

确认 ALB 监听器、证书和 VPC origin 的配置：

```bash
aws elbv2 describe-listeners --load-balancer-arn <ALB_ARN> \
  --query 'Listeners[].{Port:Port,Proto:Protocol,Policy:SslPolicy}'
aws acm describe-certificate --certificate-arn <CERT_ARN> \
  --query 'Certificate.{Status:Status,Renewal:RenewalEligibility,NotAfter:NotAfter}'
aws cloudfront get-vpc-origin --id <VPC_ORIGIN_ID> \
  --query 'VpcOrigin.VpcOriginEndpointConfig.{Proto:OriginProtocolPolicy,Ssl:OriginSslProtocols.Items}'
```

预期结果：只有一个 `443 / HTTPS` 监听器；证书 `ISSUED`、`ELIGIBLE`；VPC origin 为 `https-only` + `["TLSv1.2"]`。最后跑一遍 `./scripts/test-e2e.sh`。

## 证书续期

ACM 公有证书会在到期前自动续期，前提是：证书仍被 ALB 使用，并且托管区里的 `_xxxx` 验证 CNAME 记录还在。**不要删除这条验证记录**，也不要把托管区换成私有区。即将到期而续期失败时，ACM 会发出 AWS Health 事件。

## 排障

| 现象 | 常见原因 |
|---|---|
| CloudFront 返回 502，`X-Cache: Error from cloudfront` | 证书与回源主机名不匹配、证书过期或证书链不完整；或者分配的源站域名与证书域名不一致 |
| 部署卡在证书创建 / ACM 一直是 `PENDING_VALIDATION` | 托管区没有完成 NS 委派、公网解析不到验证记录；或者 CAA 记录不允许 Amazon 签发 |
| CloudFront 返回 504 | 安全组端口与监听器不一致（例如仍只放行 80）；或者 VPC origin 尚未部署完成 |
| `deploy.sh` 报 `源站 TLS 配置无效` | 两个变量只设了一个；托管区是私有区；主机名不在该区之下；主机名含大写字母 |
| 飞书授权回调出错 | 与回源 TLS 无关：回调地址由 `deploy.sh` 写入 `CALLBACK_URL`（CloudFront 域名）。未设置时，OAuth Lambda 对 ALB 事件直接拒绝，不会用 ALB 一侧的 Host（回源主机名）拼 redirect_uri |

## 需要知道的副作用和限制

- **主机名会公开**：ACM 公有证书会记入证书透明度（CT）日志，公网 DNS 也能解析出 ALB 的私网 IP。外网无法访问这些 IP，泄露的信息有限，但回源主机名建议用中性名字，不要包含客户、项目或环境名称。
- **成本**：ACM 公有证书不收费；如果为此新建托管区，按 Route 53 托管区定价计费，已有托管区则没有新增费用。
- **客户端一侧的 TLS 策略不受此项影响**：入口仍是 `*.cloudfront.net` 默认证书，CloudFront 对默认证书固定使用 `TLSv1` 安全策略（最低版本不可调，客户端一般会协商 TLS 1.2/1.3）。如需提高最低版本，要给分配配置自定义域名和证书；这会改变客户端 URL，本方案没有这样做。
- **在 HTTP 与 HTTPS 模式之间切换**会替换 ALB 监听器、修改安全组端口和 VPC origin 协议，CloudFront 需要几分钟传播。本仓库只实测过直接部署 HTTPS 模式，切换过程没有实测，建议在维护窗口操作，完成后跑 e2e。
- 回源 TLS 只保护 CloudFront → ALB 这一跳。ALB → Lambda 是 Lambda Invoke API 调用，不是网络连接；Middleware → AgentCore 走 TLS + SigV4。
