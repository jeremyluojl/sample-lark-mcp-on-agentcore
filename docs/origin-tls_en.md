[中文](origin-tls_zh.md) | [English](origin-tls_en.md)

# Origin TLS: HTTPS all the way from CloudFront to the internal ALB

This page covers an optional hardening step in the private-origin architecture: making the CloudFront → internal ALB hop use HTTPS too. For the overall architecture and the other controls, see [Security · Private origin](security_en.md#private-origin-cloudfront--vpc-origin--internal-alb).

## What it protects

```
client ──HTTPS──▶ CloudFront ──(this hop)──▶ internal ALB ──Lambda API──▶ OAuth / Middleware Lambda
        default *.cloudfront.net cert   VPC-origin private path
```

The VPC origin already keeps this hop off the public internet: CloudFront reaches the internal ALB only through the VPC origin ENI in your VPC, and the ALB has no public address. Without origin TLS, though, the hop is **plaintext HTTP** at the application layer, and it carries:

- the Bearer MCP token in `/mcp` request headers, and the Feishu business data returned by MCP tool calls (messages, docs, calendars, …)
- OAuth authorization codes, the PKCE `code_verifier`, the `client_secret` in `/token` request bodies, and `/register` (DCR) requests and responses

With origin TLS on, all of this is encrypted and integrity-protected between CloudFront and the ALB, which satisfies "encrypt in transit end to end" style compliance requirements.

| | Unset (default) | `ORIGIN_DOMAIN_NAME` set (recommended) |
|---|---|---|
| CloudFront → ALB | HTTP :80, VPC origin `http-only` | HTTPS :443, VPC origin `https-only`, origin SSL protocols TLSv1.2 only |
| ALB listener | HTTP :80 | HTTPS :443, ACM certificate, security policy `ELBSecurityPolicy-TLS13-1-2-2021-06` |
| ALB security group | port 80 from the CloudFront origin-facing prefix list only | port 443 from the CloudFront origin-facing prefix list only |
| Extra dependency | none | a Route 53 **public** hosted zone in this account |
| Client entry point | `*.cloudfront.net` (unchanged) | `*.cloudfront.net` (unchanged) |

## Why it needs a domain you own

When CloudFront talks HTTPS to an origin it validates the origin certificate: it must be issued by a trusted CA (self-signed certificates are rejected) and must match the domain name CloudFront uses for the origin ([AWS docs](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-cloudfront-to-custom-origin.html)). The internal ALB's DNS name looks like `internal-xxx.<region>.elb.amazonaws.com`, and nobody can get a certificate for that, so you need a hostname **dedicated to the origin hop** with an ACM-issued certificate.

This hostname is **not a client-facing domain**: clients, the Feishu redirect URL, and the Quick connector keep using `*.cloudfront.net`. The origin request policy is `ALL_VIEWER_EXCEPT_HOST_HEADER`, so CloudFront does not forward the client's Host and instead connects with the origin hostname as SNI and Host, which is exactly what the certificate covers.

## Prerequisites

- A Route 53 **public** hosted zone in this account that is NS-delegated and publicly resolvable (ACM DNS validation depends on it).
- An origin hostname inside that zone, lowercase letters, digits, `.` and `-` only, e.g. `lark-mcp-origin.example.com`.
- If the domain has CAA records, they must allow Amazon to issue (`amazon.com` / `amazontrust.com`, etc.).
- In multi-app deployments each app has its own ALB and `deploy-config`, so **each app needs a different origin hostname**.

## Configuration

Set these via environment variables or `.local/deploy-config` (for a named app, that app's `deploy-config`), then redeploy:

```bash
ORIGIN_DOMAIN_NAME=lark-mcp-origin.example.com
ORIGIN_HOSTED_ZONE_ID=<HOSTED_ZONE_ID>     # with or without the /hostedzone/ prefix
```

```bash
./scripts/deploy.sh --yes
```

Before calling CDK, `deploy.sh` checks that both variables are set together, the hosted zone exists and is public, and the hostname is inside it. If any check fails it exits with an error, so you never get a half-configured deployment. On success it prints `CloudFront -> internal ALB: HTTPS (origin hostname …)`; with both unset it prints the HTTP-mode notice. Both values are saved back to `deploy-config`, so later redeploys keep them.

CDK creates or changes:

1. An ACM public certificate (DNS validation; the validation record is written into the zone automatically)
2. An HTTPS :443 listener on the ALB with that certificate; the default action is a fixed 404, and only the declared paths are forwarded to Lambda
3. A Route 53 alias A record for the hostname pointing at the internal ALB (it resolves to the ALB's private IPs)
4. The VPC origin protocol set to `https-only`, restricted to TLSv1.2; the distribution's origin domain set to the origin hostname
5. The ALB security group ingress changed to port 443 from the prefix list

## Verification

Through the CloudFront domain, requests should work:

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://<CloudFront domain>/.well-known/oauth-authorization-server   # 200
curl -s -o /dev/null -w '%{http_code}\n' https://<CloudFront domain>/not-a-route                             # 404 (ALB default action)
```

The origin hostname resolves publicly, but only to private IPs, and a direct connection from the internet should time out:

```bash
dig +short <ORIGIN_DOMAIN_NAME>                                    # only 10.x-style private addresses
curl -s -m 5 https://<ORIGIN_DOMAIN_NAME>/ ; echo "exit=$?"        # exit=28 (timeout)
```

Check the listener, certificate, and VPC origin:

```bash
aws elbv2 describe-listeners --load-balancer-arn <ALB_ARN> \
  --query 'Listeners[].{Port:Port,Proto:Protocol,Policy:SslPolicy}'
aws acm describe-certificate --certificate-arn <CERT_ARN> \
  --query 'Certificate.{Status:Status,Renewal:RenewalEligibility,NotAfter:NotAfter}'
aws cloudfront get-vpc-origin --id <VPC_ORIGIN_ID> \
  --query 'VpcOrigin.VpcOriginEndpointConfig.{Proto:OriginProtocolPolicy,Ssl:OriginSslProtocols.Items}'
```

Expected: a single `443 / HTTPS` listener; certificate `ISSUED` and `ELIGIBLE`; VPC origin `https-only` with `["TLSv1.2"]`. Finish with `./scripts/test-e2e.sh`.

## Certificate renewal

ACM renews public certificates automatically before they expire, as long as the certificate is still in use by the ALB and the `_xxxx` validation CNAME is still in the hosted zone. **Do not delete that validation record**, and do not switch the zone to private. If renewal fails close to expiry, ACM raises an AWS Health event.

## Troubleshooting

| Symptom | Common cause |
|---|---|
| CloudFront returns 502 with `X-Cache: Error from cloudfront` | Certificate doesn't match the origin hostname, is expired, or the chain is incomplete; or the distribution's origin domain differs from the certificate domain |
| Deploy hangs on the certificate / ACM stays `PENDING_VALIDATION` | The zone isn't NS-delegated so the validation record isn't publicly resolvable; or a CAA record blocks Amazon |
| CloudFront returns 504 | Security group port doesn't match the listener (e.g. still only 80 open); or the VPC origin hasn't finished deploying |
| `deploy.sh` reports `Invalid origin TLS config` | Only one of the two variables is set; the zone is private; the hostname isn't inside the zone; the hostname has uppercase letters |
| Feishu authorization callback fails | Not related to origin TLS: `deploy.sh` writes the callback (CloudFront domain) into `CALLBACK_URL`. If it is unset, the OAuth Lambda rejects ALB events outright rather than building a redirect_uri from the ALB-side Host (the origin hostname) |

## Side effects and limits

- **The hostname becomes public**: ACM public certificates are recorded in Certificate Transparency logs, and public DNS resolves to the ALB's private IPs. Those IPs are unreachable from the internet, so little is exposed, but pick a neutral origin hostname that doesn't name a customer, project, or environment.
- **Cost**: ACM public certificates are free; a hosted zone created just for this is billed at Route 53 hosted-zone pricing, and an existing zone adds nothing.
- **Client-side TLS policy is unaffected**: the entry point still uses the default `*.cloudfront.net` certificate, for which CloudFront fixes the `TLSv1` security policy (the minimum version can't be raised; clients normally negotiate TLS 1.2/1.3). Raising the minimum requires a custom viewer domain and certificate on the distribution, which changes the client URL; this solution doesn't do that.
- **Switching between HTTP and HTTPS mode** replaces the ALB listener, changes the security group port and the VPC origin protocol, and takes a few minutes for CloudFront to propagate. This repo has only been tested deploying HTTPS mode directly; the switch itself hasn't been tested, so do it in a maintenance window and run e2e afterwards.
- Origin TLS only protects the CloudFront → ALB hop. ALB → Lambda is a Lambda Invoke API call, not a network connection; Middleware → AgentCore uses TLS + SigV4.
