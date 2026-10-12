import { describe, it, expect, vi } from "vitest";
import * as cdk from "aws-cdk-lib";
import { Template, Match } from "aws-cdk-lib/assertions";
import { OAuthStack } from "../lib/oauth-stack";

// Full CDK synth (esbuild bundling + template validation) takes several
// seconds on CI runners; the 5 s default is too tight for this file.
vi.setConfig({ testTimeout: 30_000 });

const TEST_ENV = { account: "123456789012", region: "us-west-2" };

function synth(): Template {
  const app = new cdk.App();
  const stack = new OAuthStack(app, "HardenStack", {
    env: TEST_ENV,
    runtimeArn: "arn:aws:bedrock-agentcore:us-west-2:123456789012:runtime/test",
  });
  return Template.fromStack(stack);
}

function synthTls(): Template {
  const app = new cdk.App();
  const stack = new OAuthStack(app, "HardenTlsStack", {
    env: TEST_ENV,
    runtimeArn: "arn:aws:bedrock-agentcore:us-west-2:123456789012:runtime/test",
    originDomainName: "lark-mcp-origin.example.com",
    originHostedZoneId: "Z0000000000000",
    originHostedZoneName: "example.com",
  });
  return Template.fromStack(stack);
}

describe("hardening: no publicly callable origin (CloudFront is the only entry point)", () => {
  const template = synth();

  it("there is no API Gateway (its execute-api URL was callable directly, bypassing CloudFront/WAF)", () => {
    expect(Object.keys(template.findResources("AWS::ApiGateway::RestApi"))).toHaveLength(0);
    expect(Object.keys(template.findResources("AWS::ApiGatewayV2::Api"))).toHaveLength(0);
  });

  it("the origin ALB is internal and sits in isolated subnets of a NAT-less VPC", () => {
    template.hasResourceProperties("AWS::ElasticLoadBalancingV2::LoadBalancer", {
      Scheme: "internal",
      LoadBalancerAttributes: Match.arrayWith([
        { Key: "routing.http.drop_invalid_header_fields.enabled", Value: "true" },
        { Key: "access_logs.s3.enabled", Value: "true" },
      ]),
    });
    expect(Object.keys(template.findResources("AWS::EC2::NatGateway"))).toHaveLength(0);
    // Isolated subnets: no route to the IGW (it only exists because VPC origins require one attached).
    const routes = Object.values(template.findResources("AWS::EC2::Route"));
    expect(routes.filter((r: any) => r.Properties?.GatewayId)).toHaveLength(0);
    template.resourceCountIs("AWS::EC2::VPCGatewayAttachment", 1);
  });

  it("ALB ingress is ONLY the CloudFront origin-facing prefix list (never 0.0.0.0/0)", () => {
    const sgs = Object.values(template.findResources("AWS::EC2::SecurityGroup")) as any[];
    const ingress = sgs.flatMap((sg) => sg.Properties?.SecurityGroupIngress ?? []);
    const standalone = Object.values(template.findResources("AWS::EC2::SecurityGroupIngress")) as any[];
    const all = [...ingress, ...standalone.map((r) => r.Properties)];
    expect(all.length).toBeGreaterThan(0);
    for (const rule of all) {
      expect(rule.CidrIp, "no CIDR-based ingress").toBeUndefined();
      expect(rule.CidrIpv6, "no CIDR-based ingress").toBeUndefined();
      expect(rule.SourcePrefixListId).toBeDefined();
    }
  });

  it("CloudFront reaches the ALB through a VPC origin, not a public custom origin", () => {
    template.resourceCountIs("AWS::CloudFront::VpcOrigin", 1);
    template.hasResourceProperties("AWS::CloudFront::Distribution", {
      DistributionConfig: Match.objectLike({
        Origins: [Match.objectLike({ VpcOriginConfig: Match.objectLike({ VpcOriginId: Match.anyValue() }) })],
      }),
    });
  });

  it("unlisted paths get a fixed 404 from the ALB and never invoke a Lambda", () => {
    template.hasResourceProperties("AWS::ElasticLoadBalancingV2::Listener", {
      DefaultActions: [Match.objectLike({ Type: "fixed-response", FixedResponseConfig: Match.objectLike({ StatusCode: "404" }) })],
    });
    template.resourceCountIs("AWS::ElasticLoadBalancingV2::ListenerRule", 3);
  });

  it("the ELB invoke permission is scoped by SourceAccount + target-group SourceArn (no confused deputy)", () => {
    const perms = Object.values(template.findResources("AWS::Lambda::Permission")) as any[];
    const elb = perms.filter((p) => p.Properties?.Principal === "elasticloadbalancing.amazonaws.com");
    expect(elb).toHaveLength(2);
    for (const p of elb) {
      expect(p.Properties.SourceAccount).toBeDefined();
      expect(JSON.stringify(p.Properties.SourceArn)).toMatch(/targetgroup\/lmcp-(mcp|oauth)\/\*/);
    }
  });

  it("without an origin domain the hop is HTTP (port 80), with one it is HTTPS + ACM + TLS-only VPC origin", () => {
    template.hasResourceProperties("AWS::ElasticLoadBalancingV2::Listener", { Port: 80, Protocol: "HTTP" });
    template.hasResourceProperties("AWS::CloudFront::VpcOrigin", {
      VpcOriginEndpointConfig: Match.objectLike({ OriginProtocolPolicy: "http-only" }),
    });
    const tls = synthTls();
    tls.hasResourceProperties("AWS::ElasticLoadBalancingV2::Listener", { Port: 443, Protocol: "HTTPS" });
    tls.hasResourceProperties("AWS::CertificateManager::Certificate", { DomainName: "lark-mcp-origin.example.com" });
    tls.hasResourceProperties("AWS::CloudFront::VpcOrigin", {
      VpcOriginEndpointConfig: Match.objectLike({ OriginProtocolPolicy: "https-only", OriginSSLProtocols: ["TLSv1.2"] }),
    });
    tls.hasResourceProperties("AWS::CloudFront::Distribution", {
      DistributionConfig: Match.objectLike({
        Origins: [Match.objectLike({ DomainName: "lark-mcp-origin.example.com" })],
      }),
    });
    tls.hasResourceProperties("AWS::Route53::RecordSet", { Name: "lark-mcp-origin.example.com.", Type: "A" });
  });
});

describe("hardening: public Lambdas have a reserved concurrency cap", () => {
  const template = synth();

  it("middleware Lambda caps ReservedConcurrentExecutions (DoS / cost blast radius)", () => {
    template.hasResourceProperties("AWS::Lambda::Function", {
      FunctionName: "HardenStack-middleware",
      ReservedConcurrentExecutions: Match.anyValue(),
    });
  });

  it("oauth Lambda caps ReservedConcurrentExecutions", () => {
    template.hasResourceProperties("AWS::Lambda::Function", {
      FunctionName: "HardenStack-oauth",
      ReservedConcurrentExecutions: Match.anyValue(),
    });
  });
});

describe("hardening: log retention defaults to finite (not INFINITE)", () => {
  it("LogGroups get a bounded retention even when LOG_RETENTION_DAYS is unset", () => {
    const template = synth();
    // Every Lambda log group must carry a RetentionInDays (no unbounded growth).
    const groups = template.findResources("AWS::Logs::LogGroup");
    const vals = Object.values(groups).map((g: any) => g.Properties?.RetentionInDays);
    expect(vals.length).toBeGreaterThan(0);
    expect(vals.every((v) => typeof v === "number" && v > 0)).toBe(true);
  });
});

describe("hardening: OAuth Lambda write grant is scoped to users/*, not the whole project prefix", () => {
  const template = synth();

  it("does NOT grant PutSecretValue/CreateSecret on the broad lark-mcp-on-agentcore/* prefix", () => {
    const policies = template.findResources("AWS::IAM::Policy");
    const json = JSON.stringify(policies);
    // The broad write grant (which also covers the feishu-app master secret) must be gone.
    const broadWrite = Object.values(policies).some((p: any) =>
      (p.Properties?.PolicyDocument?.Statement ?? []).some((s: any) => {
        const actions = ([] as string[]).concat(s.Action ?? []);
        const writes = actions.includes("secretsmanager:PutSecretValue") || actions.includes("secretsmanager:CreateSecret");
        const res = JSON.stringify(s.Resource ?? "");
        // broad = ends at project root "/*" rather than "/users/*"
        return writes && res.includes("lark-mcp-on-agentcore/*") && !res.includes("users/*");
      })
    );
    expect(broadWrite, "OAuth write grant still uses the broad project prefix").toBe(false);
    // And the narrowed users/* write grant must be present.
    expect(json).toContain("users/*");
    // DeleteSecret must be granted (for revoked-user cleanup) and scoped to users/*
    expect(json).toContain("secretsmanager:DeleteSecret");
    // RestoreSecret must be granted (re-auth within the 7-day recovery window)
    expect(json).toContain("secretsmanager:RestoreSecret");
  });
});
