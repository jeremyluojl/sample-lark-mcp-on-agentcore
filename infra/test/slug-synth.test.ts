import { describe, it, expect, vi } from "vitest";
import * as cdk from "aws-cdk-lib";
import { Template, Match } from "aws-cdk-lib/assertions";
import { OAuthStack } from "../lib/oauth-stack";
import { RuntimeStack } from "../lib/runtime-stack";

// Full CDK synth (esbuild bundling + Docker asset fingerprinting) can exceed the
// 5 s default when the whole suite runs in parallel — same as the other synth tests.
vi.setConfig({ testTimeout: 30_000 });

const TEST_ENV = { account: "123456789012", region: "us-west-2" };
const SLUG = "team-a";

function oauthTemplate(slug: string): Template {
  const app = new cdk.App();
  const stack = new OAuthStack(app, slug ? `OAuth-${slug}` : "OAuth", {
    env: TEST_ENV,
    slug,
    runtimeArn: "arn:aws:bedrock-agentcore:us-west-2:123456789012:runtime/test",
  });
  return Template.fromStack(stack);
}

function runtimeTemplate(slug: string): Template {
  const app = new cdk.App();
  const stack = new RuntimeStack(app, slug ? `Runtime-${slug}` : "Runtime", { env: TEST_ENV, slug });
  return Template.fromStack(stack);
}

describe(`OAuthStack slugged synth (slug=${SLUG}) carries the slug on every physical name`, () => {
  const t = oauthTemplate(SLUG);

  it("DynamoDB tables are slug-suffixed", () => {
    t.hasResourceProperties("AWS::DynamoDB::Table", { TableName: `lark-mcp-on-agentcore-oauth-codes-${SLUG}` });
    t.hasResourceProperties("AWS::DynamoDB::Table", { TableName: `lark-mcp-on-agentcore-openid-map-${SLUG}` });
  });

  it("origin ALB + target group names are slug-suffixed", () => {
    t.hasResourceProperties("AWS::ElasticLoadBalancingV2::LoadBalancer", { Name: `lmcp-alb-${SLUG}` });
    t.hasResourceProperties("AWS::ElasticLoadBalancingV2::TargetGroup", { Name: `lmcp-mcp-${SLUG}` });
    t.hasResourceProperties("AWS::ElasticLoadBalancingV2::TargetGroup", { Name: `lmcp-oauth-${SLUG}` });
  });

  it("SNS topic is slug-suffixed", () => {
    t.hasResourceProperties("AWS::SNS::Topic", { TopicName: `lark-mcp-on-agentcore-alarms-${SLUG}` });
  });

  it("dashboard is slug-suffixed", () => {
    t.hasResourceProperties("AWS::CloudWatch::Dashboard", { DashboardName: `lark-mcp-on-agentcore-${SLUG}` });
  });

  it("ALB alarm/dashboard watch THIS app's load balancer, not another app's (no observability bleed)", () => {
    // The 5xx alarm's LoadBalancer dimension must resolve from THIS stack's ALB,
    // else a slug app's alarm silently watches another app's ALB.
    const alarms = Object.values(t.findResources("AWS::CloudWatch::Alarm")) as any[];
    const albAlarm = alarms.find((a) => JSON.stringify(a.Properties?.Metrics ?? []).includes("AWS/ApplicationELB"));
    expect(albAlarm, "ALB 5xx alarm present").toBeDefined();
    const albLogicalId = Object.keys(t.findResources("AWS::ElasticLoadBalancingV2::LoadBalancer"))[0];
    expect(JSON.stringify(albAlarm.Properties.Metrics)).toContain(albLogicalId);
    const dashboards = JSON.stringify(Object.values(t.findResources("AWS::CloudWatch::Dashboard")));
    expect(dashboards).toContain("AWS/ApplicationELB");
    expect(dashboards).toContain(albLogicalId);
  });

  it("alarm names carry the slug, AND none is undefined", () => {
    const alarms = t.findResources("AWS::CloudWatch::Alarm");
    const names = Object.values(alarms).map((a) => a.Properties?.AlarmName as string);
    expect(names.length).toBe(11);
    for (const n of names) {
      expect(n).toBeTruthy();
      expect(n).not.toContain("undefined");
      expect(n.endsWith(`(${SLUG})`), `alarm name "${n}" should end with (${SLUG})`).toBe(true);
    }
    // the previously-buggy concurrency alarm too
    expect(names).toContain(`Lambda 并发过高 (%) (${SLUG})`);
  });

  it("custom MetricFilters publish to the per-slug namespace", () => {
    const filters = t.findResources("AWS::Logs::MetricFilter");
    const namespaces = new Set(
      Object.values(filters).flatMap((f) =>
        (f.Properties?.MetricTransformations ?? []).map((m: any) => m.MetricNamespace),
      ),
    );
    expect(namespaces.has(`LarkMcpOnAgentCore/${SLUG}`)).toBe(true);
    expect(namespaces.has("LarkMcpOnAgentCore")).toBe(false);
  });

  it("dashboard references no arn:...:alarm:undefined and uses the per-slug metric namespace", () => {
    const dashboards = t.findResources("AWS::CloudWatch::Dashboard");
    const body = JSON.stringify(Object.values(dashboards));
    expect(body).not.toContain("alarm:undefined");
    expect(body).toContain(`LarkMcpOnAgentCore/${SLUG}`);
  });

  it("a SLUGGED app gets NO nested-secret Deny (its users/<slug>/* is already fenced)", () => {
    // The Deny is only for the default app, whose `users/*` would otherwise reach
    // every slug's `users/<slug>/<openid>`. A slugged app's grant can't over-reach.
    const policies = JSON.stringify(Object.values(t.findResources("AWS::IAM::Policy")));
    expect(policies).not.toContain(`secret:lark-mcp-on-agentcore/users/${SLUG}/*/*`);
  });
});

describe("OAuthStack DEFAULT app — cross-app user-secret IAM isolation (Deny on nested)", () => {
  const t = oauthTemplate("");
  it("denies secretsmanager:* on the 2+-segment users/*/* shape so default can't reach a slugged app's tokens", () => {
    // IAM `*` matches `/`, so the default `users/*` grant would otherwise cover
    // every slugged `users/<slug>/<openid>`. An explicit Deny on `users/*/*`
    // closes the IAM boundary (the runtime [^/]+ screen only limits enumeration).
    t.hasResourceProperties("AWS::IAM::Policy", {
      PolicyDocument: {
        Statement: Match.arrayWith([
          Match.objectLike({
            Effect: "Deny",
            Action: "secretsmanager:*",
            Resource: Match.stringLikeRegexp("secret:lark-mcp-on-agentcore/users/\\*/\\*$"),
          }),
        ]),
      },
    });
  });
});

describe(`RuntimeStack slugged synth (slug=${SLUG}) — Killer Fix #1 IAM scoping`, () => {
  it("the secret GetSecretValue grant is scoped to feishu-app/<slug>-* (slash delimiter)", () => {
    const t = runtimeTemplate(SLUG);
    t.hasResourceProperties("AWS::IAM::Policy", {
      PolicyDocument: {
        Statement: Match.arrayWith([
          Match.objectLike({
            Action: "secretsmanager:GetSecretValue",
            Resource: Match.stringLikeRegexp(`secret:lark-mcp-on-agentcore/feishu-app/${SLUG}-\\*$`),
          }),
        ]),
      },
    });
  });

  it("the default runtime grant stays feishu-app-* and CANNOT match a slugged secret", () => {
    const t = runtimeTemplate("");
    t.hasResourceProperties("AWS::IAM::Policy", {
      PolicyDocument: {
        Statement: Match.arrayWith([
          Match.objectLike({
            Action: "secretsmanager:GetSecretValue",
            Resource: Match.stringLikeRegexp("secret:lark-mcp-on-agentcore/feishu-app-\\*$"),
          }),
        ]),
      },
    });
    // Critical isolation property: 'feishu-app-*' (char after is '-') cannot match
    // 'feishu-app/team-a-...' (char after is '/'). Assert the slug form is NOT the default form.
    expect(`lark-mcp-on-agentcore/feishu-app/${SLUG}`.startsWith("lark-mcp-on-agentcore/feishu-app-")).toBe(false);
  });
});
