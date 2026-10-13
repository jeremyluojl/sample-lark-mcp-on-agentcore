import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createHash, randomBytes } from 'crypto';
import { mockClient } from './mock-client';

// The OAuth Lambda sits behind an internal Application Load Balancer (CloudFront
// VPC origin). ALB events differ from API Gateway in two ways this file pins:
//   1. queryStringParameters arrive STILL percent-encoded (ELB docs: "the load
//      balancer does not decode them");
//   2. every response must carry isBase64Encoded (+ headers), else ALB 502s.
// It also drives the whole Quick-style OAuth flow end to end with ALB-shaped
// events, including the base64-encoded form body ALB sends for /token.

process.env.OAUTH_CLIENT_SECRET = 'test-client-secret';
process.env.CODE_TABLE = 'test-table';
process.env.CALLBACK_URL = 'https://test.cloudfront.net/callback';
process.env.SECRET_PREFIX = 'lark-mcp-on-agentcore/users';
process.env.OPENID_TABLE = 'lark-mcp-on-agentcore-openid-map';
process.env.APP_SECRET_ID = 'lark-mcp-on-agentcore/feishu-app';
process.env.STATE_SECRET_PARAM = '/lark-mcp-on-agentcore/state-secret';
process.env.OAUTH_CLIENT_ID = 'lark-mcp-on-agentcore';
process.env.FEISHU_SCOPES = 'im:message contact:user.base:readonly';

vi.mock('@aws-sdk/client-secrets-manager', () => mockClient.secretsManager);
vi.mock('@aws-sdk/client-ssm', () => mockClient.ssm);
vi.mock('@aws-sdk/lib-dynamodb', () => mockClient.dynamodb);
vi.mock('@aws-sdk/client-dynamodb', () => ({ DynamoDBClient: vi.fn(() => ({})) }));

const ELB = { elb: { targetGroupArn: 'arn:aws:elasticloadbalancing:us-west-2:111:targetgroup/lmcp-oauth/abc' } };
const QUICK_CB = 'https://us-east-1.quicksight.aws.amazon.com/sn/oauthcallback';
const enc = encodeURIComponent;

async function call(event: any) {
  vi.resetModules();
  const { handler } = await import('../index');
  return handler(event) as Promise<any>;
}

function pkce() {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
}

function mockFeishu() {
  vi.spyOn(global, 'fetch').mockImplementation(async (input: any) => {
    const url = typeof input === 'string' ? input : input.url;
    if (url.includes('app_access_token')) return new Response(JSON.stringify({ app_access_token: 'app-token' }));
    if (url.includes('oidc/access_token')) {
      return new Response(JSON.stringify({ code: 0, msg: 'ok', data: { access_token: 'feishu-tok', refresh_token: 'rt', expires_in: 7200, open_id: 'ou_alb_user' } }));
    }
    return new Response('{}');
  });
}

beforeEach(() => {
  mockClient.reset();
  mockClient.secretsManager.__set('lark-mcp-on-agentcore/feishu-app', JSON.stringify({ appId: 'cli_test', appSecret: 'app-secret' }));
});
afterEach(() => { vi.restoreAllMocks(); });

describe('getQueryParams', () => {
  it('decodes percent-encoded keys and values only for ALB events', async () => {
    vi.resetModules();
    const { getQueryParams } = await import('../index');
    const raw = { redirect_uri: enc(QUICK_CB), 'extra%5Fscope': 'a%2Cb' };
    expect(getQueryParams({ requestContext: ELB, queryStringParameters: raw })).toEqual({
      redirect_uri: QUICK_CB,
      extra_scope: 'a,b',
    });
    // API Gateway already decoded — must not be decoded twice.
    expect(getQueryParams({ queryStringParameters: { s: '100%25' } })).toEqual({ s: '100%25' });
  });

  it("keeps a literal '+' (no form-decoding) and tolerates malformed escapes", async () => {
    vi.resetModules();
    const { getQueryParams } = await import('../index');
    expect(getQueryParams({ requestContext: ELB, queryStringParameters: { state: 'a+b', bad: '%E0%A4%A' } }))
      .toEqual({ state: 'a+b', bad: '%E0%A4%A' });
    expect(getQueryParams({ requestContext: ELB })).toEqual({});
  });
});

describe('ALB response contract', () => {
  it('never derives the Feishu redirect_uri from the ALB-side Host when CALLBACK_URL is unset', async () => {
    const orig = process.env.CALLBACK_URL;
    process.env.CALLBACK_URL = 'SET_AFTER_DEPLOY';
    try {
      const r = await call({
        path: '/authorize', httpMethod: 'GET', requestContext: ELB,
        headers: { host: 'internal-lmcp-alb-1.us-east-1.elb.amazonaws.com' },
        queryStringParameters: { redirect_uri: enc(QUICK_CB), code_challenge: 'c', code_challenge_method: 'S256' },
      });
      expect(r.statusCode).toBe(500);
      expect(r.body).toContain('callback URL cannot be derived');
    } finally {
      process.env.CALLBACK_URL = orig;
    }
  });
  it('every HTTP response carries isBase64Encoded:false and headers', async () => {
    for (const ev of [
      { path: '/.well-known/oauth-authorization-server', httpMethod: 'GET' },
      { path: '/callback', httpMethod: 'GET', queryStringParameters: {} },  // 400 path, body-only response
      { path: '/nope', httpMethod: 'GET' },
    ]) {
      const r = await call({ ...ev, requestContext: ELB, headers: { host: 'origin.example.com' } });
      expect(r.isBase64Encoded).toBe(false);
      expect(r.headers?.['Cache-Control']).toBe('no-store');
    }
  });
});

describe('Quick OAuth flow with ALB-shaped events', () => {
  it('/authorize → /callback → /token succeeds with encoded query + base64 form body', async () => {
    mockFeishu();
    const { verifier, challenge } = pkce();

    // 1. /authorize: redirect_uri arrives percent-encoded. Before the fix this
    //    failed `new URL()` and returned 400 "redirect_uri not a valid URL".
    const authz = await call({
      path: '/authorize', httpMethod: 'GET', requestContext: ELB,
      queryStringParameters: {
        redirect_uri: enc(QUICK_CB), state: enc('quick state/=+'), code_challenge: challenge, code_challenge_method: 'S256',
      },
    });
    expect(authz.statusCode).toBe(302);
    const feishuUrl = new URL(authz.headers.Location);
    expect(feishuUrl.searchParams.get('redirect_uri')).toBe('https://test.cloudfront.net/callback');
    const state = feishuUrl.searchParams.get('state')!;

    // 2. /callback from Feishu (state echoed back, possibly re-encoded).
    const cb = await call({
      path: '/callback', httpMethod: 'GET', requestContext: ELB,
      queryStringParameters: { code: 'feishu-code', state: enc(state) },
    });
    expect(cb.statusCode).toBe(302);
    const back = new URL(cb.headers.Location);
    expect(`${back.origin}${back.pathname}`).toBe(QUICK_CB);
    expect(back.searchParams.get('state')).toBe('quick state/=+'); // client state round-trips intact
    const code = back.searchParams.get('code')!;

    // 3. /token: ALB base64-encodes application/x-www-form-urlencoded bodies.
    const form = new URLSearchParams({
      grant_type: 'authorization_code', code, code_verifier: verifier,
      redirect_uri: QUICK_CB, client_id: 'lark-mcp-on-agentcore', client_secret: 'test-client-secret',
    }).toString();
    const tok = await call({
      path: '/token', httpMethod: 'POST', requestContext: ELB,
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      isBase64Encoded: true, body: Buffer.from(form).toString('base64'),
    });
    expect(tok.statusCode).toBe(200);
    expect(tok.isBase64Encoded).toBe(false);
    const body = JSON.parse(tok.body);
    expect(body.token_type).toBe('Bearer');
    expect(Buffer.from(body.access_token, 'base64url').toString()).toMatch(/^ou_alb_user:\d+:[a-f0-9]{64}$/);
  });
});
