import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createHmac } from 'crypto';

// The middleware sits behind an internal ALB (CloudFront VPC origin). ALB needs
// isBase64Encoded on every response and caps the WHOLE Lambda response JSON at
// 1 MB (API Gateway allowed ~6 MB) — an over-limit response would surface as a
// bare 502 the agent cannot act on. These tests pin the contract and the guard.

process.env.STATE_SECRET_PARAM = '/test/state-secret';
process.env.RUNTIME_ARN = 'arn:aws:bedrock-agentcore:us-west-2:111:runtime/test';
process.env.AUTHORIZE_BASE = 'https://test.cloudfront.net';
process.env.DEPLOY_REGION = 'us-west-2';
process.env.SECRET_PREFIX = 'lark-mcp-on-agentcore/users';

const STATE_SECRET = 'test-state-secret';

vi.mock('@aws-sdk/client-secrets-manager', () => ({
  SecretsManagerClient: vi.fn(() => ({
    send: vi.fn(async () => ({ SecretString: JSON.stringify({ access_token: 'feishu-tok', expires_at: Date.now() / 1000 + 3600 }) })),
  })),
  GetSecretValueCommand: class { constructor(public input: any) {} },
}));
vi.mock('@aws-sdk/client-ssm', () => ({
  SSMClient: vi.fn(() => ({ send: vi.fn(async () => ({ Parameter: { Value: STATE_SECRET } })) })),
  GetParameterCommand: class { constructor(public input: any) {} },
}));
vi.mock('@smithy/signature-v4', () => ({
  SignatureV4: class { async sign(req: any) { return req; } },
}));
vi.mock('@aws-crypto/sha256-js', () => ({ Sha256: class {} }));
vi.mock('@smithy/protocol-http', () => ({
  HttpRequest: class { constructor(o: any) { Object.assign(this, o); } },
}));
vi.mock('@aws-sdk/credential-provider-node', () => ({ defaultProvider: () => async () => ({ accessKeyId: 'a', secretAccessKey: 'b' }) }));

let upstreamBody = '';
global.fetch = vi.fn(async () => new Response(upstreamBody, { status: 200, headers: { 'content-type': 'text/event-stream' } })) as any;

const TOKEN_KEY = createHmac('sha256', STATE_SECRET).update('mcp-token-v1').digest();
function bearer(userId = 'ou_user'): string {
  const exp = Math.floor(Date.now() / 1000) + 3600;
  const sig = createHmac('sha256', TOKEN_KEY).update(`${userId}:${exp}`).digest('hex');
  return `Bearer ${Buffer.from(`${userId}:${exp}:${sig}`).toString('base64url')}`;
}

const ELB = { elb: { targetGroupArn: 'arn:aws:elasticloadbalancing:us-west-2:111:targetgroup/lmcp-mcp/abc' } };

async function call(event: any) {
  vi.resetModules();
  const { handler } = await import('../index');
  return handler(event) as Promise<any>;
}

function sse(obj: unknown) { return `event: message\ndata: ${JSON.stringify(obj)}\n\n`; }
function parseSse(body: string) { return JSON.parse(body.replace(/^event: message\ndata: /, '').trim()); }

beforeEach(() => { upstreamBody = sse({ jsonrpc: '2.0', id: 1, result: { ok: true } }); });
afterEach(() => { vi.clearAllMocks(); });

describe('mcp-middleware — ALB response contract', () => {
  it('401 and 200 responses both carry isBase64Encoded:false', async () => {
    const unauth = await call({ requestContext: ELB, headers: {}, body: '{}' });
    expect(unauth.statusCode).toBe(401);
    expect(unauth.isBase64Encoded).toBe(false);

    const ok = await call({
      requestContext: ELB, headers: { authorization: bearer(), 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    });
    expect(ok.statusCode).toBe(200);
    expect(ok.isBase64Encoded).toBe(false);
    expect(ok.headers['Cache-Control']).toBe('no-store');
  });

  it('passes a response just under the 1 MB ALB limit through untouched', async () => {
    upstreamBody = sse({ jsonrpc: '2.0', id: 7, result: { content: [{ type: 'text', text: 'x'.repeat(900_000) }] } });
    const r = await call({
      requestContext: ELB, headers: { authorization: bearer() },
      body: JSON.stringify({ jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'lark_docs_fetch' } }),
    });
    expect(r.body).toBe(upstreamBody);
  });
});

describe('mcp-middleware — oversized response guard', () => {
  it('turns an over-limit tools/call result into a self-explanatory MCP error (not an ALB 502)', async () => {
    upstreamBody = sse({ jsonrpc: '2.0', id: 42, result: { content: [{ type: 'text', text: 'x'.repeat(1_200_000) }] } });
    const r = await call({
      requestContext: ELB, headers: { authorization: bearer() },
      body: JSON.stringify({ jsonrpc: '2.0', id: 42, method: 'tools/call', params: { name: 'lark_docs_fetch' } }),
    });
    expect(r.statusCode).toBe(200);
    expect(r.isBase64Encoded).toBe(false);
    expect(r.headers['Content-Type']).toBe('text/event-stream');
    expect(Buffer.byteLength(JSON.stringify(r))).toBeLessThan(1_000_000);
    const msg = parseSse(r.body);
    expect(msg.id).toBe(42);
    expect(msg.result.isError).toBe(true);
    expect(JSON.parse(msg.result.content[0].text).error).toBe('output_too_large');
  });

  it('answers a non-tools/call oversized response with a JSON-RPC error, decoding a base64 request body', async () => {
    upstreamBody = sse({ jsonrpc: '2.0', id: 'L', result: { tools: ['y'.repeat(1_200_000)] } });
    const req = JSON.stringify({ jsonrpc: '2.0', id: 'L', method: 'tools/list' });
    const r = await call({
      requestContext: ELB, headers: { authorization: bearer() },
      isBase64Encoded: true, body: Buffer.from(req).toString('base64'),
    });
    const msg = parseSse(r.body);
    expect(msg.id).toBe('L');
    expect(msg.error.code).toBe(-32000);
    expect(msg.error.message).toContain('exceeds');
  });
});
