import { describe, it, expect } from 'vitest';
import { createBeforeSend, createBeforeBreadcrumb, normalizeGlitchtipDsn } from '../src/index';
import { scrubEvent, scrubValue, REDACTED, REDACTED_NUM, type ScrubEvent } from '../src/scrub';

// A salary value used throughout. It is a bare integer — NOT regex-detectable,
// which is the whole reason the scrubber works by key-path allowlist, not pattern.
const SALARY = 84500;
const EMAIL = 'max.muster@example.ch';

function jsonHas(obj: unknown, needle: string | number): boolean {
	return JSON.stringify(obj).includes(String(needle));
}

describe('request data', () => {
	it('redacts salary and email present in request form data', () => {
		const event: ScrubEvent = {
			request: { data: { name: 'Max', email: EMAIL, salary: SALARY, status: 200 } },
		};
		// precondition: PII is present before scrubbing
		expect(jsonHas(event, SALARY)).toBe(true);
		expect(jsonHas(event, EMAIL)).toBe(true);

		const out = createBeforeSend()(event)!;
		expect(jsonHas(out, SALARY)).toBe(false);
		expect(jsonHas(out, EMAIL)).toBe(false);
	});

	it('drops a raw string body wholesale (stringified salary is not regex-detectable)', () => {
		const event: ScrubEvent = {
			request: { data: `{"email":"${EMAIL}","salary":${SALARY}}` },
		};
		const out = createBeforeSend()(event)!;
		expect((out.request as { data: unknown }).data).toBe(REDACTED);
		expect(jsonHas(out, SALARY)).toBe(false);
	});

	it('strips Authorization + cookie headers and the preview ?token= query param', () => {
		const event: ScrubEvent = {
			request: {
				headers: { Authorization: 'Bearer secret-abc', 'X-Real-IP': '1.2.3.4' },
				cookies: { sid: 'abc' },
				query_string: '?token=PAYLOAD_PREVIEW_SECRET&slug=home',
			},
		};
		const out = createBeforeSend()(event)!;
		const req = out.request as Record<string, any>;
		expect(req.headers.Authorization).toBe(REDACTED);
		expect(req.cookies).toBe(REDACTED);
		expect(req.query_string).not.toContain('PAYLOAD_PREVIEW_SECRET');
	});

	it('strips a secret param at start-of-string (Sentry query_string has no leading `?`)', () => {
		// GlitchTip/Sentry deliver request.query_string WITHOUT a leading `?`, so the
		// preview token is the FIRST param — must still be stripped (regression guard).
		const first = createBeforeSend()({
			request: { query_string: 'token=PAYLOAD_PREVIEW_SECRET&slug=home' },
		})!;
		expect((first.request as any).query_string).not.toContain('PAYLOAD_PREVIEW_SECRET');
		expect((first.request as any).query_string).toContain('[stripped]');

		// bare single secret param, no separators at all
		const bare = createBeforeSend()({
			request: { query_string: 'preview=PAYLOAD_PREVIEW_SECRET' },
		})!;
		expect((bare.request as any).query_string).not.toContain('PAYLOAD_PREVIEW_SECRET');
	});
});

describe('exception message (issue title source)', () => {
	it('masks email / AHV / IBAN in exception.values[].value (GlitchTip title comes from here)', () => {
		const event: ScrubEvent = {
			exception: {
				values: [
					{ type: 'Error', value: `lead failed for ${EMAIL} AHV 756.1234.5678.97`, stacktrace: { frames: [] } },
				],
			},
		};
		const out = createBeforeSend()(event)!;
		const v = out.exception!.values![0].value as string;
		expect(v).toContain('[email]');
		expect(v).toContain('[ahv]');
		expect(v).not.toContain(EMAIL);
	});

	// NOTE intentionally NOT tested: a secret echoed mid-prose like
	// `…failed: token=SECRET` is NOT stripped — SECRET_QS_RE targets query-string
	// context (`?`/`&`/start), not arbitrary `key=value` in a sentence, and a bare
	// secret value has no detectable format. Defense for the message channel is
	// email/IBAN/AHV masking (above); secrets/tokens leak only if interpolated into
	// a message, which code must avoid. The real preview-token channel is
	// request.query_string (covered in 'request data').
});

describe('normalizeGlitchtipDsn', () => {
	it('strips dashes from a dashed-UUID GlitchTip public key so the SDK can parse it', () => {
		const dashed = 'https://053703c0-1bdf-49f7-8a9a-aece4b0e8e7f@errors.noevu.dev/1';
		const fixed = normalizeGlitchtipDsn(dashed);
		expect(fixed).toBe('https://053703c01bdf49f78a9aaece4b0e8e7f@errors.noevu.dev/1');
		// Sentry DSN public-key regex group is (\w+) — must contain no dash.
		expect(fixed!.split('@')[0].replace('https://', '')).toMatch(/^\w+$/);
	});

	it('is idempotent and leaves a clean DSN / non-DSN untouched', () => {
		const clean = 'https://abc123@errors.noevu.dev/2';
		expect(normalizeGlitchtipDsn(clean)).toBe(clean);
		expect(normalizeGlitchtipDsn(normalizeGlitchtipDsn(clean))).toBe(clean);
		expect(normalizeGlitchtipDsn(undefined)).toBeUndefined();
		expect(normalizeGlitchtipDsn('not-a-dsn')).toBe('not-a-dsn');
	});
});

describe('breadcrumbs', () => {
	it('drops console breadcrumbs entirely (existing routes console.log PII)', () => {
		const event: ScrubEvent = {
			breadcrumbs: [
				{ category: 'console', message: `sending to ${EMAIL}` },
				{ category: 'http', message: 'GET /api/contact', data: { status: 500 } },
			],
		};
		const out = createBeforeSend()(event)!;
		expect(out.breadcrumbs).toHaveLength(1);
		expect(out.breadcrumbs![0].category).toBe('http');
		expect(jsonHas(out.breadcrumbs, EMAIL)).toBe(false);
	});

	it('beforeBreadcrumb drops a console crumb and masks email in a kept crumb', () => {
		const bc = createBeforeBreadcrumb();
		expect(bc({ category: 'console', message: EMAIL })).toBeNull();
		const kept = bc({ category: 'navigation', message: `user ${EMAIL} navigated` })!;
		expect(kept.message).not.toContain(EMAIL);
		expect(kept.message).toContain('[email]');
	});
});

describe('stack-frame locals', () => {
	it('redacts salary sitting in a frame local var', () => {
		const event: ScrubEvent = {
			exception: {
				values: [
					{
						stacktrace: {
							frames: [
								{ function: 'POST', vars: { email: EMAIL, parsedSalary: SALARY, status: 422 } },
							],
						},
					},
				],
			},
		};
		expect(jsonHas(event, SALARY)).toBe(true);
		const out = createBeforeSend()(event)!;
		expect(jsonHas(out, SALARY)).toBe(false);
		expect(jsonHas(out, EMAIL)).toBe(false);
	});

	it('masks format-detectable PII in captured source-context lines (context_line / pre/post_context)', () => {
		const event: ScrubEvent = {
			exception: {
				values: [
					{
						stacktrace: {
							frames: [
								{
									pre_context: [`const email = '${EMAIL}';`],
									context_line: `throw new Error('failed for ${EMAIL}');`,
									post_context: ['return;'],
								},
							],
						},
					},
				],
			},
		};
		const out = createBeforeSend()(event)!;
		const f = out.exception!.values![0].stacktrace!.frames![0];
		expect(jsonHas(f, EMAIL)).toBe(false);
		expect(f.context_line).toContain('[email]');
		expect((f.pre_context as string[])[0]).toContain('[email]');
	});

	it('drops the raw POST body held in a frame local named `raw`', () => {
		const event: ScrubEvent = {
			exception: {
				values: [{ stacktrace: { frames: [{ vars: { raw: `{"salary":${SALARY}}` } }] } }],
			},
		};
		const out = createBeforeSend()(event)!;
		const vars = out.exception!.values![0].stacktrace!.frames![0].vars!;
		expect(vars.raw).toBe(REDACTED);
	});
});

describe('numeric key-path allowlist', () => {
	it('catches salary under an UNEXPECTED key (reductionSteps[0])', () => {
		// salary nested as an array element under a non-safe key
		const event: ScrubEvent = {
			extra: { lead: { reductionSteps: [SALARY, 90] } },
		};
		expect(jsonHas(event, SALARY)).toBe(true);
		const out = createBeforeSend()(event)!;
		expect(jsonHas(out, SALARY)).toBe(false);
		// the second element (also unsafe key) is redacted too
		expect((out.extra as any).lead.reductionSteps[0]).toBe(REDACTED_NUM);
	});

	it('PRESERVES HTTP status + timing numbers (allowlist keeps debug data)', () => {
		const event: ScrubEvent = {
			extra: { status: 500, statusCode: 500, durationMs: 1234, count: 3, line: 42 },
		};
		const out = createBeforeSend()(event)!;
		const extra = out.extra as Record<string, number>;
		expect(extra.status).toBe(500);
		expect(extra.statusCode).toBe(500);
		expect(extra.durationMs).toBe(1234);
		expect(extra.count).toBe(3);
		expect(extra.line).toBe(42);
	});

	it('redacts an unknown numeric key but keeps an allowlisted sibling', () => {
		const out = scrubValue({ mysteryAmount: SALARY, status: 200 }, 'extra') as Record<string, unknown>;
		expect(out.mysteryAmount).toBe(REDACTED_NUM);
		expect(out.status).toBe(200);
	});
});

describe('format masking', () => {
	it('masks email / AHV / IBAN inside free strings', () => {
		const event: ScrubEvent = {
			message: `error for ${EMAIL}, AHV 756.1234.5678.97, IBAN CH9300762011623852957`,
		};
		const out = createBeforeSend()(event)!;
		const msg = out.message as string;
		expect(msg).toContain('[email]');
		expect(msg).toContain('[ahv]');
		expect(msg).toContain('[iban]');
		expect(msg).not.toContain(EMAIL);
	});
});

describe('fail-closed', () => {
	it('returns null (drops the event) when scrubbing throws', () => {
		// a getter that throws mid-traversal simulates an unexpected event shape
		const event = {
			extra: Object.defineProperty({}, 'boom', {
				enumerable: true,
				get() {
					throw new Error('explode');
				},
			}),
		} as unknown as ScrubEvent;
		expect(createBeforeSend()(event)).toBeNull();
	});

	it('passes through null/undefined events unchanged', () => {
		expect(createBeforeSend()(null)).toBeNull();
	});
});
