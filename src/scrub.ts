// @noelboss/sentry-scrub — PII scrubber for Sentry/GlitchTip events (server-side only).
//
// Scrubs EVERY channel an event carries PII in, not just request data:
//   1. request data / cookies / Authorization headers / query string
//   2. console breadcrumbs (dropped) + breadcrumb data
//   3. stack-frame locals (`exception.values[].stacktrace.frames[].vars`)
//      and `extra` / `contexts`
//   4. numeric values by a key-path allowlist — salary is NOT regex-detectable
//      (a bare 4-5 digit int looks like any number), so numbers are DROPPED
//      unless their key is known-safe; this catches salary under an unexpected
//      key (e.g. `reductionSteps[0]`). Format-detectable fields (email / IBAN /
//      AHV) are masked on top.
//
// Fail-closed wrapping lives in index.ts: any throw here → the event is dropped,
// never sent raw.

export const REDACTED = '[redacted]';
export const REDACTED_NUM = '[redacted:num]';

// Structural Sentry shapes — typed locally so the package has ZERO runtime
// dependency on a specific @sentry/* version (the event shape is stable across
// @sentry/node and @sentry/nextjs, both built on @sentry/core).
export interface ScrubFrame {
	vars?: Record<string, unknown>;
	context_line?: unknown;
	pre_context?: unknown;
	post_context?: unknown;
	[k: string]: unknown;
}
export interface ScrubException {
	type?: unknown;
	value?: unknown;
	stacktrace?: { frames?: ScrubFrame[] };
	[k: string]: unknown;
}
export interface ScrubBreadcrumb {
	category?: string;
	message?: unknown;
	data?: Record<string, unknown>;
	[k: string]: unknown;
}
export interface ScrubEvent {
	request?: Record<string, unknown>;
	exception?: { values?: ScrubException[] };
	extra?: Record<string, unknown>;
	contexts?: Record<string, unknown>;
	breadcrumbs?: ScrubBreadcrumb[];
	user?: Record<string, unknown>;
	message?: unknown;
	[k: string]: unknown;
}

// Keys whose VALUE is always PII or a secret → redact entirely (string OR number).
// `raw`/`body`/`payload` cover the stringified POST body in frame locals, where a
// JSON blob like `{"salary":50000}` is not key-path-analysable and salary inside
// it is not regex-detectable — so the whole blob is dropped.
const DENY_KEY_RE =
	/^(?:e?mail|phone|tel|telefon|mobile|handy|name|vorname|nachname|firstname|lastname|fullname|displayname|password|passwort|pwd|secret|token|authorization|auth|cookie|session|sessionid|apikey|dsn|salary|salaer|salär|saläre|brutto|bruttolohn|nettolohn|lohn|gehalt|einkommen|income|wage|iban|ahv|ahvnr|svnr|geburtsdatum|geburtstag|birthdate|birthday|dob|address|adresse|strasse|street|plz|zip|postalcode|ssn|consent|raw|body|rawbody|requestbody|payload)$/i;

// Keys under which a NUMBER is debug data worth keeping. Everything else numeric
// is dropped. Deliberately tight: keeps HTTP status + timings + positions (the
// data that makes an error debuggable) and nothing domain-specific that could
// carry salary/age. Reviewed when a new numeric debug field is added.
const SAFE_NUM_KEYS = new Set<string>([
	'status', 'statuscode', 'httpstatus', 'code', 'statusgroup',
	'line', 'lineno', 'colno', 'column', 'col',
	'count', 'length', 'size', 'index', 'idx', 'offset', 'limit', 'page', 'pages', 'total',
	'durationms', 'duration', 'dauer', 'ms', 'elapsed', 'elapsedms', 'latency',
	'timeout', 'timeoutms', 'ttl', 'maxage',
	'retries', 'retry', 'attempt', 'attempts',
	'port', 'pid', 'version',
]);

// Format-detectable PII inside free strings.
const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
const AHV_RE = /\b756[.\s]?\d{4}[.\s]?\d{4}[.\s]?\d{2}\b/g;
const IBAN_RE = /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){10,30}\b/g;
// Secret query params (incl. the CMS live-preview `?token=` param). The leading
// `(?:[?&]|^)` is load-bearing: Sentry/GlitchTip delivers `request.query_string`
// WITHOUT a leading `?`, so the first param (e.g. `token=…`) sits at start-of-
// string — `[?&]` alone would miss it and leak the secret. `^` only matches once
// (no `m` flag); subsequent params are caught by the `[?&]` alternative.
const SECRET_QS_RE =
	/(^|[?&])(token|secret|password|pwd|apikey|api_key|auth|dsn|sig|signature|preview)=[^&#]*/gi;

const MAX_DEPTH = 8;

// GlitchTip issues ProjectKey public keys as DASHED UUIDs (`053703c0-1bdf-…`),
// but the Sentry SDK DSN parser matches the public key with `(\w+)` — `\w`
// excludes `-`, so a dashed key yields "Invalid Sentry Dsn" and the transport is
// DISABLED (zero events sent, silently). GlitchTip accepts the de-dashed 32-hex
// form on ingest (same 128-bit value), so strip dashes from the public-key
// segment only — host/path/secret untouched. Returns the input unchanged if it
// is not a parseable DSN. Idempotent. Apply to every GlitchTip DSN before init.
export function normalizeGlitchtipDsn(dsn: string | undefined): string | undefined {
	if (!dsn) return dsn;
	const m = /^(\w+:\/\/)([^:@/]+)(:[^@/]*)?(@.+)$/.exec(dsn);
	if (!m) return dsn;
	const [, proto, key, secret = '', rest] = m;
	return `${proto}${(key as string).replace(/-/g, '')}${secret}${rest}`;
}

export function maskString(s: string): string {
	return s
		.replace(SECRET_QS_RE, '$1$2=[stripped]')
		.replace(EMAIL_RE, '[email]')
		.replace(AHV_RE, '[ahv]')
		.replace(IBAN_RE, '[iban]');
}

function normKey(key: string | number): string {
	return String(key).toLowerCase().replace(/[^a-z0-9]/g, '');
}

// Recursively scrub a value. `key` is the key the value sits under — array
// elements inherit their array's key, so a salary number inside
// `reductionSteps: [50000]` is judged under `reductionSteps` (unsafe) → dropped.
export function scrubValue(value: unknown, key: string | number, depth = 0): unknown {
	if (depth > MAX_DEPTH) return REDACTED;
	const nk = normKey(key);

	if (nk && DENY_KEY_RE.test(nk)) {
		return typeof value === 'number' || typeof value === 'bigint' ? REDACTED_NUM : REDACTED;
	}

	if (value === null || value === undefined) return value;

	switch (typeof value) {
		case 'number':
		case 'bigint':
			return SAFE_NUM_KEYS.has(nk) ? value : REDACTED_NUM;
		case 'boolean':
			return value;
		case 'string':
			return maskString(value);
		case 'object': {
			if (Array.isArray(value)) {
				return value.map((v) => scrubValue(v, key, depth + 1));
			}
			const out: Record<string, unknown> = {};
			for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
				out[k] = scrubValue(v, k, depth + 1);
			}
			return out;
		}
		default:
			return REDACTED; // function / symbol
	}
}

export function scrubBreadcrumb(b: ScrubBreadcrumb): ScrubBreadcrumb {
	if (typeof b.message === 'string') b.message = maskString(b.message);
	if (b.data && typeof b.data === 'object') {
		b.data = scrubValue(b.data, 'data') as Record<string, unknown>;
	}
	return b;
}

export function scrubEvent(event: ScrubEvent): ScrubEvent {
	// 1. request data / cookies / headers / query string
	const req = event.request;
	if (req && typeof req === 'object') {
		if ('data' in req) {
			// drop raw string bodies wholesale; scrub structured form data field-wise
			req.data = typeof req.data === 'string' ? REDACTED : scrubValue(req.data, 'data');
		}
		if ('cookies' in req) req.cookies = REDACTED;
		const headers = req.headers;
		if (headers && typeof headers === 'object') {
			for (const name of Object.keys(headers as Record<string, unknown>)) {
				const ln = name.toLowerCase();
				const h = headers as Record<string, unknown>;
				h[name] =
					ln === 'authorization' || ln === 'cookie' || ln === 'proxy-authorization' || ln === 'x-api-key'
						? REDACTED
						: scrubValue(h[name], name);
			}
		}
		if ('query_string' in req) req.query_string = scrubValue(req.query_string, 'query');
	}

	// 2. exception message + stack-frame locals. The Error message
	// (`exception.values[].value`) is the channel GlitchTip derives the issue
	// title / `metadata.value` from — an interpolated `Error(`… ${email} …`)`
	// leaks there even though request data + frame locals are scrubbed. maskString
	// strips format-detectable PII (email / IBAN / AHV / secret query params).
	// NOTE: a bare PII NUMBER baked into a message string (e.g. `salary=84500`) is
	// NOT regex-detectable and cannot be masked here — do not interpolate raw
	// numeric PII into Error messages; keep it in structured locals/extra/request
	// where the key-path allowlist catches it.
	const values = event.exception?.values;
	if (Array.isArray(values)) {
		for (const ex of values) {
			if (typeof ex.value === 'string') ex.value = maskString(ex.value);
			if (typeof ex.type === 'string') ex.type = maskString(ex.type);
			const frames = ex?.stacktrace?.frames;
			if (Array.isArray(frames)) {
				for (const f of frames) {
					if (f && f.vars && typeof f.vars === 'object') {
						f.vars = scrubValue(f.vars, 'vars') as Record<string, unknown>;
					}
					// Source-context lines (the code around the throw) are captured
					// verbatim — a hardcoded email/IBAN/AHV/secret literal in source
					// would leak here even though runtime vars are scrubbed. maskString
					// the format-detectable PII; line numbers live elsewhere, untouched.
					if (f && typeof f.context_line === 'string') f.context_line = maskString(f.context_line);
					if (f && Array.isArray(f.pre_context))
						f.pre_context = f.pre_context.map((l) => (typeof l === 'string' ? maskString(l) : l));
					if (f && Array.isArray(f.post_context))
						f.post_context = f.post_context.map((l) => (typeof l === 'string' ? maskString(l) : l));
				}
			}
		}
	}

	// 3. extra / contexts
	if (event.extra && typeof event.extra === 'object') {
		event.extra = scrubValue(event.extra, 'extra') as Record<string, unknown>;
	}
	if (event.contexts && typeof event.contexts === 'object') {
		event.contexts = scrubValue(event.contexts, 'contexts') as Record<string, unknown>;
	}

	// 4. user — keep id only (sendDefaultPii:false should already strip, belt + braces)
	if (event.user && typeof event.user === 'object') {
		event.user = event.user.id !== undefined ? { id: event.user.id } : {};
	}

	// 5. breadcrumbs — drop console (existing routes log PII via console.*), scrub rest
	if (Array.isArray(event.breadcrumbs)) {
		event.breadcrumbs = event.breadcrumbs
			.filter((b) => b?.category !== 'console')
			.map((b) => scrubBreadcrumb(b));
	}

	// 6. top-level message
	if (typeof event.message === 'string') event.message = maskString(event.message);

	return event;
}
