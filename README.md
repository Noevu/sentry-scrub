# @noevu/sentry-scrub

Fail-closed PII scrubber for **Sentry / GlitchTip** events. Server-side only. Used
across the Noevu fleet so that error traces never carry personal data — salary,
income, AHV numbers, emails, IBANs, names, cookies, auth headers, or secret query
params (incl. CMS live-preview `?token=`).

## Why

A captured error must never become the leak you were preventing. A naïve
`beforeSend` that only filters request bodies leaves PII in **other channels** of
the same event. This scrubber covers all of them and **fails closed** — if scrubbing
throws for any reason, the event is dropped rather than sent raw.

## Install

```sh
npm install @noevu/sentry-scrub
```

`.npmrc` (the package lives on GitHub Packages under the Noevu org):

```
@noevu:registry=https://npm.pkg.github.com
```

## Use

```js
import * as Sentry from '@sentry/node'; // or @sentry/nextjs
import { createBeforeSend, createBeforeBreadcrumb, normalizeGlitchtipDsn } from '@noevu/sentry-scrub';

Sentry.init({
  dsn: normalizeGlitchtipDsn(process.env.GLITCHTIP_DSN),
  sendDefaultPii: false,
  tracesSampleRate: 0,
  beforeSend: createBeforeSend(),
  beforeBreadcrumb: createBeforeBreadcrumb(),
});
```

Import it at the **top** of your init file so it resolves before `Sentry.init()`.

## What it scrubs

- **Request data** — bodies dropped, form fields (incl. salary/income) stripped,
  cookies + `Authorization` removed, secret query params (`token`/`secret`/… incl.
  start-of-string) masked.
- **Console breadcrumbs** — dropped (existing routes often `console.log` PII).
- **Stack-frame locals / `extra` / `contexts`** — numbers redacted unless under a
  known-safe debug key (`status`, `durationMs`, `line`, …); a bare salary number is
  not regex-detectable, so unknown numeric keys are dropped.
- **Exception message** (`exception.values[].value` — GlitchTip's issue title) and
  **source-context lines** — email / IBAN / AHV masked.
- Format-detectable PII — `email`, `IBAN`, Swiss `AHV` (`756.xxxx.xxxx.xx`).

`normalizeGlitchtipDsn` de-dashes GlitchTip's UUID public key — the Sentry SDK DSN
parser uses `(\w+)`, which rejects `-`, silently disabling the transport.

> A bare numeric PII value baked into an Error **message string** (e.g.
> `Error("salary=84500")`) is NOT regex-detectable and cannot be masked — keep
> numeric PII in structured locals/extra/request, where the key-path allowlist
> catches it.

## License

MIT
