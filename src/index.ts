// @noelboss/sentry-scrub — public API.
//
// FAIL-CLOSED: the consuming app imports this at the top of its Sentry init file
// so it resolves BEFORE `Sentry.init()` runs. If scrubbing throws for any reason,
// `beforeSend` returns null (the event is dropped) — a captured error must never
// become the leak we were preventing.
//
//   import { createBeforeSend, createBeforeBreadcrumb } from '@noelboss/sentry-scrub';
//   Sentry.init({
//     dsn: process.env.VRM_GLITCHTIP_DSN_FRONTEND,
//     sendDefaultPii: false,
//     tracesSampleRate: 0,
//     beforeSend: createBeforeSend(),
//     beforeBreadcrumb: createBeforeBreadcrumb(),
//   });

import {
	scrubEvent,
	scrubBreadcrumb,
	type ScrubEvent,
	type ScrubBreadcrumb,
} from './scrub.js';

export {
	scrubEvent,
	scrubBreadcrumb,
	scrubValue,
	maskString,
	normalizeGlitchtipDsn,
	REDACTED,
	REDACTED_NUM,
	type ScrubEvent,
	type ScrubBreadcrumb,
} from './scrub.js';

export function createBeforeSend(): (event: ScrubEvent | null) => ScrubEvent | null {
	return function beforeSend(event) {
		try {
			if (!event) return event;
			return scrubEvent(event);
		} catch {
			return null; // fail closed
		}
	};
}

export function createBeforeBreadcrumb(): (b: ScrubBreadcrumb | null) => ScrubBreadcrumb | null {
	return function beforeBreadcrumb(breadcrumb) {
		try {
			if (!breadcrumb) return breadcrumb;
			if (breadcrumb.category === 'console') return null; // PII rides along on console crumbs
			return scrubBreadcrumb(breadcrumb);
		} catch {
			return null; // fail closed
		}
	};
}
