import { useEffect, useState } from 'react';
import { Gauge } from 'lucide-react';
import { MOCK_MODE, accessInfo, getQuota } from '../api';
import type { AccessInfo, QuotaInfo } from '../types';

export function useAccess(): AccessInfo | null {
  const [access, setAccess] = useState<AccessInfo | null>(null);
  useEffect(() => {
    let alive = true;
    accessInfo()
      .then((a) => alive && setAccess(a))
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, []);
  return access;
}

/** Shown on every page when the server runs as an open public demo. */
export function PublicDemoBanner() {
  const access = useAccess();
  if (MOCK_MODE || access?.mode !== 'public_demo') return null;
  return (
    <div className="public-banner" role="note">
      <strong>PUBLIC DEMO</strong>
      <span>
        No sign-in needed. Up to {access.session_limit ?? '?'} analyses per browser session. Everything submitted here is visible to other visitors and is wiped when the server restarts, so do not paste private information.
      </span>
    </div>
  );
}

/** "N of M analyses left in this browser session" under the intake form (public demo only). */
export function QuotaLine() {
  const access = useAccess();
  const [quota, setQuota] = useState<QuotaInfo | null>(null);
  useEffect(() => {
    if (access?.mode !== 'public_demo') return;
    let alive = true;
    getQuota()
      .then((q) => alive && setQuota(q))
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, [access]);
  if (!quota?.public_demo || quota.operator || !quota.session || !quota.daily) return null;
  const { session, daily } = quota;
  const left = Math.min(session.remaining, daily.remaining);
  return (
    <p className={`field-help intake-quota ${left === 0 ? 'is-empty' : ''}`} role="status">
      <Gauge size={14} aria-hidden />
      <span>
        {left === 0
          ? daily.remaining === 0
            ? `Daily limit reached (${daily.limit} analyses per visitor per day). Try again tomorrow.`
            : `Session limit reached (${session.limit} analyses per browser session).`
          : `${left} of ${session.limit} analyses left in this browser session${daily.remaining < session.remaining ? ` (${daily.remaining} left today)` : ''}.`}
      </span>
    </p>
  );
}
