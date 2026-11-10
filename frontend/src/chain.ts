import type { Health } from './types';

/**
 * What the dashboard may truthfully say about blockchain reporting, derived only from /api/health.
 * Nothing here invents an address or a deployment: addresses come from the server, and the public-network wording
 * appears only when the server reports a connected Sepolia deployment.
 */
export type ChainStatus =
  | { kind: 'unknown' } // health not loaded or unreachable: make no claim, disable nothing
  | { kind: 'pending'; writesBlocked: true; reason: string } // no deployment configured: public registration is not set up
  | { kind: 'unavailable'; writesBlocked: true; reason: string } // a deployment exists but the chain is not usable right now
  | { kind: 'local'; writesBlocked: false; chainId: number; contract: string | null }
  | { kind: 'sepolia'; writesBlocked: false; chainId: number; contract: string | null }
  | { kind: 'other'; writesBlocked: false; chainId: number; contract: string | null };

export const SEPOLIA_CHAIN_ID = 11155111;
export const LOCAL_CHAIN_ID = 31337;

export const PENDING_REASON = 'Public on-chain registration is pending Sepolia setup. You can still use the investigation features.';

const UNAVAILABLE: Record<string, string> = {
  rpc_unreachable: 'The configured blockchain could not be reached right now.',
  chain_mismatch: 'The connected blockchain does not match the configured deployment.',
  no_contract_code: 'No registry contract was found at the configured address (the chain may have been reset).',
  not_built: 'The registry contract has not been built on this server.',
  not_configured: 'Signing keys for this blockchain are not configured on the server.',
};

export function chainStatus(h: Health | null | undefined): ChainStatus {
  const c = h?.chain;
  if (!h || !c) return { kind: 'unknown' };
  if (c.connected && typeof c.chain_id === 'number') {
    const base = { chainId: c.chain_id, contract: c.contract ?? null, writesBlocked: false as const };
    if (c.chain_id === LOCAL_CHAIN_ID) return { kind: 'local', ...base };
    if (c.chain_id === SEPOLIA_CHAIN_ID) return { kind: 'sepolia', ...base };
    return { kind: 'other', ...base };
  }
  if (c.connected === false) {
    if (c.kind === 'not_deployed') return { kind: 'pending', writesBlocked: true, reason: PENDING_REASON };
    return {
      kind: 'unavailable',
      writesBlocked: true,
      reason: `${UNAVAILABLE[c.kind ?? ''] ?? 'The blockchain is not available right now.'} Registration is unavailable until it is; the investigation features are not affected.`,
    };
  }
  return { kind: 'unknown' };
}
