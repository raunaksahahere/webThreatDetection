import { useEffect, useState } from 'react';
import { Wallet } from 'lucide-react';
import { MOCK_MODE, healthInfo } from '../api';
import { chainStatus, type ChainStatus } from '../chain';
import { Notice } from './Section';

export function useChainStatus(): ChainStatus {
  const [status, setStatus] = useState<ChainStatus>({ kind: 'unknown' });
  useEffect(() => {
    let alive = true;
    healthInfo()
      .then((h) => alive && setStatus(chainStatus(h)))
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, []);
  return status;
}

const NO_WALLET = 'You can investigate links and messages without connecting or funding a wallet.';

/** Free-demo notice shown where users meet blockchain reporting. Wording follows what the server actually reports. */
export function DemoModeNotice({ status }: { status: ChainStatus }) {
  if (status.kind === 'unknown') return null;
  if (status.kind === 'sepolia' || status.kind === 'other') {
    const net = status.kind === 'sepolia' ? 'the public Ethereum Sepolia test network (test ETH only, no real money)' : `chain ${status.chainId}`;
    return (
      <Notice tone="info" title="Blockchain status">
        <p>
          Reports are registered on {net}
          {status.contract ? (
            <>
              {' '}
              at contract <code className="mono">{status.contract}</code>
            </>
          ) : null}
          . No wallet is needed to use this site: the server signs registrations, and registering, revising and reviewing need the operator token.
        </p>
        <p>Reading a registered report and verifying it independently need no wallet and no token.</p>
      </Notice>
    );
  }
  const where =
    status.kind === 'local'
      ? 'Registration here is written to a local Anvil chain inside this server: it is not public, nobody else can check it, and it is reset when the server restarts.'
      : status.kind === 'unavailable'
        ? status.reason
        : 'Blockchain reporting and verification are implemented and tested locally.';
  return (
    <Notice tone="info" title="Free demonstration mode">
      <p>{NO_WALLET}</p>
      <p>{where}</p>
      <p>
        {status.kind === 'local' ? 'Blockchain reporting and verification are implemented and tested locally. ' : ''}
        Public Sepolia reporting is awaiting deployment and configuration (a deployed contract, configured roles and free Sepolia test ETH for the signing accounts). No purchase of real cryptocurrency is required.
      </p>
    </Notice>
  );
}

/** The reason an unavailable transaction action is disabled, placed right beside it and referenced by aria-describedby. */
export function ActionReason({ id, status }: { id: string; status: ChainStatus }) {
  if (!('reason' in status)) return null;
  return (
    <p id={id} className="action-reason" role="note">
      {status.reason}
    </p>
  );
}

/** One line on the intake page. Investigating never asks for a wallet. */
export function NoWalletLine() {
  const status = useChainStatus();
  if (MOCK_MODE || status.kind === 'unknown') return null;
  return (
    <p className="field-help no-wallet-line">
      <Wallet size={14} aria-hidden />
      <span>No wallet needed: investigating links and messages never asks you to connect or fund one.</span>
    </p>
  );
}
