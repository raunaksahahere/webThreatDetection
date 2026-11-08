import { defang } from '../format';
import { CopyButton } from './CopyButton';

/**
 * A URL from analysed content: shown defanged as plain text, never as a link.
 * The copy button copies the exact value (for sandboxes and blocklists).
 */
export function SafeUrl({ value, alreadyDefanged = false, wrap = true }: { value: string; alreadyDefanged?: boolean; wrap?: boolean }) {
  const shown = alreadyDefanged ? value : defang(value);
  return (
    <span className={`safe-url ${wrap ? 'wrap' : ''}`}>
      <code className="mono" title="Defanged for display. Not a link.">
        {shown}
      </code>
      <CopyButton value={value} label="Copy exact value (do not open it in a browser)" />
    </span>
  );
}
