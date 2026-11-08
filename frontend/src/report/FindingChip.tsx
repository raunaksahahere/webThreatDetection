export function FindingChip({ id, known, onFocus }: { id: string; known: boolean; onFocus: (id: string) => void }) {
  if (!known)
    return (
      <span className="finding-chip is-unknown mono" title="This finding ID does not exist in the report">
        {id}
      </span>
    );
  return (
    <button type="button" className="finding-chip mono" onClick={() => onFocus(id)} title="Show this finding">
      {id}
    </button>
  );
}
