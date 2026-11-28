import type { SnapshotSummary } from "../types/api";

interface ScoreTrendChartProps {
  readonly snapshots: readonly SnapshotSummary[];
}

export function ScoreTrendChart({ snapshots }: ScoreTrendChartProps) {
  const points = [...snapshots]
    .reverse()
    .filter((s): s is SnapshotSummary & { hardening_index: number } => s.hardening_index !== null);

  if (points.length === 0) {
    return (
      <p className="text-sm text-slate-400">
        Aún no hay puntaje Lynis histórico registrado para este servidor.
      </p>
    );
  }

  const width = 560;
  const height = 140;
  const padX = 28;
  const padY = 18;
  const innerW = width - padX * 2;
  const innerH = height - padY * 2;

  const coords = points.map((snap, idx) => {
    const x =
      points.length === 1
        ? padX + innerW / 2
        : padX + (idx / (points.length - 1)) * innerW;
    const clamped = Math.max(0, Math.min(100, snap.hardening_index));
    const y = padY + innerH - (clamped / 100) * innerH;
    return { x, y, score: clamped, date: snap.collected_at.slice(0, 10) };
  });

  const polyline = coords.map((c) => `${c.x.toFixed(1)},${c.y.toFixed(1)}`).join(" ");

  return (
    <div className="space-y-2">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="h-36 w-full rounded border border-slate-800 bg-slate-950"
        role="img"
        aria-label={`Evolución del puntaje Lynis en ${points.length} snapshots`}
      >
        {[25, 50, 75, 100].map((mark) => {
          const y = padY + innerH - (mark / 100) * innerH;
          return (
            <g key={mark}>
              <line
                x1={padX}
                x2={width - padX}
                y1={y}
                y2={y}
                stroke="#1e293b"
                strokeDasharray="3 3"
              />
              <text x={4} y={y + 4} fontSize="10" fill="#94a3b8">
                {mark}
              </text>
            </g>
          );
        })}
        {coords.length > 1 && (
          <polyline
            fill="none"
            stroke="#38bdf8"
            strokeWidth="2.5"
            points={polyline}
          />
        )}
        {coords.map((c, idx) => (
          <g key={`${c.date}-${idx}`}>
            <circle cx={c.x} cy={c.y} r="4" fill="#38bdf8" stroke="#090e1a" strokeWidth="1.5" />
            <text
              x={c.x}
              y={c.y - 8}
              textAnchor="middle"
              fontSize="10"
              fill="#f8fafc"
              className="font-mono"
            >
              {c.score}
            </text>
          </g>
        ))}
      </svg>
      <div className="flex flex-wrap justify-between text-xs text-slate-400 tabular-nums">
        <span>Inicio: {coords[0]?.date}</span>
        <span>Último: {coords[coords.length - 1]?.date}</span>
      </div>
    </div>
  );
}
