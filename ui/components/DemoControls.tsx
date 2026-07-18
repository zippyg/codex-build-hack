"use client";

import type { DemoControls as Controls } from "@/lib/useEventStream";
import type { Beat } from "@/lib/state";

const BEATS: { n: Beat; label: string }[] = [
  { n: 1, label: "App" },
  { n: 2, label: "Scan" },
  { n: 3, label: "Compile" },
  { n: 4, label: "Judge" },
  { n: 5, label: "Swap" },
  { n: 6, label: "Guard" },
];

const btn =
  "rounded-md border px-3 py-1.5 font-mono text-xs uppercase tracking-wide transition-colors";

export function DemoControls({ controls, beat }: { controls: Controls; beat: Beat }) {
  if (controls.playing === undefined) return null;
  const playLabel = controls.playing ? "Pause" : controls.atEnd ? "Replay" : "Play";
  return (
    <div
      data-testid="controls"
      className="flex h-16 shrink-0 items-center gap-2 border-t border-white/10 bg-ink px-6"
    >
      <button
        onClick={controls.restart}
        className={`${btn} border-white/10 text-fg/60 hover:border-white/25 hover:text-fg`}
      >
        Restart
      </button>
      <button
        onClick={controls.toggle}
        data-testid="playpause"
        className={`${btn} min-w-[84px] border-emerald-400/40 bg-emerald-400/10 text-emerald-300 hover:bg-emerald-400/20`}
      >
        {playLabel}
      </button>
      <div className="mx-2 h-6 w-px bg-white/10" />
      <span className="mr-1 font-mono text-[11px] uppercase tracking-wide text-fg/35">
        Jump to
      </span>
      {BEATS.map(({ n, label }) => {
        const active = beat === n;
        return (
          <button
            key={n}
            onClick={() => controls.seekBeat(n)}
            aria-current={active}
            className={`${btn} ${
              active
                ? "border-white/30 bg-white/10 text-fg"
                : "border-white/10 text-fg/55 hover:border-white/20 hover:text-fg"
            }`}
          >
            <span className="tabular-nums text-fg/40">{n}</span>&nbsp;{label}
          </button>
        );
      })}
    </div>
  );
}
