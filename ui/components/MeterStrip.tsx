"use client";

import { useEffect, useRef, useState } from "react";
import { animate } from "motion";
import { p50, type DashState, type TrafficSample } from "@/lib/state";
import { cn } from "@/lib/utils";

function Sparkline({ samples, swapped }: { samples: TrafficSample[]; swapped: boolean }) {
  const W = 400;
  const H = 84;
  const MAX = 1300; // honest fixed scale: the cliff must be a cliff, not a rescale
  if (samples.length < 2) return <svg viewBox={`0 0 ${W} ${H}`} className="h-full w-full" />;
  const pts = samples.map((s, i) => ({
    x: (i / (samples.length - 1)) * (W - 4) + 2,
    y: H - 4 - (Math.min(s.latencyMs, MAX) / MAX) * (H - 10),
    compiled: s.source === "compiled",
  }));
  const firstCompiled = pts.findIndex((p) => p.compiled);
  const llmPts = firstCompiled === -1 ? pts : pts.slice(0, firstCompiled + 1);
  const compiledPts = firstCompiled === -1 ? [] : pts.slice(Math.max(firstCompiled - 1, 0));
  const line = (ps: typeof pts) => ps.map((p) => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(" ");
  return (
    <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="h-full w-full">
      <polyline
        points={line(llmPts)}
        fill="none"
        stroke="rgba(231,231,234,0.45)"
        strokeWidth="2.5"
      />
      {compiledPts.length > 1 && (
        <polyline points={line(compiledPts)} fill="none" stroke="#22C55E" strokeWidth="2.5" />
      )}
      {swapped && compiledPts.length > 0 && (
        <circle
          cx={compiledPts[compiledPts.length - 1].x}
          cy={compiledPts[compiledPts.length - 1].y}
          r="3.5"
          fill="#22C55E"
        />
      )}
    </svg>
  );
}

const usd = (v: number, dp = 4) => `$${v.toFixed(dp)}`;

export function MeterStrip({ state }: { state: DashState }) {
  const [crashed, setCrashed] = useState(false);
  const [animVal, setAnimVal] = useState<number | null>(null);
  const fired = useRef(false);

  const llmP50 = p50(state.traffic, "llm");
  const compiledP50 = p50(state.traffic, "compiled");
  const afterMs = state.swap?.afterMs ?? compiledP50 ?? 3;

  useEffect(() => {
    if (!state.swapped || fired.current) return;
    fired.current = true;
    setCrashed(true);
    const from = llmP50 ?? state.swap?.beforeMs ?? 912;
    // THE hero animation: 800ms spring drop with slight overshoot, then settle.
    const controls = animate(from, afterMs, {
      type: "spring",
      duration: 0.8,
      bounce: 0.28,
      onUpdate: (v) => setAnimVal(Math.max(0, v)),
    });
    controls.then(() => setAnimVal(null));
    return () => controls.stop();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.swapped]);

  const latencyShown =
    animVal !== null ? animVal : crashed ? (compiledP50 ?? afterMs) : (llmP50 ?? null);

  const lastCost = state.traffic.length
    ? state.traffic[state.traffic.length - 1].costUsd
    : null;
  const costPerReq = crashed ? 0 : lastCost;
  const cumulative = state.frozenCost ?? state.cumulativeCost;

  return (
    <section className="grid h-[22vh] min-h-40 shrink-0 grid-cols-[7fr_5fr] border-b border-hairline">
      <div className="flex items-center gap-8 border-r border-hairline px-8">
        <div className="shrink-0">
          <div className="font-mono text-[13px] tracking-[0.3em] text-muted">P50 LATENCY</div>
          <div className="flex items-baseline gap-2">
            <span
              data-testid="latency-value"
              className={cn(
                "tnum font-mono text-[clamp(56px,11vh,120px)] leading-[1.05] font-medium",
                crashed ? "meter-crashed text-go" : "text-fg",
              )}
            >
              {latencyShown === null ? "·" : Math.round(latencyShown).toLocaleString()}
            </span>
            <span
              className={cn(
                "font-mono text-[clamp(20px,3.2vh,34px)]",
                crashed ? "text-go/70" : "text-muted",
              )}
            >
              ms
            </span>
          </div>
        </div>
        <div className="h-[11vh] min-w-0 flex-1 self-end pb-3">
          <Sparkline samples={state.traffic} swapped={state.swapped} />
        </div>
      </div>

      <div className="flex items-center gap-10 px-8">
        <div>
          <div className="font-mono text-[13px] tracking-[0.3em] text-muted">COST / REQ</div>
          <span
            data-testid="cost-per-req"
            className={cn(
              "tnum font-mono text-[clamp(40px,8.6vh,96px)] leading-[1.05] font-medium",
              crashed ? "text-go" : "text-fg",
            )}
          >
            {costPerReq === null ? "·" : usd(costPerReq)}
          </span>
        </div>
        <div>
          <div className="font-mono text-[13px] tracking-[0.3em] text-muted">TODAY</div>
          <div className="relative inline-block">
            <span
              data-testid="cum-cost"
              className={cn(
                "tnum font-mono text-[clamp(22px,4vh,40px)] leading-tight",
                state.frozenCost !== null ? "text-muted/30" : "text-fg",
              )}
            >
              {usd(cumulative, 2)}
            </span>
            {state.frozenCost !== null && (
              <span
                data-testid="frozen-stamp"
                className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 -rotate-12 rounded border-2 border-go/70 bg-ink/60 px-2.5 py-0.5 font-mono text-[13px] font-bold tracking-[0.24em] text-go whitespace-nowrap"
              >
                FROZEN
              </span>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
