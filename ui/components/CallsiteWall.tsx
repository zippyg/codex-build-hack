"use client";

import { motion } from "motion/react";
import type { CallsiteState, DashState } from "@/lib/state";
import { cn } from "@/lib/utils";

const KIND_LABEL = { structured: "STRUCTURED", classifier: "CLASSIFIER", freeform: "FREEFORM" };

function VerdictBadge({ cs }: { cs: CallsiteState }) {
  const v = cs.verdict;
  if (!v) return null;
  const style = {
    COMPILED: "border-go bg-go/10 text-go",
    COMPILED_WITH_DIFFS: "border-warm bg-warm/10 text-warm",
    NOT_COMPILABLE: "border-keep bg-keep/10 text-keep",
    ERROR: "border-alarm bg-alarm/10 text-alarm",
  }[v.status];
  const label = {
    COMPILED: `COMPILED ${v.holdout_n}/${v.holdout_n}`,
    COMPILED_WITH_DIFFS: `DIFFS ${Math.round((v.agreement ?? 0) * v.holdout_n)}/${v.holdout_n}`,
    NOT_COMPILABLE: "KEEP MODEL",
    ERROR: "ERROR",
  }[v.status];
  return (
    <motion.span
      initial={{ scale: 0.85, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      transition={{ duration: 0.2, ease: "easeOut" }}
      data-testid={`verdict-${v.callsite_id}`}
      data-status={v.status}
      className={cn(
        "inline-block rounded border px-3 py-0.5 font-mono text-[15px] font-semibold tracking-[0.14em]",
        style,
      )}
    >
      {label}
    </motion.span>
  );
}

const STATUS_LABEL: Record<CallsiteState["status"], string> = {
  queued: "QUEUED",
  synthesizing: "SYNTHESIZING",
  replaying: "REPLAYING",
  iterating: "ITERATING",
  done: "DONE",
};

function Card({ cs, index }: { cs: CallsiteState; index: number }) {
  const a = cs.audit;
  const compiled = cs.verdict?.status === "COMPILED";
  const pct = cs.replayTotal > 0 ? cs.replayPassed / cs.replayTotal : 0;
  const barColor =
    cs.verdict == null
      ? "bg-warm"
      : cs.verdict.status === "NOT_COMPILABLE"
        ? "bg-keep"
        : cs.verdict.status === "COMPILED_WITH_DIFFS"
          ? "bg-warm"
          : "bg-go";
  const active = cs.status !== "queued" && cs.status !== "done";

  return (
    <motion.div
      initial={{ opacity: 0, y: 14 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25, delay: index * 0.08, ease: "easeOut" }}
      data-testid={`callsite-${a.callsite_id}`}
      className={cn(
        "flex min-h-0 flex-1 flex-col justify-between rounded-lg border bg-panel p-4",
        compiled ? "card-compiled border-go/50" : active ? "border-warm/40" : "border-hairline",
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="truncate font-mono text-[17px] text-fg">
            {a.file}
            <span className="text-muted">:{a.line}</span>
          </div>
          <div className="mt-0.5 font-mono text-[14px] text-muted">{a.symbol}()</div>
        </div>
        <span className="shrink-0 rounded border border-hairline px-2 py-0.5 font-mono text-[12px] tracking-[0.16em] text-muted">
          {KIND_LABEL[a.kind]}
        </span>
      </div>

      <div className="mt-2 flex items-center gap-2 font-mono text-[13px]">
        <span className={cn("tracking-[0.14em]", active ? "text-warm" : "text-muted")}>
          {STATUS_LABEL[cs.status]}
        </span>
        {cs.round !== null && cs.round !== undefined && cs.status !== "queued" && (
          <span className="rounded-full border border-hairline px-2 py-px text-[12px] text-muted">
            round {cs.round}
          </span>
        )}
        <span className="flex-1" />
        <span className="tnum text-muted">
          {cs.replayTotal > 0
            ? `${cs.replayPassed}/${cs.replayTotal}`
            : `${a.sample_count} samples`}
        </span>
      </div>

      <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-panel-2">
        <motion.div
          className={cn("h-full rounded-full", barColor)}
          initial={false}
          animate={{ width: `${pct * 100}%` }}
          transition={{ duration: 0.35, ease: "easeOut" }}
        />
      </div>

      <div className="mt-2.5 h-8">
        <VerdictBadge cs={cs} />
      </div>
    </motion.div>
  );
}

export function CallsiteWall({ state }: { state: DashState }) {
  return (
    <aside className="flex min-h-0 flex-col gap-3 overflow-hidden border-r border-hairline p-4">
      <div className="font-mono text-[13px] tracking-[0.3em] text-muted">CALLSITES</div>
      {state.order.length === 0 ? (
        <div
          data-testid="wall-placeholder"
          className="flex flex-1 items-center justify-center rounded-lg border border-dashed border-hairline font-mono text-[14px] tracking-[0.2em] text-muted/50"
        >
          SCAN NOT STARTED
        </div>
      ) : (
        state.order.map((id, i) => <Card key={id} cs={state.callsites[id]} index={i} />)
      )}
    </aside>
  );
}
