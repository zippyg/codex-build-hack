"use client";

import { diffWords } from "diff";
import { motion } from "motion/react";
import type { DashState } from "@/lib/state";

const asText = (v: unknown) => (typeof v === "string" ? v : JSON.stringify(v));

function WordDiff({ expected, got }: { expected: unknown; got: unknown }) {
  const parts = diffWords(asText(expected), asText(got));
  return (
    <span className="font-mono text-[17px]">
      {parts.map((p, i) =>
        p.added ? (
          <span key={i} className="rounded-sm bg-warm/20 px-1 text-warm">
            {p.value}
          </span>
        ) : p.removed ? (
          <span key={i} className="rounded-sm bg-alarm/10 px-1 text-muted line-through">
            {p.value}
          </span>
        ) : (
          <span key={i} className="text-fg">
            {p.value}
          </span>
        ),
      )}
    </span>
  );
}

export function DiffReceipts({ state }: { state: DashState }) {
  const v = state.diffVerdict;
  if (!v) return null;
  const disagreements = v.holdout_n - Math.round((v.agreement ?? 0) * v.holdout_n);
  return (
    <div className="flex min-h-0 flex-1 flex-col justify-center px-4">
      <div className="font-mono text-[13px] tracking-[0.3em] text-muted">DIFF RECEIPTS</div>
      <div className="mt-1 mb-5 font-sans text-[clamp(18px,2.6vh,24px)] text-fg">
        <span className="font-mono text-warm">{v.callsite_id}</span> · {v.reason}
      </div>
      <div className="flex flex-col gap-3" data-testid="diff-list">
        {v.diffs.map((d, i) => {
          const match = asText(d.expected) === asText(d.got);
          return (
            <motion.div
              key={d.event_id || i}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.22, delay: i * 0.12, ease: "easeOut" }}
              className="rounded-lg border border-hairline bg-panel p-4"
            >
              <div className="mb-2 flex items-center gap-3 font-mono text-[13px] text-muted">
                <span>{d.event_id}</span>
                <span className="italic">"{asText((d.input as { text?: string })?.text ?? d.input)}"</span>
                <span className="flex-1" />
                <span className={match ? "text-go" : "text-warm"}>
                  {match ? "MATCH" : "DISAGREEMENT"}
                </span>
              </div>
              <div className="flex items-center gap-4">
                <WordDiff expected={d.expected} got={d.got} />
                <span className="flex-1" />
                <span className="font-mono text-[13px] text-muted">{d.summary}</span>
              </div>
            </motion.div>
          );
        })}
      </div>
      <div className="mt-5 font-sans text-[clamp(16px,2.2vh,20px)] text-muted">
        {disagreements} of {v.holdout_n} holdout cases disagree: mostly the model disagreeing
        with itself on genuinely ambiguous inputs.
      </div>
    </div>
  );
}
