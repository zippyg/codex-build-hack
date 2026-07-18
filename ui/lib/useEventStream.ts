"use client";

import { useEffect, useReducer, useRef } from "react";
import { PipelineEvent, RecordedLine } from "./contracts";
import { initialState, reduce, type DashState } from "./state";

export interface StreamOptions {
  // Live SSE endpoint. When set, fixture replay is skipped: same event shape on the wire.
  live?: string | null;
  // URL serving recorded NDJSON ({at_ms, event} per line). The demo-director source.
  fixture?: string;
  // Replay speed multiplier: 2 = twice as fast. Ignored for live streams.
  speed?: number;
  // Deterministic seek: apply every event with at_ms <= until instantly, then hold.
  until?: number | null;
}

export function useEventStream({
  live = null,
  fixture = "/fixture",
  speed = 1,
  until = null,
}: StreamOptions): DashState {
  const [state, dispatch] = useReducer(reduce, initialState);
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);

  useEffect(() => {
    if (live) {
      const es = new EventSource(live);
      es.onmessage = (msg) => {
        const parsed = PipelineEvent.safeParse(JSON.parse(msg.data));
        if (parsed.success) dispatch(parsed.data);
        else console.error("contract violation on live stream", parsed.error.issues);
      };
      return () => es.close();
    }

    let cancelled = false;
    (async () => {
      const res = await fetch(fixture);
      const text = await res.text();
      if (cancelled) return;
      const lines = text
        .split("\n")
        .filter((l) => l.trim().length > 0)
        .map((l) => RecordedLine.parse(JSON.parse(l)));

      if (until !== null) {
        for (const { at_ms, event } of lines) if (at_ms <= until) dispatch(event);
        return;
      }
      for (const { at_ms, event } of lines) {
        const t = setTimeout(() => dispatch(event), at_ms / speed);
        timers.current.push(t);
      }
    })();

    return () => {
      cancelled = true;
      for (const t of timers.current) clearTimeout(t);
      timers.current = [];
    };
  }, [live, fixture, speed, until]);

  return state;
}
