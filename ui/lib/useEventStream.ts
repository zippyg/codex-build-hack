"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { PipelineEvent, RecordedLine } from "./contracts";
import { initialState, reduce, type Beat, type DashState } from "./state";

export interface StreamOptions {
  live?: string | null;
  fixture?: string;
  speed?: number;
  until?: number | null;
}

export interface DemoControls {
  playing: boolean;
  atEnd: boolean;
  ready: boolean;
  play: () => void;
  pause: () => void;
  toggle: () => void;
  restart: () => void;
  seekBeat: (beat: Beat) => void;
}

interface Line {
  at_ms: number;
  event: ReturnType<typeof RecordedLine.parse>["event"];
}

const TICK_MS = 60;

function foldTo(lines: Line[], toMs: number): DashState {
  let s = initialState;
  for (const { at_ms, event } of lines) if (at_ms <= toMs) s = reduce(s, event);
  return s;
}

// The at_ms just before each beat's successor begins, so seeking a beat shows it fully realized.
function beatEnds(lines: Line[]): Record<number, number> {
  const firstSeen: Record<number, number> = {};
  let s = initialState;
  for (const { at_ms, event } of lines) {
    s = reduce(s, event);
    if (firstSeen[s.beat] === undefined) firstSeen[s.beat] = at_ms;
  }
  const max = lines.length ? lines[lines.length - 1].at_ms : 0;
  const ends: Record<number, number> = {};
  for (let b = 1 as number; b <= 6; b++) {
    ends[b] = firstSeen[b + 1] !== undefined ? firstSeen[b + 1] - 1 : max;
  }
  return ends;
}

export function useEventStream({
  live = null,
  fixture = "/fixture",
  speed = 1,
  until = null,
}: StreamOptions): { state: DashState; controls: DemoControls } {
  const [state, setState] = useState<DashState>(initialState);
  const [playing, setPlaying] = useState(false);
  const [atEnd, setAtEnd] = useState(false);
  const [ready, setReady] = useState(false);

  const lines = useRef<Line[]>([]);
  const ends = useRef<Record<number, number>>({});
  const maxAt = useRef(0);
  const head = useRef(0);

  // Live SSE: same wire shape, no player controls.
  useEffect(() => {
    if (!live) return;
    const es = new EventSource(live);
    es.onmessage = (msg) => {
      const parsed = PipelineEvent.safeParse(JSON.parse(msg.data));
      if (parsed.success) setState((s) => reduce(s, parsed.data));
      else console.error("contract violation on live stream", parsed.error.issues);
    };
    return () => es.close();
  }, [live]);

  // Load the recorded fixture once.
  useEffect(() => {
    if (live) return;
    let cancelled = false;
    (async () => {
      const res = await fetch(fixture);
      const text = await res.text();
      if (cancelled) return;
      const parsed = text
        .split("\n")
        .filter((l) => l.trim().length > 0)
        .map((l) => RecordedLine.parse(JSON.parse(l)) as Line);
      lines.current = parsed;
      ends.current = beatEnds(parsed);
      maxAt.current = parsed.length ? parsed[parsed.length - 1].at_ms : 0;
      setReady(true);
      if (until !== null) {
        head.current = until;
        setState(foldTo(parsed, until));
      } else {
        head.current = 0;
        setState(initialState);
        setPlaying(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [live, fixture, until]);

  // The playhead loop: advance wall time, re-fold. 144 events is cheap to re-fold each tick.
  useEffect(() => {
    if (live || until !== null || !playing) return;
    const id = setInterval(() => {
      head.current += TICK_MS * speed;
      if (head.current >= maxAt.current) {
        head.current = maxAt.current;
        setState(foldTo(lines.current, head.current));
        setPlaying(false);
        setAtEnd(true);
        return;
      }
      setState(foldTo(lines.current, head.current));
    }, TICK_MS);
    return () => clearInterval(id);
  }, [live, until, playing, speed]);

  const play = useCallback(() => {
    if (head.current >= maxAt.current) head.current = 0;
    setAtEnd(false);
    setPlaying(true);
  }, []);
  const pause = useCallback(() => setPlaying(false), []);
  const toggle = useCallback(() => (playing ? pause() : play()), [playing, play, pause]);
  const restart = useCallback(() => {
    head.current = 0;
    setState(initialState);
    setAtEnd(false);
    setPlaying(true);
  }, []);
  const seekBeat = useCallback((beat: Beat) => {
    const target = ends.current[beat] ?? 0;
    head.current = target;
    setPlaying(false);
    setAtEnd(target >= maxAt.current);
    setState(foldTo(lines.current, target));
  }, []);

  return {
    state,
    controls: { playing, atEnd, ready, play, pause, toggle, restart, seekBeat },
  };
}
