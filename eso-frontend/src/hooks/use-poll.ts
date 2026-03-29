// src/hooks/use-poll.ts
'use client';
import { useEffect, useRef, useState } from 'react';

export function usePoll<T>(fetcher: () => Promise<T>, intervalMs: number, enabled: boolean) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const timer = useRef<NodeJS.Timeout>();

  useEffect(() => {
    if (!enabled) { clearInterval(timer.current); return; }

    const tick = async () => {
      try { setData(await fetcher()); setError(null); }
      catch (e: any) { setError(e.message); }
    };

    tick();
    timer.current = setInterval(tick, intervalMs);
    return () => clearInterval(timer.current);
  }, [enabled, intervalMs]);

  return { data, error };
}
