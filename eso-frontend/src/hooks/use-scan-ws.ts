// src/hooks/use-scan-ws.ts
'use client';
import { useEffect, useRef, useState, useCallback } from 'react';

export type ScanEvent = {
  type: string;
  process_id: string;
  data: Record<string, any>;
  timestamp: string;
};

type WSState = 'connecting' | 'connected' | 'disconnected' | 'error';

export function useScanWS(processId: string | null) {
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [status, setStatus] = useState<WSState>('disconnected');
  const [latest, setLatest] = useState<ScanEvent | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<NodeJS.Timeout>();

  const connect = useCallback(() => {
    if (!processId) return;

    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    // Use the API proxy — Next.js rewrites /api/* to backend
    // But WebSocket needs direct connection to backend
    const host = window.location.hostname;
    const url = `${proto}://${host}:8000/api/v1/ws/scan/${processId}`;

    setStatus('connecting');

    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      setStatus('connected');
    };

    ws.onmessage = (msg) => {
      try {
        const event: ScanEvent = JSON.parse(msg.data);
        setEvents(prev => [...prev, event]);
        setLatest(event);

        // Auto-close on terminal events
        if (['complete', 'error', 'failed'].includes(event.type)) {
          setStatus('disconnected');
        }
      } catch (e) {
        console.warn('WS parse error:', e);
      }
    };

    ws.onerror = () => {
      setStatus('error');
    };

    ws.onclose = () => {
      setStatus('disconnected');
      wsRef.current = null;
    };
  }, [processId]);

  // Connect on mount / processId change
  useEffect(() => {
    if (!processId) return;
    setEvents([]);
    setLatest(null);
    connect();

    return () => {
      clearTimeout(reconnectTimer.current);
      wsRef.current?.close();
      wsRef.current = null;
    };
  }, [processId, connect]);

  // Derived state from events
  const outputLines = events
    .filter(e => e.type === 'task_output')
    .map(e => ({ tool: e.data.tool, line: e.data.line, task: e.data.task_name }));

  const proposals = events
    .filter(e => e.type === 'approval_needed')
    .at(-1)?.data.proposals || null;

  const isComplete = events.some(e => ['complete', 'error', 'failed'].includes(e.type));

  return { events, latest, status, outputLines, proposals, isComplete };
}
