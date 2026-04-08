"use client";

import { useEffect, useRef } from "react";
import { Terminal as TerminalIcon } from "lucide-react";
import "@xterm/xterm/css/xterm.css";

interface TerminalPanelProps {
  containerName: string;
  projectId?: string;
}

export function TerminalPanel({ containerName }: TerminalPanelProps) {
  const termRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!termRef.current || !containerName) return;

    let cancelled = false;
    let ws: WebSocket | null = null;
    let term: import("@xterm/xterm").Terminal | null = null;
    let observer: ResizeObserver | null = null;

    (async () => {
      if (cancelled) return;

      const { Terminal } = await import("@xterm/xterm");
      const { FitAddon } = await import("@xterm/addon-fit");
      if (cancelled) return;

      term = new Terminal({
        theme: {
          background: "#0a0a0b",
          foreground: "#d4d4d8",
          cursor: "#d4d4d8",
          selectionBackground: "#3b82f680",
        },
        fontSize: 13,
        fontFamily: "JetBrains Mono, Fira Code, monospace",
        cursorBlink: true,
      });

      const fitAddon = new FitAddon();
      term.loadAddon(fitAddon);
      term.open(termRef.current!);
      fitAddon.fit();

      // Connect to ttyd via Traefik — ttyd runs without auth (network-isolated),
      // access control is handled by Traefik routing + container network isolation.
      const wsUrl = `ws://${containerName}.localhost:8090/ttyd/ws`;

      let retries = 0;
      const MAX_RETRIES = 5;
      const RETRY_DELAY = 2000;

      function connect() {
        if (cancelled || !term) return;
        ws = new WebSocket(wsUrl, ["tty"]);
        ws.binaryType = "arraybuffer";

        ws.onopen = () => {
          if (cancelled || !term) return;
          retries = 0;
          term.reset();
          // Send terminal dimensions as first message (ttyd protocol)
          ws!.send(JSON.stringify({
            AuthToken: "",
            columns: term.cols,
            rows: term.rows,
          }));
        };

        ws.onmessage = (event) => {
          if (cancelled || !term) return;
          const data = event.data;
          if (data instanceof ArrayBuffer) {
            const arr = new Uint8Array(data);
            if (arr.length < 2) return;
            if (arr[0] === 48) term.write(arr.slice(1));
          } else if (typeof data === "string" && data.length > 1) {
            if (data.charCodeAt(0) === 48) term.write(data.slice(1));
          }
        };

        ws.onerror = () => {
          // Errors are followed by onclose — retry happens there
        };

        ws.onclose = () => {
          if (cancelled || !term) return;
          if (retries < MAX_RETRIES) {
            retries++;
            term.writeln(`\r\n[Connecting to terminal... attempt ${retries}/${MAX_RETRIES}]`);
            setTimeout(connect, RETRY_DELAY);
          } else {
            term.writeln("\r\n[Terminal disconnected — could not connect after 5 attempts]");
            term.writeln("[Try stopping and restarting the workspace]");
          }
        };
      }

      connect();

      term.onData((input) => {
        if (ws?.readyState === WebSocket.OPEN) {
          ws.send("0" + input);
        }
      });

      term.onResize(({ cols, rows }) => {
        if (ws?.readyState === WebSocket.OPEN) {
          ws.send("1" + JSON.stringify({ columns: cols, rows }));
        }
      });

      observer = new ResizeObserver(() => {
        try { fitAddon.fit(); } catch {}
      });
      observer.observe(termRef.current!);
    })();

    return () => {
      cancelled = true;
      ws?.close();
      term?.dispose();
      observer?.disconnect();
    };
  }, [containerName]);

  if (!containerName) {
    return (
      <div className="h-full bg-[#0a0a0b] flex items-center justify-center">
        <div className="flex items-center gap-2 text-zinc-600 text-xs">
          <TerminalIcon size={14} />
          <span>No workspace connected</span>
        </div>
      </div>
    );
  }

  return <div ref={termRef} className="h-full w-full bg-[#0a0a0b]" />;
}
