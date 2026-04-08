"use client";

import { useState, useRef, useEffect } from "react";
import {
  Send,
  Loader2,
  FileCode,
  Terminal,
  CheckCircle2,
  XCircle,
  Brain,
  Wrench,
  ChevronDown,
  ChevronRight,
  StopCircle,
} from "lucide-react";
import { useAuth } from "@/lib/AuthProvider";

interface Message {
  role: "user" | "assistant";
  content: string;
}

interface AgentEvent {
  type: string;
  data: any;
  ts?: number;
}

function ToolIcon({ tool }: { tool: string }) {
  if (tool === "file_write" || tool === "file_read") return <FileCode size={12} className="shrink-0" />;
  if (tool === "shell_exec") return <Terminal size={12} className="shrink-0" />;
  return <Wrench size={12} className="shrink-0" />;
}

function ActivityItem({ event }: { event: AgentEvent }) {
  const [expanded, setExpanded] = useState(false);

  if (event.type === "thinking") {
    const iter = event.data?.iteration;
    if (iter) {
      return (
        <div className="flex items-center gap-2 text-xs text-zinc-500 py-1">
          <Brain size={12} className="text-purple-400 shrink-0" />
          <span>Iteration {iter}/{event.data.maxIterations}</span>
        </div>
      );
    }
    return null;
  }

  if (event.type === "text") {
    const text = typeof event.data === "string" ? event.data : event.data?.text || "";
    if (!text.trim()) return null;
    return (
      <div className="text-xs text-zinc-300 py-1 pl-5 leading-relaxed">
        {text.length > 200 ? text.substring(0, 200) + "..." : text}
      </div>
    );
  }

  if (event.type === "tool_call") {
    const tool = event.data?.tool || "unknown";
    const input = event.data?.input || event.data?.args || {};
    let summary = "";

    if (tool === "file_write") {
      const bytes = input.content?.length || 0;
      summary = `${input.path} (${bytes} chars)`;
    } else if (tool === "file_read") {
      summary = input.path || "";
    } else if (tool === "shell_exec") {
      summary = input.command || "";
    } else {
      summary = JSON.stringify(input).substring(0, 80);
    }

    return (
      <div className="py-1">
        <button
          onClick={() => setExpanded(!expanded)}
          className="flex items-center gap-2 text-xs w-full text-left hover:bg-zinc-800/50 rounded px-1 -mx-1 py-0.5"
        >
          {expanded ? <ChevronDown size={10} className="text-zinc-600 shrink-0" /> : <ChevronRight size={10} className="text-zinc-600 shrink-0" />}
          <ToolIcon tool={tool} />
          <span className="text-yellow-400 font-medium">{tool}</span>
          <span className="text-zinc-500 truncate">{summary}</span>
        </button>
        {expanded && (
          <pre className="text-[10px] text-zinc-600 bg-zinc-900 rounded p-2 ml-5 mt-1 overflow-x-auto max-h-40 overflow-y-auto">
            {JSON.stringify(input, null, 2)}
          </pre>
        )}
      </div>
    );
  }

  if (event.type === "tool_result") {
    const isError = event.data?.isError;
    const result = event.data?.result || "";
    const duration = event.data?.durationMs;

    return (
      <div className="flex items-start gap-2 text-xs py-0.5 pl-5">
        {isError ? (
          <XCircle size={11} className="text-red-400 mt-0.5 shrink-0" />
        ) : (
          <CheckCircle2 size={11} className="text-green-400 mt-0.5 shrink-0" />
        )}
        <span className={isError ? "text-red-400" : "text-green-400/80"}>
          {result.length > 120 ? result.substring(0, 120) + "..." : result}
          {duration ? ` (${duration}ms)` : ""}
        </span>
      </div>
    );
  }

  if (event.type === "error") {
    return (
      <div className="flex items-center gap-2 text-xs text-red-400 py-1">
        <XCircle size={12} className="shrink-0" />
        <span>{event.data?.message || event.data?.error || "Unknown error"}</span>
      </div>
    );
  }

  if (event.type === "done") {
    return (
      <div className="flex items-center gap-2 text-xs text-emerald-400 py-1.5 border-t border-zinc-800/50 mt-1">
        <CheckCircle2 size={12} className="shrink-0" />
        <span>
          Done — {event.data?.iterations} iteration{event.data?.iterations !== 1 ? "s" : ""}, {event.data?.tokensUsed?.toLocaleString()} tokens
          {event.data?.model ? ` · ${event.data.model}` : ""}
        </span>
      </div>
    );
  }

  return null;
}

// Direct backend URL for SSE streaming (Next.js rewrite proxy buffers SSE)
const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:4100";

export function ChatPanel({ projectId }: { projectId: string }) {
  const { token } = useAuth();
  const [input, setInput] = useState("");
  const [messages, setMessages] = useState<Message[]>([]);
  const [activities, setActivities] = useState<AgentEvent[]>([]);
  const [isStreaming, setIsStreaming] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const abortRef = useRef<AbortController | null>(null);

  // Load history on mount
  useEffect(() => {
    if (!token) return;
    fetch(`${API_BASE}/api/agent/${projectId}/history`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((r) => r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`)))
      .then((data) => {
        const msgs = data.messages || data.conversations?.[0]?.messages || [];
        setMessages(msgs.map((m: any) => ({ role: m.role, content: m.content })));
      })
      .catch(() => {});
  }, [projectId, token]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, activities]);

  const stopAgent = () => {
    abortRef.current?.abort();
    setIsStreaming(false);
  };

  const sendMessage = async () => {
    if (!input.trim() || isStreaming) return;
    const userMsg = input.trim();
    setInput("");
    setMessages((prev) => [...prev, { role: "user", content: userMsg }]);
    setActivities([]);
    setIsStreaming(true);

    const controller = new AbortController();
    abortRef.current = controller;

    try {
      const res = await fetch(`${API_BASE}/api/agent/${projectId}/message`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        body: JSON.stringify({ message: userMsg }),
        signal: controller.signal,
      });

      if (!res.ok && !res.headers.get("content-type")?.includes("text/event-stream")) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || `HTTP ${res.status}`);
      }

      const reader = res.body!.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let assistantText = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";

        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          const payload = line.slice(6);
          if (payload === "[DONE]") continue;

          try {
            const event: AgentEvent = { ...JSON.parse(payload), ts: Date.now() };
            setActivities((prev) => [...prev, event]);

            if (event.type === "text") {
              assistantText += typeof event.data === "string" ? event.data : event.data?.text || "";
            }
          } catch {}
        }
      }

      if (assistantText) {
        setMessages((prev) => [...prev, { role: "assistant", content: assistantText }]);
      }
    } catch (err: any) {
      if (err.name !== "AbortError") {
        setMessages((prev) => [...prev, { role: "assistant", content: `Error: ${err.message}` }]);
      }
    }

    setIsStreaming(false);
    abortRef.current = null;
  };

  return (
    <div className="flex flex-col h-full bg-zinc-950">
      {/* Messages & Activity */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {messages.length === 0 && !isStreaming && (
          <div className="flex flex-col items-center justify-center py-16 text-zinc-600">
            <div className="w-12 h-12 rounded-2xl bg-zinc-900 border border-zinc-800 flex items-center justify-center mb-4">
              <Brain size={22} className="text-blue-400" />
            </div>
            <p className="text-base font-medium text-zinc-400 mb-1">What would you like to build?</p>
            <p className="text-xs text-zinc-600 max-w-[240px] text-center leading-relaxed">Describe your app and the AI agent will scaffold, code, and validate it.</p>
          </div>
        )}

        {messages.map((msg, i) => (
          <div key={i} className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
            <div
              className={`max-w-[90%] rounded-xl px-4 py-2.5 text-sm ${
                msg.role === "user"
                  ? "bg-blue-600 text-white"
                  : "bg-zinc-800 text-zinc-100"
              }`}
            >
              <pre className="whitespace-pre-wrap font-sans break-words">{msg.content}</pre>
            </div>
          </div>
        ))}

        {/* Live activity feed */}
        {activities.length > 0 && (
          <div className="bg-zinc-900/60 border border-zinc-800 rounded-lg p-3">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2 text-xs font-medium text-zinc-400">
                {isStreaming ? (
                  <>
                    <Loader2 className="animate-spin text-blue-400" size={13} />
                    Agent working
                  </>
                ) : (
                  <>
                    <CheckCircle2 className="text-emerald-400" size={13} />
                    Agent finished
                  </>
                )}
              </div>
              {isStreaming && (
                <button onClick={stopAgent} className="flex items-center gap-1 text-[10px] text-red-400 hover:text-red-300">
                  <StopCircle size={11} />
                  Stop
                </button>
              )}
            </div>
            <div className="space-y-0">
              {activities.map((event, i) => (
                <ActivityItem key={i} event={event} />
              ))}
            </div>
          </div>
        )}

        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <div className="border-t border-zinc-800/80 p-3">
        <div className="flex gap-2">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && !e.shiftKey && sendMessage()}
            placeholder={isStreaming ? "Agent is working..." : "Describe what to build..."}
            disabled={isStreaming}
            className="flex-1 bg-zinc-900/50 border border-zinc-800 rounded-xl px-4 py-2.5 text-sm text-white placeholder-zinc-600 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50 disabled:opacity-50 transition-all"
          />
          <button
            onClick={sendMessage}
            disabled={isStreaming || !input.trim()}
            className="bg-blue-600 text-white p-2.5 rounded-xl disabled:opacity-30 hover:bg-blue-500 transition-all hover:shadow-lg hover:shadow-blue-500/20"
          >
            {isStreaming ? <Loader2 className="animate-spin" size={16} /> : <Send size={16} />}
          </button>
        </div>
      </div>
    </div>
  );
}
