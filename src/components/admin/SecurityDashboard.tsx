"use client";

import { useEffect, useState } from "react";
import { Shield, AlertTriangle, Activity, Cpu, DollarSign, RefreshCw, TrendingUp, Lock } from "lucide-react";
import { useAuth } from "@/lib/AuthProvider";

interface SecurityStats {
  inputFirewall: { totalChecked: number; blocked: number; flagged: number; topPatterns: { pattern: string; count: number }[] };
  outputFilter: { totalChecked: number; blocked: number; alerted: number; topBlocked: { pattern: string; count: number }[] };
  trajectoryMonitor: { activeSessions: number; flaggedSessions: number; pausedSessions: number };
}

interface ProviderHealth {
  name: string;
  score: number;
  weight: number;
  rpm: number;
  rpmLimit: number;
  errors: number;
  successes: number;
}

interface BillingInfo {
  credits: number;
  plan: string;
  usage: { totalCredits: number; byModel: Record<string, number> };
}

export function SecurityDashboard() {
  const { token } = useAuth();
  const [security, setSecurity] = useState<SecurityStats | null>(null);
  const [providers, setProviders] = useState<ProviderHealth[]>([]);
  const [billing, setBilling] = useState<BillingInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());

  const fetchAll = async () => {
    const headers: Record<string, string> = {};
    if (token) headers.Authorization = `Bearer ${token}`;

    try {
      const [secRes, llmRes, billRes] = await Promise.all([
        fetch("/api/security/stats", { headers }),
        fetch("/api/agent/llm-health", { headers }),
        fetch("/api/billing/balance", { headers }),
      ]);
      if (secRes.ok) setSecurity(await secRes.json());
      if (llmRes.ok) setProviders((await llmRes.json()).providers || []);
      if (billRes.ok) setBilling(await billRes.json());
    } catch {}
    setLoading(false);
    setLastRefresh(new Date());
  };

  useEffect(() => {
    if (!token) return;
    fetchAll();
    const interval = setInterval(fetchAll, 10000);
    return () => clearInterval(interval);
  }, [token]);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="flex items-center gap-3 text-zinc-500">
          <RefreshCw className="animate-spin" size={18} />
          <span>Loading security data...</span>
        </div>
      </div>
    );
  }

  const totalBlocked = (security?.inputFirewall.blocked ?? 0) + (security?.outputFilter.blocked ?? 0);

  return (
    <div className="max-w-6xl mx-auto px-6 py-8 space-y-6">
      {/* Summary bar */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-green-500/10 border border-green-500/20">
            <Lock size={13} className="text-green-400" />
            <span className="text-xs font-medium text-green-400">16 Security Layers Active</span>
          </div>
          <span className="text-xs text-zinc-600">
            Last refresh: {lastRefresh.toLocaleTimeString()}
          </span>
        </div>
        <button onClick={fetchAll} className="text-zinc-500 hover:text-white transition-colors p-1.5 rounded-lg hover:bg-zinc-800">
          <RefreshCw size={14} />
        </button>
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <StatCard
          icon={<Shield size={18} />}
          title="Input Firewall"
          value={security?.inputFirewall.blocked ?? 0}
          label="Blocked"
          sublabel={`${security?.inputFirewall.totalChecked ?? 0} scanned`}
          color="red"
        />
        <StatCard
          icon={<AlertTriangle size={18} />}
          title="Command Filter"
          value={security?.outputFilter.blocked ?? 0}
          label="Commands Blocked"
          sublabel={`${security?.outputFilter.alerted ?? 0} alerts raised`}
          color="yellow"
        />
        <StatCard
          icon={<Activity size={18} />}
          title="Sessions"
          value={security?.trajectoryMonitor.activeSessions ?? 0}
          label="Active Sessions"
          sublabel={`${security?.trajectoryMonitor.flaggedSessions ?? 0} flagged`}
          color="blue"
        />
        <StatCard
          icon={<TrendingUp size={18} />}
          title="Total Threats"
          value={totalBlocked}
          label="Blocked Total"
          sublabel="Across all layers"
          color="green"
        />
      </div>

      {/* Two-column layout */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* LLM Provider Health */}
        <div className="bg-zinc-900/50 border border-zinc-800 rounded-xl p-5">
          <h2 className="text-sm font-semibold mb-4 flex items-center gap-2 text-zinc-300">
            <Cpu size={16} className="text-blue-400" /> LLM Provider Health
          </h2>
          <div className="space-y-3">
            {providers.map((p) => (
              <div key={p.name} className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-mono text-zinc-300">{p.name}</span>
                  <div className="flex items-center gap-3 text-xs text-zinc-500">
                    <span>Score: <span className={p.score > 20 ? "text-green-400" : p.score > 0 ? "text-yellow-400" : "text-red-400"}>{p.score}</span></span>
                    <span className="text-green-400">{p.successes} ok</span>
                    <span className="text-red-400">{p.errors} err</span>
                  </div>
                </div>
                <div className="h-1.5 bg-zinc-800 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all duration-500 ${
                      p.score > 20 ? "bg-green-500" : p.score > 0 ? "bg-yellow-500" : "bg-red-500"
                    }`}
                    style={{ width: `${Math.min(100, Math.max(3, (p.weight || 0) * 100))}%` }}
                  />
                </div>
              </div>
            ))}
            {providers.length === 0 && (
              <div className="text-zinc-600 text-sm py-4 text-center">No providers configured</div>
            )}
          </div>
        </div>

        {/* Credits & Usage */}
        <div className="bg-zinc-900/50 border border-zinc-800 rounded-xl p-5">
          <h2 className="text-sm font-semibold mb-4 flex items-center gap-2 text-zinc-300">
            <DollarSign size={16} className="text-emerald-400" /> Credits & Usage
          </h2>
          {billing ? (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <div className="text-3xl font-bold text-white">{billing.credits.toFixed(1)}</div>
                  <div className="text-xs text-zinc-500 mt-1">Credits remaining</div>
                </div>
                {billing.usage && (
                  <div>
                    <div className="text-3xl font-bold text-white">{billing.usage.totalCredits.toFixed(1)}</div>
                    <div className="text-xs text-zinc-500 mt-1">Used this period</div>
                  </div>
                )}
              </div>
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded-full text-xs bg-blue-500/10 text-blue-400 border border-blue-500/20">
                  {billing.plan}
                </span>
              </div>
            </div>
          ) : (
            <div className="text-zinc-600 text-sm py-4 text-center">No billing data</div>
          )}
        </div>
      </div>

      {/* Top Blocked Patterns */}
      {security?.inputFirewall.topPatterns && security.inputFirewall.topPatterns.length > 0 && (
        <div className="bg-zinc-900/50 border border-zinc-800 rounded-xl p-5">
          <h2 className="text-sm font-semibold mb-4 text-zinc-300">Top Blocked Patterns</h2>
          <div className="space-y-2">
            {security.inputFirewall.topPatterns.map((p, i) => (
              <div key={i} className="flex items-center justify-between py-1.5 border-b border-zinc-800/50 last:border-0">
                <code className="text-xs font-mono text-red-400 bg-red-500/5 px-2 py-0.5 rounded">{p.pattern}</code>
                <span className="text-xs text-zinc-500 tabular-nums">{p.count}x</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function StatCard({
  icon,
  title,
  value,
  label,
  sublabel,
  color,
}: {
  icon: React.ReactNode;
  title: string;
  value: number;
  label: string;
  sublabel: string;
  color: "red" | "yellow" | "blue" | "green";
}) {
  const colorMap = {
    red: "border-red-500/20 from-red-500/5 to-transparent text-red-400",
    yellow: "border-yellow-500/20 from-yellow-500/5 to-transparent text-yellow-400",
    blue: "border-blue-500/20 from-blue-500/5 to-transparent text-blue-400",
    green: "border-green-500/20 from-green-500/5 to-transparent text-green-400",
  };

  return (
    <div className={`rounded-xl border bg-gradient-to-b p-4 ${colorMap[color]}`}>
      <div className="flex items-center gap-2 mb-3">
        {icon}
        <span className="text-xs font-medium text-zinc-400">{title}</span>
      </div>
      <div className="text-2xl font-bold tabular-nums">{value}</div>
      <div className="text-xs mt-1">{label}</div>
      <div className="text-xs text-zinc-600 mt-0.5">{sublabel}</div>
    </div>
  );
}
