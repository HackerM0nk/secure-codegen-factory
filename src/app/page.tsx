"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import {
  Plus,
  Folder,
  Trash2,
  Loader2,
  Shield,
  Sparkles,
  Clock,
  X,
  Zap,
  Lock,
  Eye,
} from "lucide-react";
import { useAuth } from "@/lib/AuthProvider";

interface Project {
  id: string;
  name: string;
  description: string | null;
  status: string;
  previewUrl: string | null;
  createdAt: string;
  updatedAt: string;
}

function Toast({ message, type, onClose }: { message: string; type: "error" | "success"; onClose: () => void }) {
  useEffect(() => {
    const t = setTimeout(onClose, 4000);
    return () => clearTimeout(t);
  }, [onClose]);

  return (
    <div className={`fixed bottom-6 right-6 z-50 animate-toast-in flex items-center gap-3 px-4 py-3 rounded-lg border shadow-lg ${
      type === "error"
        ? "bg-red-950/90 border-red-500/30 text-red-200"
        : "bg-green-950/90 border-green-500/30 text-green-200"
    }`}>
      <span className="text-sm">{message}</span>
      <button onClick={onClose} className="opacity-60 hover:opacity-100">
        <X size={14} />
      </button>
    </div>
  );
}

export default function HomePage() {
  const router = useRouter();
  const { token, loading: authLoading } = useAuth();
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [showDialog, setShowDialog] = useState(false);
  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [credits, setCredits] = useState<number | null>(null);
  const [toast, setToast] = useState<{ message: string; type: "error" | "success" } | null>(null);

  useEffect(() => {
    if (authLoading || !token) return;

    fetch("/api/projects", {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((r) => r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`)))
      .then((data) => setProjects(data.data || data || []))
      .catch(() => setProjects([]))
      .finally(() => setLoading(false));

    fetch("/api/billing/balance", {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((r) => r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`)))
      .then((data) => setCredits(data.credits ?? null))
      .catch(() => {});
  }, [token, authLoading]);

  const createProject = async () => {
    if (!newName.trim()) return;
    setCreating(true);
    try {
      const res = await fetch("/api/projects", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ name: newName, description: newDesc }),
      });
      if (!res.ok) throw new Error("Failed to create project");
      const project = await res.json();
      router.push(`/project/${project.id}`);
    } catch {
      setToast({ message: "Failed to create project", type: "error" });
    }
    setCreating(false);
  };

  const deleteProject = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm("Delete this project?")) return;
    try {
      await fetch(`/api/projects/${id}`, {
        method: "DELETE",
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      setProjects((p) => p.filter((x) => x.id !== id));
      setToast({ message: "Project deleted", type: "success" });
    } catch {
      setToast({ message: "Failed to delete project", type: "error" });
    }
  };

  return (
    <div className="min-h-screen bg-zinc-950">
      {/* Header */}
      <header className="border-b border-zinc-800/80 header-gradient sticky top-0 z-10">
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-violet-600 flex items-center justify-center">
              <Zap size={16} className="text-white" />
            </div>
            <div>
              <h1 className="text-lg font-semibold text-white tracking-tight">AI Dev Factory</h1>
              <p className="text-xs text-zinc-500">Security-first architecture prototype</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            {credits !== null && (
              <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-900 border border-zinc-800">
                <Sparkles size={13} className="text-yellow-400" />
                <span className="text-xs text-zinc-400">
                  <span className="text-white font-mono font-medium">{credits.toFixed(0)}</span> credits
                </span>
              </div>
            )}
            <a
              href="/admin"
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-zinc-500 hover:text-zinc-300 hover:bg-zinc-900 transition-colors"
            >
              <Shield size={13} />
              Security
            </a>
            <button
              onClick={() => setShowDialog(true)}
              className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg text-sm font-medium transition-all hover:shadow-lg hover:shadow-blue-500/20"
            >
              <Plus size={15} />
              New Project
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-6xl mx-auto px-6 py-8">
        {loading ? (
          <div className="flex items-center justify-center py-24">
            <Loader2 className="animate-spin text-zinc-600" size={24} />
          </div>
        ) : projects.length === 0 ? (
          /* Empty State */
          <div className="text-center py-24">
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-zinc-900 border border-zinc-800 mb-6">
              <Folder className="text-zinc-600" size={28} />
            </div>
            <h2 className="text-xl font-semibold text-zinc-200 mb-2">No projects yet</h2>
            <p className="text-sm text-zinc-500 mb-8 max-w-md mx-auto">
              Describe what you want to build and the AI agent will scaffold, code, and validate it in an isolated sandbox.
            </p>
            <button
              onClick={() => setShowDialog(true)}
              className="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white px-6 py-3 rounded-lg text-sm font-medium transition-all hover:shadow-lg hover:shadow-blue-500/20"
            >
              <Plus size={16} />
              Create Your First Project
            </button>

            {/* Feature badges */}
            <div className="flex items-center justify-center gap-3 mt-12">
              {[
                { icon: Lock, label: "16 Security Layers" },
                { icon: Eye, label: "Full Observability" },
                { icon: Shield, label: "Defense-in-Depth" },
              ].map(({ icon: Icon, label }) => (
                <div key={label} className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-zinc-900 border border-zinc-800 text-xs text-zinc-500">
                  <Icon size={12} />
                  {label}
                </div>
              ))}
            </div>
          </div>
        ) : (
          /* Project Grid */
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {projects.map((p) => (
              <div
                key={p.id}
                onClick={() => router.push(`/project/${p.id}`)}
                className="bg-zinc-900/50 border border-zinc-800/80 rounded-xl p-5 cursor-pointer hover:border-zinc-700 hover:bg-zinc-900 transition-all group"
              >
                <div className="flex items-start justify-between mb-3">
                  <h3 className="font-medium text-white truncate pr-2">{p.name}</h3>
                  <button
                    onClick={(e) => deleteProject(p.id, e)}
                    className="opacity-0 group-hover:opacity-100 p-1.5 -m-1 text-zinc-600 hover:text-red-400 transition-all rounded-lg hover:bg-red-500/10"
                  >
                    <Trash2 size={13} />
                  </button>
                </div>
                {p.description && (
                  <p className="text-sm text-zinc-500 mb-4 line-clamp-2 leading-relaxed">{p.description}</p>
                )}
                <div className="flex items-center justify-between text-xs">
                  <span
                    className={`px-2 py-1 rounded-md font-medium ${
                      p.status === "running"
                        ? "bg-green-500/10 text-green-400 border border-green-500/20"
                        : p.status === "error"
                        ? "bg-red-500/10 text-red-400 border border-red-500/20"
                        : "bg-zinc-800 text-zinc-500 border border-zinc-700/50"
                    }`}
                  >
                    {p.status}
                  </span>
                  <div className="flex items-center gap-1 text-zinc-600">
                    <Clock size={11} />
                    <span>{new Date(p.updatedAt || p.createdAt).toLocaleDateString()}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </main>

      {/* Create Dialog */}
      {showDialog && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50" onClick={() => setShowDialog(false)}>
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6 w-full max-w-md mx-4 shadow-2xl" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-lg font-semibold text-white">New Project</h2>
              <button onClick={() => { setShowDialog(false); setNewName(""); setNewDesc(""); }} className="text-zinc-500 hover:text-white p-1 rounded-lg hover:bg-zinc-800 transition-colors">
                <X size={16} />
              </button>
            </div>
            <input
              autoFocus
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="Project name"
              className="w-full bg-zinc-800/50 border border-zinc-700 rounded-xl px-4 py-3 text-sm text-white placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50 mb-3 transition-all"
              onKeyDown={(e) => e.key === "Enter" && createProject()}
            />
            <textarea
              value={newDesc}
              onChange={(e) => setNewDesc(e.target.value)}
              placeholder="Describe what you want to build..."
              rows={3}
              className="w-full bg-zinc-800/50 border border-zinc-700 rounded-xl px-4 py-3 text-sm text-white placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50 mb-5 resize-none transition-all"
            />
            <div className="flex gap-3 justify-end">
              <button
                onClick={() => { setShowDialog(false); setNewName(""); setNewDesc(""); }}
                className="px-4 py-2.5 text-sm text-zinc-400 hover:text-white rounded-lg hover:bg-zinc-800 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={createProject}
                disabled={creating || !newName.trim()}
                className="bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:hover:bg-blue-600 text-white px-5 py-2.5 rounded-lg text-sm font-medium transition-all hover:shadow-lg hover:shadow-blue-500/20"
              >
                {creating ? (
                  <span className="flex items-center gap-2"><Loader2 className="animate-spin" size={14} /> Creating...</span>
                ) : (
                  "Create Project"
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Toast */}
      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  );
}
