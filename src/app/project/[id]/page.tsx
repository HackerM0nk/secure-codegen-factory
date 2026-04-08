"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { ArrowLeft, Play, Square, Loader2, Shield, Terminal, Code2, Eye } from "lucide-react";
import { WorkspaceLayout } from "@/components/workspace/WorkspaceLayout";
import { useAuth } from "@/lib/AuthProvider";

interface Project {
  id: string;
  name: string;
  description: string | null;
  status: string;
  containerName: string | null;
  previewUrl: string | null;
}

export default function ProjectPage() {
  const params = useParams();
  const router = useRouter();
  const projectId = params.id as string;

  const { token, loading: authLoading } = useAuth();
  const [project, setProject] = useState<Project | null>(null);
  const [loading, setLoading] = useState(true);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchProject = async () => {
    if (!token) return;
    try {
      const res = await fetch(`/api/projects/${projectId}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        setProject(data);
      }
    } catch {}
    setLoading(false);
  };

  useEffect(() => {
    if (authLoading || !token) return;
    fetchProject();
  }, [projectId, token, authLoading]);

  const startWorkspace = async () => {
    setStarting(true);
    setError(null);
    try {
      const res = await fetch("/api/workspaces", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ projectId }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || "Failed to start workspace");
      }
      await fetchProject();
    } catch (err: any) {
      setError(err.message);
    }
    setStarting(false);
  };

  const stopWorkspace = async () => {
    try {
      await fetch(`/api/workspaces/${projectId}`, {
        method: "DELETE",
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      await fetchProject();
    } catch {}
  };

  if (loading) {
    return (
      <div className="h-screen flex items-center justify-center bg-zinc-950">
        <Loader2 className="animate-spin text-zinc-600" size={28} />
      </div>
    );
  }

  if (!project) {
    return (
      <div className="h-screen flex flex-col items-center justify-center bg-zinc-950 gap-4">
        <p className="text-zinc-500">Project not found</p>
        <button onClick={() => router.push("/")} className="text-sm text-blue-400 hover:text-blue-300">
          Back to projects
        </button>
      </div>
    );
  }

  // Workspace stopped — show start screen
  if (project.status !== "running") {
    return (
      <div className="h-screen bg-zinc-950 flex flex-col">
        <header className="border-b border-zinc-800/80 px-5 py-3 flex items-center gap-4 header-gradient">
          <button onClick={() => router.push("/")} className="text-zinc-500 hover:text-white transition-colors">
            <ArrowLeft size={18} />
          </button>
          <div className="flex items-center gap-3">
            <h1 className="font-medium text-white">{project.name}</h1>
            <span className={`px-2 py-0.5 rounded-md text-xs font-medium ${
              project.status === "error"
                ? "bg-red-500/10 text-red-400 border border-red-500/20"
                : "bg-zinc-800 text-zinc-500 border border-zinc-700/50"
            }`}>
              {project.status}
            </span>
          </div>
        </header>

        <div className="flex-1 flex items-center justify-center">
          <div className="text-center max-w-md">
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-zinc-900 border border-zinc-800 mb-6">
              <Play className="text-zinc-500" size={28} />
            </div>
            <h2 className="text-xl font-semibold text-zinc-200 mb-2">Ready to build</h2>
            <p className="text-sm text-zinc-500 mb-8 leading-relaxed">
              Start the workspace to launch an isolated sandbox with AI agent, code editor, terminal, and live preview.
            </p>

            {error && (
              <div className="mb-6 px-4 py-3 rounded-lg bg-red-950/50 border border-red-500/20 text-sm text-red-300">
                {error}
              </div>
            )}

            <button
              onClick={startWorkspace}
              disabled={starting}
              className="inline-flex items-center gap-2.5 bg-green-600 hover:bg-green-500 disabled:opacity-50 text-white px-8 py-3.5 rounded-xl font-medium transition-all hover:shadow-lg hover:shadow-green-500/20"
            >
              {starting ? (
                <>
                  <Loader2 className="animate-spin" size={18} />
                  Starting workspace...
                </>
              ) : (
                <>
                  <Play size={18} />
                  Start Workspace
                </>
              )}
            </button>

            {/* Capability badges */}
            <div className="flex items-center justify-center gap-3 mt-10">
              {[
                { icon: Code2, label: "Code Editor" },
                { icon: Terminal, label: "Terminal" },
                { icon: Eye, label: "Live Preview" },
                { icon: Shield, label: "Sandboxed" },
              ].map(({ icon: Icon, label }) => (
                <div key={label} className="flex items-center gap-1.5 text-xs text-zinc-600">
                  <Icon size={12} />
                  {label}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Workspace running — full IDE layout
  return (
    <div className="h-screen bg-zinc-950 flex flex-col">
      <header className="border-b border-zinc-800/80 px-4 py-1.5 flex items-center gap-3 shrink-0 header-gradient">
        <button onClick={() => router.push("/")} className="text-zinc-500 hover:text-white transition-colors">
          <ArrowLeft size={16} />
        </button>
        <span className="font-medium text-white text-sm">{project.name}</span>
        <span className="px-1.5 py-0.5 rounded-md text-[10px] font-medium bg-green-500/10 text-green-400 border border-green-500/20">
          running
        </span>
        <div className="flex-1" />
        {project.previewUrl && (
          <a
            href={project.previewUrl}
            target="_blank"
            className="text-[11px] text-zinc-600 hover:text-zinc-400 font-mono transition-colors"
          >
            {project.previewUrl}
          </a>
        )}
        <button
          onClick={stopWorkspace}
          className="flex items-center gap-1.5 text-xs text-zinc-500 hover:text-red-400 px-2.5 py-1 rounded-lg hover:bg-red-500/10 transition-all"
        >
          <Square size={11} />
          Stop
        </button>
      </header>

      <div className="flex-1 min-h-0">
        <WorkspaceLayout
          projectId={projectId}
          previewUrl={project.previewUrl || ""}
          containerName={project.containerName || ""}
        />
      </div>
    </div>
  );
}
