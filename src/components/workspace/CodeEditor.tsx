"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import Editor from "@monaco-editor/react";
import { File, Folder, FolderOpen, RefreshCw, ChevronRight, ChevronDown, Check } from "lucide-react";
import { useAuth } from "@/lib/AuthProvider";

interface FileEntry {
  path: string;
  name: string;
  isDirectory: boolean;
}

interface TreeNode extends FileEntry {
  children?: TreeNode[];
  depth: number;
  loaded: boolean;
}

function getLanguage(filename: string): string {
  const ext = filename.split(".").pop() || "";
  const map: Record<string, string> = {
    ts: "typescript", tsx: "typescript", js: "javascript", jsx: "javascript",
    json: "json", html: "html", css: "css", md: "markdown", py: "python",
    sh: "shell", yaml: "yaml", yml: "yaml", sql: "sql", prisma: "prisma",
  };
  return map[ext] || "plaintext";
}

function sortEntries(entries: FileEntry[]): FileEntry[] {
  return [...entries].sort((a, b) => {
    if (a.isDirectory && !b.isDirectory) return -1;
    if (!a.isDirectory && b.isDirectory) return 1;
    return a.name.localeCompare(b.name);
  });
}

function FileTreeItem({
  node,
  expanded,
  currentFile,
  onToggle,
  onOpen,
}: {
  node: TreeNode;
  expanded: Set<string>;
  currentFile: string | null;
  onToggle: (path: string) => void;
  onOpen: (path: string) => void;
}) {
  const isExpanded = expanded.has(node.path);
  const isActive = currentFile === node.path;
  const indent = node.depth * 12;

  return (
    <>
      <button
        onClick={() => node.isDirectory ? onToggle(node.path) : onOpen(node.path)}
        className={`w-full text-left py-1 pr-3 text-xs flex items-center gap-1 hover:bg-zinc-800 truncate ${
          isActive ? "bg-zinc-800 text-white" : "text-zinc-400"
        }`}
        style={{ paddingLeft: `${8 + indent}px` }}
      >
        {node.isDirectory ? (
          <>
            {isExpanded ? (
              <ChevronDown size={10} className="text-zinc-600 shrink-0" />
            ) : (
              <ChevronRight size={10} className="text-zinc-600 shrink-0" />
            )}
            {isExpanded ? (
              <FolderOpen size={12} className="text-yellow-600 shrink-0" />
            ) : (
              <Folder size={12} className="text-zinc-600 shrink-0" />
            )}
          </>
        ) : (
          <>
            <span className="w-[10px] shrink-0" />
            <File size={12} className="text-zinc-600 shrink-0" />
          </>
        )}
        <span className="truncate">{node.name}</span>
      </button>
      {node.isDirectory && isExpanded && node.children && (
        <>
          {node.children.map((child) => (
            <FileTreeItem
              key={child.path}
              node={child}
              expanded={expanded}
              currentFile={currentFile}
              onToggle={onToggle}
              onOpen={onOpen}
            />
          ))}
          {node.children.length === 0 && node.loaded && (
            <div
              className="text-[10px] text-zinc-700 py-1 italic"
              style={{ paddingLeft: `${20 + indent}px` }}
            >
              empty
            </div>
          )}
        </>
      )}
    </>
  );
}

export function CodeEditor({ projectId }: { projectId: string }) {
  const { token } = useAuth();
  const [tree, setTree] = useState<TreeNode[]>([]);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [currentFile, setCurrentFile] = useState<string | null>(null);
  const [content, setContent] = useState("");
  const [savedContent, setSavedContent] = useState<string>("");
  const [loading, setLoading] = useState(false);
  const [saveStatus, setSaveStatus] = useState<"idle" | "saving" | "saved" | "error">("idle");
  const saveStatusTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const fetchDir = useCallback(async (dirPath: string): Promise<FileEntry[]> => {
    try {
      const res = await fetch(`/api/files/${projectId}/list?path=${encodeURIComponent(dirPath)}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      const data = await res.json();
      const files: FileEntry[] = data.files || (Array.isArray(data) ? data : []);
      return files.filter((f) => f.path !== dirPath);
    } catch {
      return [];
    }
  }, [projectId, token]);

  const buildNodes = useCallback((entries: FileEntry[], depth: number): TreeNode[] => {
    return sortEntries(entries).map((f) => ({
      ...f,
      depth,
      children: f.isDirectory ? [] : undefined,
      loaded: false,
    }));
  }, []);

  // Initial load
  const loadRoot = useCallback(async () => {
    const entries = await fetchDir("/workspace");
    const nodes = buildNodes(entries, 0);
    setTree(nodes);

    // Auto-expand src/ if it exists
    const srcNode = nodes.find((n) => n.name === "src" && n.isDirectory);
    if (srcNode) {
      const srcEntries = await fetchDir(srcNode.path);
      const srcChildren = buildNodes(srcEntries, 1);
      setTree((prev) =>
        prev.map((n) =>
          n.path === srcNode.path ? { ...n, children: srcChildren, loaded: true } : n
        )
      );
      setExpanded(new Set([srcNode.path]));
    }
  }, [fetchDir, buildNodes]);

  useEffect(() => {
    loadRoot();
    const interval = setInterval(loadRoot, 8000);
    return () => clearInterval(interval);
  }, [loadRoot]);

  const toggleDir = async (dirPath: string) => {
    const isExpanded = expanded.has(dirPath);

    if (isExpanded) {
      // Collapse
      setExpanded((prev) => {
        const next = new Set(prev);
        next.delete(dirPath);
        return next;
      });
      return;
    }

    // Expand — fetch children
    const entries = await fetchDir(dirPath);
    const depth = dirPath.replace("/workspace", "").split("/").filter(Boolean).length;
    const children = buildNodes(entries, depth);

    // Update tree recursively
    const updateChildren = (nodes: TreeNode[]): TreeNode[] =>
      nodes.map((n) => {
        if (n.path === dirPath) {
          return { ...n, children, loaded: true };
        }
        if (n.children) {
          return { ...n, children: updateChildren(n.children) };
        }
        return n;
      });

    setTree((prev) => updateChildren(prev));
    setExpanded((prev) => new Set(prev).add(dirPath));
  };

  const openFile = async (path: string) => {
    setLoading(true);
    try {
      const res = await fetch(`/api/files/${projectId}/read?path=${encodeURIComponent(path)}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      const data = await res.json();
      setCurrentFile(path);
      setContent(data.content);
      setSavedContent(data.content);
    } catch {}
    setLoading(false);
  };

  const saveFile = useCallback(async () => {
    if (!currentFile || !token) return;

    setSaveStatus("saving");
    if (saveStatusTimer.current) {
      clearTimeout(saveStatusTimer.current);
    }

    try {
      const res = await fetch(`/api/files/${projectId}/write`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ path: currentFile, content }),
      });

      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || "Save failed");
      }

      setSavedContent(content);
      setSaveStatus("saved");
      saveStatusTimer.current = setTimeout(() => setSaveStatus("idle"), 2000);
    } catch {
      setSaveStatus("error");
      saveStatusTimer.current = setTimeout(() => setSaveStatus("idle"), 3000);
    }
  }, [currentFile, content, token, projectId]);

  useEffect(() => {
    const handleSave = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "s") {
        e.preventDefault();
        saveFile();
      }
    };
    document.addEventListener("keydown", handleSave);
    return () => document.removeEventListener("keydown", handleSave);
  }, [saveFile]);

  // Cleanup timer on unmount
  useEffect(() => {
    return () => {
      if (saveStatusTimer.current) clearTimeout(saveStatusTimer.current);
    };
  }, []);

  const isDirty = content !== savedContent && currentFile !== null;
  const fileName = currentFile?.split("/").pop() || "";

  return (
    <div className="flex h-full bg-zinc-900">
      {/* File tree sidebar */}
      <div className="w-52 border-r border-zinc-800 overflow-y-auto shrink-0">
        <div className="flex items-center justify-between px-3 py-2 border-b border-zinc-800">
          <span className="text-xs text-zinc-500 font-medium uppercase tracking-wider">Files</span>
          <button onClick={loadRoot} className="text-zinc-500 hover:text-white">
            <RefreshCw size={12} />
          </button>
        </div>
        <div className="py-1">
          {tree.map((node) => (
            <FileTreeItem
              key={node.path}
              node={node}
              expanded={expanded}
              currentFile={currentFile}
              onToggle={toggleDir}
              onOpen={openFile}
            />
          ))}
          {tree.length === 0 && (
            <p className="text-xs text-zinc-600 px-3 py-4 text-center">No files yet</p>
          )}
        </div>
      </div>

      {/* Editor */}
      <div className="flex-1 flex flex-col min-w-0">
        {currentFile && (
          <div className="flex items-center justify-between px-3 py-1.5 border-b border-zinc-800 bg-zinc-900">
            <span className="text-xs text-zinc-400 font-mono truncate">
              {currentFile}
              {isDirty && <span className="text-yellow-500 ml-1" title="Unsaved changes">&bull;</span>}
            </span>
            <div className="flex items-center gap-2 shrink-0 ml-2">
              {saveStatus === "saving" && (
                <span className="text-xs text-zinc-500">Saving...</span>
              )}
              {saveStatus === "saved" && (
                <span className="text-xs text-green-500 flex items-center gap-1">
                  <Check size={10} /> Saved
                </span>
              )}
              {saveStatus === "error" && (
                <span className="text-xs text-red-400">Save failed</span>
              )}
              {isDirty && saveStatus === "idle" && (
                <button
                  onClick={saveFile}
                  className="text-[10px] text-zinc-500 hover:text-white px-1.5 py-0.5 rounded border border-zinc-700 hover:border-zinc-500"
                >
                  Save
                </button>
              )}
            </div>
          </div>
        )}
        <div className="flex-1">
          {currentFile ? (
            <Editor
              theme="vs-dark"
              language={getLanguage(fileName)}
              value={content}
              onChange={(v) => setContent(v || "")}
              options={{
                minimap: { enabled: false },
                fontSize: 13,
                fontFamily: "JetBrains Mono, Fira Code, monospace",
                lineNumbers: "on",
                scrollBeyondLastLine: false,
                wordWrap: "on",
                tabSize: 2,
                readOnly: false,
                padding: { top: 8 },
              }}
            />
          ) : (
            <div className="h-full flex items-center justify-center text-zinc-600 text-sm">
              Select a file to edit
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
