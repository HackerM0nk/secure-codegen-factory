"use client";

import { useState } from "react";
import { RefreshCw, ExternalLink, Globe } from "lucide-react";

export function PreviewPanel({ previewUrl }: { previewUrl: string }) {
  const [key, setKey] = useState(0);

  if (!previewUrl) {
    return (
      <div className="h-full bg-zinc-900 flex items-center justify-center">
        <div className="text-center">
          <div className="inline-flex items-center justify-center w-10 h-10 rounded-xl bg-zinc-800 border border-zinc-700/50 mb-3">
            <Globe size={18} className="text-zinc-600" />
          </div>
          <p className="text-sm text-zinc-500">No preview available</p>
          <p className="text-xs text-zinc-700 mt-1">Start the dev server to see a preview</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full bg-zinc-900">
      <div className="flex items-center gap-2 px-3 py-1.5 border-b border-zinc-800/80 shrink-0">
        <button
          onClick={() => setKey((k) => k + 1)}
          className="p-1 text-zinc-500 hover:text-white transition-colors rounded-md hover:bg-zinc-800"
          title="Refresh"
        >
          <RefreshCw size={12} />
        </button>
        <div className="flex-1 bg-zinc-800/50 rounded-md px-2.5 py-1 text-[11px] text-zinc-500 font-mono truncate border border-zinc-700/30">
          {previewUrl}
        </div>
        <a
          href={previewUrl}
          target="_blank"
          className="p-1 text-zinc-500 hover:text-white transition-colors rounded-md hover:bg-zinc-800"
          title="Open in new tab"
        >
          <ExternalLink size={12} />
        </a>
      </div>
      <div className="flex-1 relative">
        <iframe
          key={key}
          src={previewUrl}
          className="absolute inset-0 w-full h-full bg-white"
          sandbox="allow-scripts allow-same-origin allow-forms allow-popups allow-modals"
        />
      </div>
    </div>
  );
}
