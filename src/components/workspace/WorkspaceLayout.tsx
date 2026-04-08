"use client";

import dynamic from "next/dynamic";
import { Panel, PanelGroup, PanelResizeHandle } from "react-resizable-panels";
import { ChatPanel } from "./ChatPanel";
import { PreviewPanel } from "./PreviewPanel";

const CodeEditor = dynamic(() => import("./CodeEditor").then((m) => m.CodeEditor), {
  ssr: false,
  loading: () => (
    <div className="h-full bg-zinc-900 flex items-center justify-center text-zinc-600 text-sm">
      Loading editor...
    </div>
  ),
});

const TerminalPanel = dynamic(() => import("./TerminalPanel").then((m) => m.TerminalPanel), {
  ssr: false,
  loading: () => (
    <div className="h-full bg-zinc-950 flex items-center justify-center text-zinc-600 text-sm">
      Loading terminal...
    </div>
  ),
});

interface Props {
  projectId: string;
  previewUrl: string;
  containerName: string;
}

function ResizeHandleH() {
  return (
    <PanelResizeHandle className="w-[3px] bg-zinc-800/60 hover:bg-blue-500/70 active:bg-blue-500 transition-colors cursor-col-resize relative group">
      <div className="absolute inset-y-0 -left-1 -right-1" />
    </PanelResizeHandle>
  );
}

function ResizeHandleV() {
  return (
    <PanelResizeHandle className="h-[3px] bg-zinc-800/60 hover:bg-blue-500/70 active:bg-blue-500 transition-colors cursor-row-resize relative group">
      <div className="absolute inset-x-0 -top-1 -bottom-1" />
    </PanelResizeHandle>
  );
}

export function WorkspaceLayout({ projectId, previewUrl, containerName }: Props) {
  return (
    <PanelGroup direction="horizontal" className="h-full">
      <Panel defaultSize={28} minSize={18}>
        <ChatPanel projectId={projectId} />
      </Panel>

      <ResizeHandleH />

      <Panel defaultSize={72} minSize={40}>
        <PanelGroup direction="vertical">
          <Panel defaultSize={65} minSize={30}>
            <PanelGroup direction="horizontal">
              <Panel defaultSize={50} minSize={20}>
                <CodeEditor projectId={projectId} />
              </Panel>
              <ResizeHandleH />
              <Panel defaultSize={50} minSize={20}>
                <PreviewPanel previewUrl={previewUrl} />
              </Panel>
            </PanelGroup>
          </Panel>

          <ResizeHandleV />

          <Panel defaultSize={35} minSize={10}>
            <TerminalPanel containerName={containerName} projectId={projectId} />
          </Panel>
        </PanelGroup>
      </Panel>
    </PanelGroup>
  );
}
