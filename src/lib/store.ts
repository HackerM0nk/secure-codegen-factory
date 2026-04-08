import { create } from "zustand";

interface ChatMessage {
  role: "user" | "assistant" | "system";
  content: string;
  timestamp: number;
}

interface AgentEvent {
  type: "thinking" | "tool_call" | "tool_result" | "text" | "error" | "done";
  data: any;
  timestamp: number;
}

interface WorkspaceState {
  // Chat
  messages: ChatMessage[];
  agentEvents: AgentEvent[];
  isAgentWorking: boolean;
  addMessage: (msg: Omit<ChatMessage, "timestamp">) => void;
  addAgentEvent: (event: Omit<AgentEvent, "timestamp">) => void;
  clearAgentEvents: () => void;
  setAgentWorking: (working: boolean) => void;

  // Editor
  currentFile: string | null;
  openFiles: string[];
  dirtyFiles: Set<string>;
  setCurrentFile: (file: string | null) => void;
  openFile: (file: string) => void;
  closeFile: (file: string) => void;
  markDirty: (file: string) => void;
  markClean: (file: string) => void;

  // Billing
  creditBalance: number | null;
  setCreditBalance: (balance: number) => void;

  // Security
  securityStats: { blocks: number; alerts: number; score: number } | null;
  setSecurityStats: (stats: { blocks: number; alerts: number; score: number }) => void;

  // Reset
  reset: () => void;
}

export const useWorkspaceStore = create<WorkspaceState>((set) => ({
  messages: [],
  agentEvents: [],
  isAgentWorking: false,
  currentFile: null,
  openFiles: [],
  dirtyFiles: new Set(),
  creditBalance: null,
  securityStats: null,

  addMessage: (msg) =>
    set((state) => ({
      messages: [...state.messages, { ...msg, timestamp: Date.now() }],
    })),

  addAgentEvent: (event) =>
    set((state) => ({
      agentEvents: [...state.agentEvents, { ...event, timestamp: Date.now() }],
    })),

  clearAgentEvents: () => set({ agentEvents: [] }),
  setAgentWorking: (working) => set({ isAgentWorking: working }),

  setCurrentFile: (file) => set({ currentFile: file }),
  openFile: (file) =>
    set((state) => ({
      currentFile: file,
      openFiles: state.openFiles.includes(file)
        ? state.openFiles
        : [...state.openFiles, file],
    })),
  closeFile: (file) =>
    set((state) => ({
      openFiles: state.openFiles.filter((f) => f !== file),
      currentFile:
        state.currentFile === file
          ? state.openFiles.find((f) => f !== file) || null
          : state.currentFile,
      dirtyFiles: new Set([...state.dirtyFiles].filter((f) => f !== file)),
    })),
  markDirty: (file) =>
    set((state) => ({
      dirtyFiles: new Set([...state.dirtyFiles, file]),
    })),
  markClean: (file) =>
    set((state) => ({
      dirtyFiles: new Set([...state.dirtyFiles].filter((f) => f !== file)),
    })),

  setCreditBalance: (balance) => set({ creditBalance: balance }),
  setSecurityStats: (stats) => set({ securityStats: stats }),
  reset: () =>
    set({
      messages: [],
      agentEvents: [],
      isAgentWorking: false,
      currentFile: null,
      openFiles: [],
      dirtyFiles: new Set(),
    }),
}));
