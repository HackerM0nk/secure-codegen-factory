"use client";

import { ArrowLeft, Shield } from "lucide-react";
import { useRouter } from "next/navigation";
import { SecurityDashboard } from "@/components/admin/SecurityDashboard";

export default function AdminPage() {
  const router = useRouter();

  return (
    <div className="min-h-screen bg-zinc-950 text-white">
      <header className="border-b border-zinc-800 px-6 py-4 flex items-center gap-4 header-gradient sticky top-0 z-10">
        <button onClick={() => router.push("/")} className="text-zinc-400 hover:text-white transition-colors">
          <ArrowLeft size={18} />
        </button>
        <div className="flex items-center gap-2">
          <Shield size={20} className="text-red-400" />
          <h1 className="text-lg font-semibold text-white">Security Dashboard</h1>
        </div>
      </header>
      <SecurityDashboard />
    </div>
  );
}
