import React from "react";
import { motion } from "framer-motion";
import {
  Sparkles,
  HardDrive,
  AppWindow,
  ShieldCheck,
  Flame,
  Trash2,
  Activity,
  Lightbulb,
} from "lucide-react";
import { NavTab } from "../types/forensics";
import { formatBytes } from "../utils/format";

interface SidebarProps {
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  permanentShred: boolean;
  onToggleShred: (val: boolean) => void;
  sessionFreedBytes: number;
  whitelistCount: number;
  isScanning: boolean;
}

const NAV_ITEMS: {
  id: NavTab;
  label: string;
  subtitle: string;
  icon: React.ComponentType<{ className?: string }>;
}[] = [
  {
    id: "quick_clean",
    label: "Quick Clean",
    subtitle: "System & browser hygiene",
    icon: Sparkles,
  },
  {
    id: "insights",
    label: "Insights",
    subtitle: "Smart recommendations",
    icon: Lightbulb,
  },
  {
    id: "forensics",
    label: "Deep Forensics",
    subtitle: "Stale & forgotten files",
    icon: HardDrive,
  },
  {
    id: "apps",
    label: "Unused Apps",
    subtitle: "Launch & bloat tracker",
    icon: AppWindow,
  },
  {
    id: "whitelist",
    label: "Whitelist",
    subtitle: "Excluded paths & files",
    icon: ShieldCheck,
  },
];

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  permanentShred,
  onToggleShred,
  sessionFreedBytes,
  whitelistCount,
  isScanning,
}) => {
  return (
    <aside className="w-[248px] shrink-0 h-full bg-[#111419] border-r border-white/[0.08] flex flex-col justify-between select-none">
      {/* Brand Header */}
      <div>
        <div className="px-5 pt-5 pb-4 border-b border-white/[0.06] flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-[#06B6D4] to-[#3B82F6] p-[1px] shadow-[0_0_20px_rgba(6,182,212,0.28)]">
              <div className="w-full h-full rounded-[7px] bg-[#0D0F12] flex items-center justify-center">
                <Activity className="w-4 h-4 text-[#06B6D4]" />
              </div>
            </div>
            <div>
              <div className="text-[14px] font-semibold tracking-tight text-white leading-none">
                OptimizeMe
              </div>
              <div className="text-[11px] text-slate-400 mt-1 flex items-center gap-1.5">
                <span
                  className={`w-1.5 h-1.5 rounded-full ${
                    isScanning
                      ? "bg-[#06B6D4] animate-pulse"
                      : "bg-emerald-400"
                  }`}
                />
                <span>{isScanning ? "Scanning I/O..." : "Engine Ready"}</span>
              </div>
            </div>
          </div>
          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-white/[0.05] text-slate-400 border border-white/[0.08]">
            v0.1
          </span>
        </div>

        {/* Navigation Links */}
        <nav className="p-3 space-y-1">
          <div className="px-2.5 pb-1.5 pt-1 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
            Modules
          </div>
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const active = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onSelectTab(item.id)}
                className={`relative w-full text-left px-3 py-2.5 rounded-lg transition-colors flex items-center gap-3 group ${
                  active
                    ? "text-white"
                    : "text-slate-400 hover:text-slate-200 hover:bg-white/[0.03]"
                }`}
              >
                {active && (
                  <motion.div
                    layoutId="sidebar-active-pill"
                    transition={{ type: "spring", stiffness: 420, damping: 34 }}
                    className="absolute inset-0 rounded-lg bg-[#161920] border border-white/[0.1] shadow-sm"
                  />
                )}
                <Icon
                  className={`relative z-10 w-4 h-4 shrink-0 transition-colors ${
                    active
                      ? "text-[#06B6D4]"
                      : "text-slate-500 group-hover:text-slate-300"
                  }`}
                />
                <div className="relative z-10 min-w-0 flex-1">
                  <div className="flex items-center justify-between">
                    <span className="text-[13px] font-medium truncate">
                      {item.label}
                    </span>
                    {item.id === "whitelist" && whitelistCount > 0 && (
                      <span className="text-[10px] font-mono px-1.5 py-0.2 rounded-full bg-white/[0.06] text-slate-300">
                        {whitelistCount}
                      </span>
                    )}
                  </div>
                  <div className="text-[11px] text-slate-500 truncate">
                    {item.subtitle}
                  </div>
                </div>
              </button>
            );
          })}
        </nav>
      </div>

      {/* Bottom Triage Mode & Session Telemetry */}
      <div className="p-3 space-y-2.5 border-t border-white/[0.06]">
        <div className="p-3 rounded-xl bg-[#161920] border border-white/[0.07]">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[11px] font-medium text-slate-300 flex items-center gap-1.5">
              {permanentShred ? (
                <Flame className="w-3.5 h-3.5 text-red-400" />
              ) : (
                <Trash2 className="w-3.5 h-3.5 text-[#06B6D4]" />
              )}
              Deletion Mode
            </span>
            <button
              onClick={() => onToggleShred(!permanentShred)}
              className={`relative w-9 h-5 rounded-full transition-colors border ${
                permanentShred
                  ? "bg-red-500/30 border-red-500/50"
                  : "bg-white/[0.08] border-white/[0.12]"
              }`}
              title="Toggle between safe Recycle Bin deletion and permanent zero-overwrite shred"
            >
              <span
                className={`block w-3.5 h-3.5 rounded-full transition-transform ${
                  permanentShred
                    ? "translate-x-4.5 bg-red-400"
                    : "translate-x-0.5 bg-[#06B6D4]"
                }`}
              />
            </button>
          </div>
          <p className="text-[11px] leading-relaxed text-slate-500">
            {permanentShred
              ? "Secure Shred active: files are overwritten & permanently erased."
              : "Safe Mode active: files move to Recycle Bin / Trash."}
          </p>
        </div>

        <div className="px-3 py-2.5 rounded-xl bg-[#161920]/70 border border-white/[0.06] flex items-center justify-between">
          <div>
            <div className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">
              Session Reclaimed
            </div>
            <div className="text-[14px] font-semibold font-mono text-emerald-400 tabular-nums mt-0.5">
              {formatBytes(sessionFreedBytes)}
            </div>
          </div>
          <div className="w-2 h-2 rounded-full bg-emerald-400/70" />
        </div>
      </div>
    </aside>
  );
};
