import React, { useMemo, useState } from "react";
import {
  AppWindow,
  Search,
  FolderOpen,
  AlertTriangle,
  Sparkles,
  Clock,
  Trash2,
  CheckCircle2,
  HelpCircle,
} from "lucide-react";
import { AppInstallStatus, AppUsageRecord } from "../types/forensics";
import { formatBytes } from "../utils/format";

interface AppsTrackerViewProps {
  apps: AppUsageRecord[];
  isScanning: boolean;
  onRunScan: () => void;
  onReveal: (path: string) => void;
  onCleanupOrphans: (keys: string[]) => void;
}

function StatusBadge({ status }: { status: AppInstallStatus }) {
  switch (status) {
    case "installed":
      return (
        <span className="shrink-0 inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
          <CheckCircle2 className="w-3 h-3" /> Installed
        </span>
      );
    case "broken":
      return (
        <span className="shrink-0 inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold bg-red-500/15 text-red-300 border border-red-500/30">
          <AlertTriangle className="w-3 h-3" /> Broken
        </span>
      );
    case "orphaned":
      return (
        <span className="shrink-0 inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold bg-amber-500/15 text-amber-300 border border-amber-500/30">
          <AlertTriangle className="w-3 h-3" /> Orphaned
        </span>
      );
    default:
      return (
        <span className="shrink-0 inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold bg-white/[0.06] text-slate-300 border border-white/[0.1]">
          <HelpCircle className="w-3 h-3" /> Unverified
        </span>
      );
  }
}

export const AppsTrackerView: React.FC<AppsTrackerViewProps> = ({
  apps,
  isScanning,
  onRunScan,
  onReveal,
  onCleanupOrphans,
}) => {
  const [search, setSearch] = useState("");
  const [bloatedOnly, setBloatedOnly] = useState(false);
  const [orphansOnly, setOrphansOnly] = useState(false);

  const orphanedApps = useMemo(
    () => apps.filter((a) => a.status === "orphaned"),
    [apps]
  );

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return apps.filter((a) => {
      if (bloatedOnly && !a.isBloatedUnused) return false;
      if (orphansOnly && a.status !== "orphaned") return false;
      if (
        q &&
        !a.name.toLowerCase().includes(q) &&
        !a.publisher.toLowerCase().includes(q)
      ) {
        return false;
      }
      return true;
    });
  }, [apps, search, bloatedOnly, orphansOnly]);

  const bloatedCount = useMemo(
    () => apps.filter((a) => a.isBloatedUnused).length,
    [apps]
  );

  const bloatedBytes = useMemo(
    () =>
      apps
        .filter((a) => a.isBloatedUnused)
        .reduce((acc, a) => acc + a.estimatedSizeBytes, 0),
    [apps]
  );

  if (apps.length === 0 && !isScanning) {
    return (
      <div className="h-full flex items-center justify-center p-8">
        <div className="max-w-md w-full p-7 rounded-2xl bg-[#161920] border border-white/[0.08] text-center">
          <div className="w-12 h-12 rounded-2xl bg-[#06B6D4]/10 border border-[#06B6D4]/25 flex items-center justify-center mx-auto mb-4">
            <AppWindow className="w-6 h-6 text-[#06B6D4]" />
          </div>
          <h2 className="text-[16px] font-semibold text-white">
            Unused Applications & Binaries Tracker
          </h2>
          <p className="text-[13px] text-slate-400 mt-1.5 leading-relaxed">
            Scans the filesystem directly, cross-references the registry, and
            correlates real launch history (UserAssist + Prefetch). Flags bloated
            software and <span className="text-amber-300">orphaned entries</span> left
            behind by apps you already uninstalled.
          </p>
          <button
            onClick={onRunScan}
            className="mt-5 w-full py-2.5 px-4 rounded-xl bg-gradient-to-r from-[#06B6D4] to-[#3B82F6] text-white text-[13px] font-medium hover:brightness-110 transition-all flex items-center justify-center gap-2 cursor-pointer"
          >
            <Sparkles className="w-4 h-4" />
            Analyze Installed Applications
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col overflow-hidden">
      {/* Header Filters */}
      <div className="shrink-0 px-6 py-4 border-b border-white/[0.06] flex flex-wrap items-center justify-between gap-3 bg-[#0D0F12]">
        <div className="flex items-center gap-3">
          <div className="px-3 py-1.5 rounded-xl bg-[#161920] border border-white/[0.08] text-[12px] text-slate-300">
            <span className="font-mono font-semibold text-white">
              {apps.length}
            </span>{" "}
            apps
          </div>
          {bloatedCount > 0 && (
            <button
              onClick={() => setBloatedOnly((v) => !v)}
              className={`px-3 py-1.5 rounded-xl text-[12px] font-medium border flex items-center gap-1.5 transition-colors cursor-pointer ${
                bloatedOnly
                  ? "bg-amber-500/20 border-amber-500/40 text-amber-200"
                  : "bg-amber-500/10 border-amber-500/25 text-amber-300 hover:bg-amber-500/15"
              }`}
            >
              <AlertTriangle className="w-3.5 h-3.5" />
              {bloatedCount} Bloated & Unused ({formatBytes(bloatedBytes)})
            </button>
          )}
          {orphanedApps.length > 0 && (
            <button
              onClick={() => setOrphansOnly((v) => !v)}
              className={`px-3 py-1.5 rounded-xl text-[12px] font-medium border flex items-center gap-1.5 transition-colors cursor-pointer ${
                orphansOnly
                  ? "bg-red-500/20 border-red-500/40 text-red-200"
                  : "bg-red-500/10 border-red-500/25 text-red-300 hover:bg-red-500/15"
              }`}
            >
              <Trash2 className="w-3.5 h-3.5" />
              {orphanedApps.length} Orphaned Entries
            </button>
          )}
        </div>

        <div className="flex items-center gap-2">
          {orphanedApps.length > 0 && (
            <button
              onClick={() =>
                onCleanupOrphans(
                  orphanedApps.map((a) => a.registryPath).filter(Boolean) as string[]
                )
              }
              className="px-3 py-1.5 rounded-xl text-[12px] font-semibold bg-red-500/20 hover:bg-red-500/30 border border-red-500/40 text-red-100 transition-colors cursor-pointer"
              title="Delete the stale registry entries for all already-uninstalled apps"
            >
              Remove all {orphanedApps.length} stale entries
            </button>
          )}
          <div className="relative w-64">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter apps or publisher..."
              className="w-full pl-8 pr-3 py-1.5 rounded-xl bg-[#161920] border border-white/[0.08] text-[12px] text-white placeholder:text-slate-500 outline-none focus:border-[#06B6D4]"
            />
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="flex-1 overflow-auto">
        <table className="w-full border-collapse text-left">
          <thead className="sticky top-0 z-10 bg-[#111419]/95 backdrop-blur-md border-b border-white/[0.08] text-[11px] uppercase tracking-wider text-slate-400">
            <tr>
              <th className="py-2.5 pl-6 pr-3 font-semibold">Application</th>
              <th className="py-2.5 px-3 font-semibold w-44">Publisher</th>
              <th className="py-2.5 px-3 font-semibold w-28">Footprint</th>
              <th className="py-2.5 px-3 font-semibold w-60">Last Launched</th>
              <th className="py-2.5 px-3 font-semibold w-32">Signal</th>
              <th className="py-2.5 pl-3 pr-6 font-semibold w-28 text-right">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/[0.04] text-[12.5px]">
            {filtered.map((app) => (
              <tr
                key={app.id}
                className="hover:bg-[#161920] transition-colors group"
              >
                <td className="py-3 pl-6 pr-3 max-w-[320px]">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-medium text-slate-100 truncate">
                      {app.name}
                    </span>
                    <StatusBadge status={app.status} />
                    {app.isBloatedUnused && (
                      <span className="shrink-0 px-1.5 py-0.5 rounded text-[10px] font-semibold bg-amber-500/15 text-amber-300 border border-amber-500/30">
                        Bloated & Dormant
                      </span>
                    )}
                  </div>
                  <div
                    className="text-[11px] font-mono text-slate-500 truncate mt-0.5"
                    title={app.installLocation}
                  >
                    {app.installLocation || "No install location recorded"}
                  </div>
                </td>
                <td className="py-3 px-3 text-slate-400 truncate max-w-[170px]">
                  {app.publisher}
                </td>
                <td className="py-3 px-3 font-mono font-semibold text-white tabular-nums">
                  {app.estimatedSizeBytes > 0
                    ? formatBytes(app.estimatedSizeBytes)
                    : "—"}
                </td>
                <td className="py-3 px-3">
                  <span
                    className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px] font-medium border ${
                      app.daysUnused >= 365
                        ? "bg-red-500/10 text-red-300 border-red-500/25"
                        : app.daysUnused >= 90
                        ? "bg-amber-500/10 text-amber-300 border-amber-500/25"
                        : "bg-white/[0.04] text-slate-300 border-white/[0.08]"
                    }`}
                  >
                    <Clock className="w-3 h-3 shrink-0" />
                    <span className="truncate max-w-[190px]">
                      {app.relativeLastUsed}
                    </span>
                    {app.launchCount != null && (
                      <span className="text-[10px] font-mono text-slate-400">
                        ×{app.launchCount}
                      </span>
                    )}
                  </span>
                </td>
                <td className="py-3 px-3 text-[11px] font-mono text-slate-500">
                  {app.lastLaunchedSource}
                </td>
                <td className="py-3 pl-3 pr-6 text-right whitespace-nowrap">
                  {app.status === "orphaned" && app.registryPath ? (
                    <button
                      onClick={() => onCleanupOrphans([app.registryPath!])}
                      className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg hover:bg-red-500/20 text-slate-400 hover:text-red-300 cursor-pointer"
                      title="Delete this stale registry entry (the app is already uninstalled)"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      <span className="text-[11px] font-medium">Remove entry</span>
                    </button>
                  ) : app.exists && (app.executablePath || app.installLocation) ? (
                    <button
                      onClick={() =>
                        onReveal(app.executablePath || app.installLocation)
                      }
                      className="p-1.5 rounded-lg hover:bg-white/[0.08] text-slate-400 hover:text-[#06B6D4] cursor-pointer"
                      title="Reveal in Explorer"
                    >
                      <FolderOpen className="w-4 h-4" />
                    </button>
                  ) : (
                    <span className="text-[11px] text-slate-600 italic">
                      Files missing
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
