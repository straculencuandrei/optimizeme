import React, { useMemo, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  FolderPlus,
  Search,
  ArrowUpDown,
  ArrowDown,
  ArrowUp,
  Eye,
  FolderOpen,
  ShieldCheck,
  Trash2,
  Flame,
  Clock,
  Tag,
  HardDrive,
  X,
  CheckSquare,
  Square,
  Sparkles,
} from "lucide-react";
import {
  DefaultScanTarget,
  FileCategory,
  FileRecord,
  ForensicsScanResult,
  SortDirection,
  SortField,
  StalePresetDays,
  StorageBreakdownItem,
} from "../types/forensics";
import {
  formatBytes,
  getCategoryMeta,
  getStalenessSeverity,
} from "../utils/format";

interface ForensicsViewProps {
  defaultTargets: DefaultScanTarget[];
  selectedTargetPaths: string[];
  customTargetPaths: string[];
  minSizeBytes: number;
  isScanning: boolean;
  scanResult: ForensicsScanResult | null;
  streamedFiles: FileRecord[];
  permanentShred: boolean;
  onToggleTargetPath: (path: string) => void;
  onAddCustomPath: () => void;
  onRemoveCustomPath: (path: string) => void;
  onChangeMinSize: (bytes: number) => void;
  onRunScan: () => void;
  wiztreePath: string | null;
  onRunTurboScan: (root: string) => void;
  onQuickLook: (file: FileRecord) => void;
  onReveal: (path: string) => void;
  onIgnoreFile: (path: string) => void;
  onDeleteFiles: (paths: string[]) => void;
}

const STALE_PRESETS: { label: string; days: StalePresetDays }[] = [
  { label: "All Ages", days: 0 },
  { label: "30+ days", days: 30 },
  { label: "6+ months", days: 180 },
  { label: "1+ year", days: 365 },
  { label: "2+ years", days: 730 },
];

const TYPE_FILTERS: { id: "all" | FileCategory; label: string }[] = [
  { id: "all", label: "All Types" },
  { id: "installer", label: "Installers" },
  { id: "archive", label: "Archives" },
  { id: "media", label: "Media" },
  { id: "disk_image", label: "Disk Images" },
  { id: "document", label: "Documents" },
];

const MIN_SIZE_OPTIONS = [
  { label: "Any size (0 B+)", value: 0 },
  { label: "1 MB+", value: 1024 * 1024 },
  { label: "10 MB+", value: 10 * 1024 * 1024 },
  { label: "50 MB+", value: 50 * 1024 * 1024 },
  { label: "250 MB+", value: 250 * 1024 * 1024 },
];

export const ForensicsView: React.FC<ForensicsViewProps> = ({
  defaultTargets,
  selectedTargetPaths,
  customTargetPaths,
  minSizeBytes,
  isScanning,
  scanResult,
  streamedFiles,
  permanentShred,
  onToggleTargetPath,
  onAddCustomPath,
  onRemoveCustomPath,
  onChangeMinSize,
  onRunScan,
  wiztreePath,
  onRunTurboScan,
  onQuickLook,
  onReveal,
  onIgnoreFile,
  onDeleteFiles,
}) => {
  const [staleDays, setStaleDays] = useState<StalePresetDays>(30);
  const [typeFilter, setTypeFilter] = useState<"all" | FileCategory>("all");
  const [downloadForgetOnly, setDownloadForgetOnly] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [sortField, setSortField] = useState<SortField>("impact");
  const [sortDir, setSortDir] = useState<SortDirection>("desc");
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [visibleLimit, setVisibleLimit] = useState(200);

  // Merge final or live-streamed records, deduplicated defensively by id
  const rawFiles = useMemo(() => {
    const source = scanResult ? scanResult.files : streamedFiles;
    const seen = new Set<string>();
    const unique: FileRecord[] = [];
    for (const f of source) {
      if (!seen.has(f.id)) {
        seen.add(f.id);
        unique.push(f);
      }
    }
    return unique;
  }, [scanResult, streamedFiles]);

  const filteredFiles = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    const list = rawFiles.filter((f) => {
      if (staleDays > 0 && f.daysUnused < staleDays) return false;
      if (typeFilter !== "all" && f.category !== typeFilter) return false;
      if (downloadForgetOnly && !f.tags.includes("Download & Forget")) return false;
      if (
        q &&
        !f.name.toLowerCase().includes(q) &&
        !f.path.toLowerCase().includes(q) &&
        !f.extension.toLowerCase().includes(q)
      ) {
        return false;
      }
      return true;
    });

    list.sort((a, b) => {
      let cmp = 0;
      if (sortField === "impact") {
        cmp = Number(a.impactScore) - Number(b.impactScore);
      } else if (sortField === "size") {
        cmp = Number(a.sizeBytes) - Number(b.sizeBytes);
      } else if (sortField === "unused") {
        cmp = Number(a.daysUnused) - Number(b.daysUnused);
      } else {
        cmp = a.name.localeCompare(b.name);
      }
      if (cmp === 0) {
        cmp = Number(a.sizeBytes) - Number(b.sizeBytes);
      }
      if (cmp === 0) {
        return a.id.localeCompare(b.id);
      }
      return sortDir === "desc" ? -cmp : cmp;
    });

    return list;
  }, [rawFiles, staleDays, typeFilter, downloadForgetOnly, searchQuery, sortField, sortDir]);

  const visibleFiles = useMemo(
    () => filteredFiles.slice(0, visibleLimit),
    [filteredFiles, visibleLimit]
  );

  const filteredTotalBytes = useMemo(
    () => filteredFiles.reduce((acc, f) => acc + f.sizeBytes, 0),
    [filteredFiles]
  );

  const breakdown: StorageBreakdownItem[] = useMemo(() => {
    if (scanResult?.breakdown && scanResult.breakdown.length > 0) {
      return scanResult.breakdown;
    }
    return [];
  }, [scanResult]);

  const totalBreakdownBytes = useMemo(
    () => breakdown.reduce((acc, b) => acc + b.sizeBytes, 0),
    [breakdown]
  );

  const selectedRecords = useMemo(
    () => filteredFiles.filter((f) => selectedIds.has(f.id)),
    [filteredFiles, selectedIds]
  );

  const selectedTotalBytes = useMemo(
    () => selectedRecords.reduce((acc, f) => acc + f.sizeBytes, 0),
    [selectedRecords]
  );

  const maxImpact = useMemo(() => {
    let m = 1;
    for (const f of visibleFiles) {
      if (f.impactScore > m) m = f.impactScore;
    }
    return m;
  }, [visibleFiles]);

  const handleSort = (field: SortField) => {
    setVisibleLimit(200);
    if (sortField === field) {
      setSortDir((d) => (d === "desc" ? "asc" : "desc"));
    } else {
      setSortField(field);
      setSortDir(field === "name" ? "asc" : "desc");
    }
  };

  const toggleRow = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleAllVisible = () => {
    const allSelected =
      visibleFiles.length > 0 && visibleFiles.every((f) => selectedIds.has(f.id));
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (allSelected) {
        visibleFiles.forEach((f) => next.delete(f.id));
      } else {
        visibleFiles.forEach((f) => next.add(f.id));
      }
      return next;
    });
  };

  const renderSortIcon = (field: SortField) => {
    if (sortField !== field) {
      return <ArrowUpDown className="w-3 h-3 text-slate-600" />;
    }
    return sortDir === "desc" ? (
      <ArrowDown className="w-3 h-3 text-[#06B6D4]" />
    ) : (
      <ArrowUp className="w-3 h-3 text-[#06B6D4]" />
    );
  };

  const existingTargets = defaultTargets.filter((t) => t.exists);
  const allTargetsSelected =
    existingTargets.length > 0 &&
    existingTargets.every((t) => selectedTargetPaths.includes(t.path));

  const handleToggleAllTargets = () => {
    if (allTargetsSelected) {
      existingTargets.forEach(
        (t) => selectedTargetPaths.includes(t.path) && onToggleTargetPath(t.path)
      );
    } else {
      existingTargets.forEach(
        (t) => !selectedTargetPaths.includes(t.path) && onToggleTargetPath(t.path)
      );
    }
  };

  const turboRoot =
    defaultTargets.find((t) => t.id.startsWith("drive_") && t.exists)?.path ??
    "C:\\";

  return (
    <div className="h-full flex flex-col overflow-hidden">
      {/* Scope & Controls Strip */}
      <div className="shrink-0 px-6 pt-4 pb-3 space-y-3 border-b border-white/[0.06] bg-[#0D0F12]">
        {/* Target Folders + Min Size */}
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mr-1.5">
              Targets:
            </span>
            <button
              onClick={handleToggleAllTargets}
              className="px-2.5 py-1 rounded-lg text-[12px] font-semibold border transition-colors cursor-pointer bg-[#161920] border-white/[0.08] text-slate-400 hover:text-slate-200"
              title="Toggle all available targets"
            >
              {allTargetsSelected ? "Clear all" : "Select all"}
            </button>
            {defaultTargets
              .filter((t) => t.exists)
              .map((target) => {
                const active = selectedTargetPaths.includes(target.path);
                return (
                  <button
                    key={target.id}
                    onClick={() => onToggleTargetPath(target.path)}
                    className={`px-2.5 py-1 rounded-lg text-[12px] font-medium border transition-colors cursor-pointer ${
                      active
                        ? "bg-[#06B6D4]/15 border-[#06B6D4]/40 text-[#67E8F9]"
                        : "bg-[#161920] border-white/[0.08] text-slate-400 hover:text-slate-200"
                    }`}
                    title={target.path}
                  >
                    {target.label}
                  </button>
                );
              })}

            {customTargetPaths.map((cp) => (
              <span
                key={cp}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[12px] font-medium bg-[#3B82F6]/15 border border-[#3B82F6]/35 text-blue-200"
                title={cp}
              >
                <span className="max-w-[160px] truncate">{cp}</span>
                <button
                  onClick={() => onRemoveCustomPath(cp)}
                  className="hover:text-white cursor-pointer"
                >
                  <X className="w-3 h-3" />
                </button>
              </span>
            ))}

            <button
              onClick={onAddCustomPath}
              className="px-2.5 py-1 rounded-lg text-[12px] font-medium bg-white/[0.04] hover:bg-white/[0.08] border border-dashed border-white/[0.16] text-slate-300 flex items-center gap-1.5 cursor-pointer"
            >
              <FolderPlus className="w-3.5 h-3.5 text-[#06B6D4]" />
              Custom Folder
            </button>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-[11px] text-slate-500 font-medium">Min Size:</span>
            <select
              value={minSizeBytes}
              onChange={(e) => onChangeMinSize(Number(e.target.value))}
              className="bg-[#161920] border border-white/[0.1] rounded-lg px-2.5 py-1 text-[12px] text-slate-200 outline-none focus:border-[#06B6D4]"
            >
              {MIN_SIZE_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>

            {wiztreePath && (
              <button
                onClick={() => onRunTurboScan(turboRoot)}
                disabled={isScanning}
                className="px-2.5 py-1 rounded-lg text-[12px] font-semibold bg-violet-500/20 border border-violet-500/40 text-violet-200 hover:bg-violet-500/30 disabled:opacity-40 cursor-pointer"
                title={`Whole-drive MFT scan via WizTree (${wiztreePath})`}
              >
                MFT Turbo Scan {turboRoot}
              </button>
            )}
          </div>
        </div>

        {/* Horizontal Storage Breakdown Bar */}
        {breakdown.length > 0 && totalBreakdownBytes > 0 && (
          <div className="p-3 rounded-xl bg-[#161920] border border-white/[0.07] space-y-2">
            <div className="flex items-center justify-between text-[11px]">
              <span className="font-semibold uppercase tracking-wider text-slate-400">
                Storage Breakdown by File Category
              </span>
              <span className="font-mono text-slate-300 tabular-nums">
                {scanResult?.totalFilesScanned.toLocaleString()} indexed •{" "}
                {formatBytes(totalBreakdownBytes)} matched
              </span>
            </div>
            <div className="h-2.5 w-full rounded-full bg-[#0D0F12] overflow-hidden flex gap-[2px]">
              {breakdown.map((item) => {
                const pct = (item.sizeBytes / totalBreakdownBytes) * 100;
                if (pct < 0.6) return null;
                return (
                  <div
                    key={item.category}
                    style={{
                      width: `${pct}%`,
                      backgroundColor: item.color,
                    }}
                    title={`${item.category}: ${formatBytes(item.sizeBytes)} (${item.fileCount} files)`}
                    className="h-full first:rounded-l-full last:rounded-r-full transition-all"
                  />
                );
              })}
            </div>
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-slate-400">
              {breakdown.slice(0, 6).map((item) => (
                <div key={item.category} className="flex items-center gap-1.5">
                  <span
                    className="w-2 h-2 rounded-full"
                    style={{ backgroundColor: item.color }}
                  />
                  <span>{item.category}</span>
                  <span className="font-mono text-slate-300 tabular-nums">
                    {formatBytes(item.sizeBytes)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Filter & Search Row */}
        <div className="flex flex-wrap items-center justify-between gap-2.5">
          <div className="flex flex-wrap items-center gap-2">
            {/* Stale Timeframe Presets */}
            <div className="inline-flex items-center p-0.5 rounded-xl bg-[#161920] border border-white/[0.08]">
              <Clock className="w-3.5 h-3.5 text-slate-500 ml-2 mr-1.5" />
              {STALE_PRESETS.map((preset) => (
                <button
                  key={preset.days}
                  onClick={() => setStaleDays(preset.days)}
                  className={`px-2.5 py-1 rounded-lg text-[11.5px] font-medium transition-colors cursor-pointer ${
                    staleDays === preset.days
                      ? "bg-[#06B6D4]/20 text-[#67E8F9]"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  {preset.label}
                </button>
              ))}
            </div>

            {/* File Type Pills */}
            <div className="inline-flex items-center p-0.5 rounded-xl bg-[#161920] border border-white/[0.08]">
              {TYPE_FILTERS.map((tf) => (
                <button
                  key={tf.id}
                  onClick={() => setTypeFilter(tf.id)}
                  className={`px-2.5 py-1 rounded-lg text-[11.5px] font-medium transition-colors cursor-pointer ${
                    typeFilter === tf.id
                      ? "bg-[#3B82F6]/20 text-blue-200"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  {tf.label}
                </button>
              ))}
            </div>

            {/* Download & Forget Toggle */}
            <button
              onClick={() => setDownloadForgetOnly((v) => !v)}
              className={`px-3 py-1.5 rounded-xl text-[11.5px] font-medium border flex items-center gap-1.5 transition-colors cursor-pointer ${
                downloadForgetOnly
                  ? "bg-amber-500/20 border-amber-500/40 text-amber-200"
                  : "bg-[#161920] border-white/[0.08] text-slate-400 hover:text-slate-200"
              }`}
            >
              <Tag className="w-3.5 h-3.5" />
              Download & Forget
            </button>
          </div>

          {/* Search */}
          <div className="relative w-64">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter filename, ext, or path..."
              className="w-full pl-8 pr-3 py-1.5 rounded-xl bg-[#161920] border border-white/[0.08] text-[12px] text-white placeholder:text-slate-500 outline-none focus:border-[#06B6D4]"
            />
          </div>
        </div>
      </div>

      {/* Main Data Table Workspace */}
      <div className="flex-1 overflow-auto relative">
        {rawFiles.length === 0 && !isScanning ? (
          <div className="h-full flex items-center justify-center p-8">
            <div className="max-w-md w-full p-7 rounded-2xl bg-[#161920] border border-white/[0.08] text-center">
              <div className="w-12 h-12 rounded-2xl bg-[#3B82F6]/10 border border-[#3B82F6]/25 flex items-center justify-center mx-auto mb-4">
                <HardDrive className="w-6 h-6 text-[#3B82F6]" />
              </div>
              <h2 className="text-[16px] font-semibold text-white">
                Deep Storage Forensics
              </h2>
              <p className="text-[13px] text-slate-400 mt-1.5 leading-relaxed">
                Analyze selected directories in parallel worker threads to surface
                huge, forgotten files and <span className="text-amber-300">Download & Forget</span> installers.
              </p>
              <button
                onClick={onRunScan}
                disabled={selectedTargetPaths.length === 0 && customTargetPaths.length === 0}
                className="mt-5 w-full py-2.5 px-4 rounded-xl bg-gradient-to-r from-[#06B6D4] to-[#3B82F6] disabled:opacity-40 text-white text-[13px] font-medium hover:brightness-110 transition-all flex items-center justify-center gap-2 cursor-pointer"
              >
                <Sparkles className="w-4 h-4" />
                Start Deep Forensics Scan
              </button>
            </div>
          </div>
        ) : filteredFiles.length === 0 && !isScanning ? (
          <div className="h-full flex items-center justify-center p-8 text-center">
            <div>
              <p className="text-[14px] font-medium text-slate-300">
                No files match your current age/type filters.
              </p>
              <p className="text-[12px] text-slate-500 mt-1">
                Try lowering the stale threshold to &ldquo;All Ages&rdquo; or clearing the search box.
              </p>
            </div>
          </div>
        ) : (
          <table className="w-full border-collapse text-left">
            <thead className="sticky top-0 z-20 bg-[#111419]/95 backdrop-blur-md border-b border-white/[0.08] text-[11px] uppercase tracking-wider text-slate-400">
              <tr>
                <th className="py-2.5 pl-6 pr-2 w-10">
                  <button
                    onClick={toggleAllVisible}
                    className="text-slate-400 hover:text-[#06B6D4] cursor-pointer"
                    title="Select all visible rows"
                  >
                    {visibleFiles.length > 0 &&
                    visibleFiles.every((f) => selectedIds.has(f.id)) ? (
                      <CheckSquare className="w-4 h-4 text-[#06B6D4]" />
                    ) : (
                      <Square className="w-4 h-4" />
                    )}
                  </button>
                </th>
                <th className="py-2.5 px-3">
                  <button
                    onClick={() => handleSort("name")}
                    className="flex items-center gap-1.5 font-semibold hover:text-white cursor-pointer"
                  >
                    File & Location
                    {renderSortIcon("name")}
                  </button>
                </th>
                <th className="py-2.5 px-3 w-28 font-semibold">Category</th>
                <th className="py-2.5 px-3 w-28">
                  <button
                    onClick={() => handleSort("size")}
                    className="flex items-center gap-1.5 font-semibold hover:text-white cursor-pointer"
                  >
                    Size
                    {renderSortIcon("size")}
                  </button>
                </th>
                <th className="py-2.5 px-3 w-64">
                  <button
                    onClick={() => handleSort("unused")}
                    className="flex items-center gap-1.5 font-semibold hover:text-white cursor-pointer"
                  >
                    Time Since Last Used
                    {renderSortIcon("unused")}
                  </button>
                </th>
                <th className="py-2.5 px-3 w-32">
                  <button
                    onClick={() => handleSort("impact")}
                    className="flex items-center gap-1.5 font-semibold hover:text-white cursor-pointer"
                  >
                    Impact
                    {renderSortIcon("impact")}
                  </button>
                </th>
                <th className="py-2.5 pl-3 pr-6 w-36 text-right font-semibold">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.04] text-[12.5px]">
              {visibleFiles.map((file) => {
                const checked = selectedIds.has(file.id);
                const catMeta = getCategoryMeta(file.category);
                const staleMeta = getStalenessSeverity(file.daysUnused);
                const impactPct = Math.max(
                  6,
                  Math.min(100, (file.impactScore / maxImpact) * 100)
                );

                return (
                  <tr
                    key={file.id}
                    className={`group transition-colors ${
                      checked
                        ? "bg-[#06B6D4]/[0.07]"
                        : "hover:bg-[#161920]"
                    }`}
                  >
                    <td className="py-2.5 pl-6 pr-2 align-middle">
                      <button
                        onClick={() => toggleRow(file.id)}
                        className="cursor-pointer text-slate-500 hover:text-[#06B6D4]"
                      >
                        {checked ? (
                          <CheckSquare className="w-4 h-4 text-[#06B6D4]" />
                        ) : (
                          <Square className="w-4 h-4" />
                        )}
                      </button>
                    </td>

                    <td className="py-2.5 px-3 max-w-[340px]">
                      <div className="flex items-center gap-2 min-w-0">
                        <span
                          className="font-medium text-slate-100 truncate cursor-pointer hover:text-[#06B6D4]"
                          onClick={() => onQuickLook(file)}
                          title={file.name}
                        >
                          {file.name}
                        </span>
                        {file.tags.slice(0, 2).map((tag) => (
                          <span
                            key={tag}
                            className={`shrink-0 px-1.5 py-0.5 rounded text-[10px] font-semibold border ${
                              tag === "Download & Forget"
                                ? "bg-amber-500/15 text-amber-300 border-amber-500/30"
                                : tag === "Stale Giant"
                                ? "bg-red-500/15 text-red-300 border-red-500/30"
                                : "bg-white/[0.06] text-slate-300 border-white/[0.1]"
                            }`}
                          >
                            {tag}
                          </span>
                        ))}
                      </div>
                      <div
                        className="text-[11px] font-mono text-slate-500 truncate mt-0.5"
                        title={file.parentDir}
                      >
                        {file.parentDir}
                      </div>
                    </td>

                    <td className="py-2.5 px-3 align-middle">
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-medium border ${catMeta.bgClass} ${catMeta.textClass}`}
                      >
                        {catMeta.label}
                      </span>
                    </td>

                    <td className="py-2.5 px-3 align-middle font-mono font-semibold text-white tabular-nums whitespace-nowrap">
                      {formatBytes(file.sizeBytes)}
                    </td>

                    <td className="py-2.5 px-3 align-middle">
                      <span
                        className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px] font-medium border ${staleMeta.badgeClass}`}
                        title={`Source: ${file.lastUsedSource}`}
                      >
                        <span
                          className={`w-1.5 h-1.5 rounded-full shrink-0 ${staleMeta.dotClass}`}
                        />
                        <span className="truncate max-w-[215px]">
                          {file.relativeLastUsed}
                        </span>
                      </span>
                    </td>

                    <td className="py-2.5 px-3 align-middle">
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1.5 rounded-full bg-white/[0.06] overflow-hidden">
                          <div
                            className="h-full rounded-full bg-gradient-to-r from-[#06B6D4] to-[#F59E0B]"
                            style={{ width: `${impactPct}%` }}
                          />
                        </div>
                        <span className="text-[11px] font-mono text-slate-400 tabular-nums">
                          {Math.round(file.impactScore).toLocaleString()}
                        </span>
                      </div>
                    </td>

                    <td className="py-2.5 pl-3 pr-6 align-middle text-right">
                      <div className="inline-flex items-center gap-1 opacity-75 group-hover:opacity-100 transition-opacity">
                        <button
                          onClick={() => onQuickLook(file)}
                          className="p-1.5 rounded-lg hover:bg-white/[0.08] text-slate-400 hover:text-white cursor-pointer"
                          title="Quick Look Preview"
                        >
                          <Eye className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => onReveal(file.path)}
                          className="p-1.5 rounded-lg hover:bg-white/[0.08] text-slate-400 hover:text-[#06B6D4] cursor-pointer"
                          title="Reveal in Explorer / Finder"
                        >
                          <FolderOpen className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => onIgnoreFile(file.path)}
                          className="p-1.5 rounded-lg hover:bg-emerald-500/15 text-slate-400 hover:text-emerald-300 cursor-pointer"
                          title="Keep / Ignore in Future Scans"
                        >
                          <ShieldCheck className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => onDeleteFiles([file.path])}
                          className={`p-1.5 rounded-lg cursor-pointer ${
                            permanentShred
                              ? "hover:bg-red-500/20 text-slate-400 hover:text-red-300"
                              : "hover:bg-amber-500/15 text-slate-400 hover:text-amber-300"
                          }`}
                          title={
                            permanentShred
                              ? "Shred Permanently"
                              : "Move to Recycle Bin / Trash"
                          }
                        >
                          {permanentShred ? (
                            <Flame className="w-3.5 h-3.5" />
                          ) : (
                            <Trash2 className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}

        {/* Pagination / Footer Summary */}
        {filteredFiles.length > visibleLimit && (
          <div className="p-4 text-center border-t border-white/[0.06] bg-[#111419]">
            <button
              onClick={() => setVisibleLimit((v) => v + 200)}
              className="px-4 py-2 rounded-xl bg-[#161920] hover:bg-white/[0.08] border border-white/[0.1] text-[12px] font-medium text-slate-200 cursor-pointer"
            >
              Show More ({filteredFiles.length - visibleLimit} remaining •{" "}
              {formatBytes(filteredTotalBytes)} total)
            </button>
          </div>
        )}
      </div>

      {/* Floating Bulk Action Bar */}
      <AnimatePresence>
        {selectedRecords.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 20 }}
            className="shrink-0 mx-6 mb-4 mt-2 px-4 py-3 rounded-2xl bg-[#161920] border border-[#06B6D4]/40 shadow-[0_8px_30px_rgba(0,0,0,0.5)] flex items-center justify-between gap-4"
          >
            <div className="flex items-center gap-3">
              <span className="px-2.5 py-1 rounded-lg bg-[#06B6D4]/15 text-[#67E8F9] text-[12px] font-mono font-semibold tabular-nums">
                {selectedRecords.length} selected
              </span>
              <span className="text-[13px] font-mono font-semibold text-white tabular-nums">
                {formatBytes(selectedTotalBytes)}
              </span>
              <button
                onClick={() => setSelectedIds(new Set())}
                className="text-[12px] text-slate-400 hover:text-white cursor-pointer"
              >
                Clear
              </button>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => {
                  selectedRecords.forEach((r) => onIgnoreFile(r.path));
                  setSelectedIds(new Set());
                }}
                className="px-3.5 py-2 rounded-xl bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/30 text-[12px] font-medium text-emerald-200 flex items-center gap-1.5 cursor-pointer"
              >
                <ShieldCheck className="w-3.5 h-3.5" />
                Whitelist Selected
              </button>
              <button
                onClick={() => {
                  onDeleteFiles(selectedRecords.map((r) => r.path));
                  setSelectedIds(new Set());
                }}
                className={`px-4 py-2 rounded-xl text-[12px] font-semibold flex items-center gap-1.5 cursor-pointer border ${
                  permanentShred
                    ? "bg-red-500/25 hover:bg-red-500/35 border-red-500/50 text-red-100"
                    : "bg-gradient-to-r from-[#06B6D4] to-[#3B82F6] border-transparent text-white hover:brightness-110"
                }`}
              >
                {permanentShred ? (
                  <Flame className="w-3.5 h-3.5" />
                ) : (
                  <Trash2 className="w-3.5 h-3.5" />
                )}
                {permanentShred
                  ? `Shred ${formatBytes(selectedTotalBytes)}`
                  : `Move to Trash (${formatBytes(selectedTotalBytes)})`}
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};
