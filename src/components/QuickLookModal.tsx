import React from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  X,
  FolderOpen,
  ExternalLink,
  ShieldCheck,
  Trash2,
  Flame,
  FileCode2,
  HardDrive,
} from "lucide-react";
import { FilePreviewInfo, FileRecord } from "../types/forensics";
import { formatBytes, formatDateTime } from "../utils/format";

interface QuickLookModalProps {
  file: FileRecord | null;
  preview: FilePreviewInfo | null;
  loading: boolean;
  permanentShred: boolean;
  onClose: () => void;
  onReveal: (path: string) => void;
  onOpenDefault: (path: string) => void;
  onWhitelist: (path: string) => void;
  onDelete: (path: string) => void;
}

export const QuickLookModal: React.FC<QuickLookModalProps> = ({
  file,
  preview,
  loading,
  permanentShred,
  onClose,
  onReveal,
  onOpenDefault,
  onWhitelist,
  onDelete,
}) => {
  return (
    <AnimatePresence>
      {file && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4"
          onClick={onClose}
        >
          <motion.div
            initial={{ opacity: 0, scale: 0.96, y: 10 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.96, y: 10 }}
            transition={{ duration: 0.16 }}
            onClick={(e) => e.stopPropagation()}
            className="w-full max-w-2xl rounded-2xl bg-[#161920] border border-white/[0.12] shadow-2xl overflow-hidden"
          >
            {/* Header */}
            <div className="px-5 py-4 border-b border-white/[0.08] flex items-center justify-between gap-3">
              <div className="flex items-center gap-3 min-w-0">
                <div className="w-9 h-9 rounded-xl bg-[#06B6D4]/10 border border-[#06B6D4]/25 flex items-center justify-center shrink-0">
                  <FileCode2 className="w-4.5 h-4.5 text-[#06B6D4]" />
                </div>
                <div className="min-w-0">
                  <h3 className="text-[14px] font-semibold text-white truncate">
                    {file.name}
                  </h3>
                  <p className="text-[11px] font-mono text-slate-400 truncate">
                    {file.path}
                  </p>
                </div>
              </div>
              <button
                onClick={onClose}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/[0.06] cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Body */}
            <div className="p-5 space-y-4">
              {/* Metadata Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="p-3 rounded-xl bg-[#0D0F12] border border-white/[0.06]">
                  <div className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">
                    File Size
                  </div>
                  <div className="text-[13px] font-mono font-semibold text-white mt-1 tabular-nums">
                    {formatBytes(file.sizeBytes)}
                  </div>
                </div>
                <div className="p-3 rounded-xl bg-[#0D0F12] border border-white/[0.06]">
                  <div className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">
                    Last Opened / Used
                  </div>
                  <div className="text-[12px] text-amber-300 font-medium mt-1">
                    {formatDateTime(file.lastUsedAt)}
                  </div>
                </div>
                <div className="p-3 rounded-xl bg-[#0D0F12] border border-white/[0.06]">
                  <div className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">
                    Created
                  </div>
                  <div className="text-[12px] text-slate-300 mt-1">
                    {formatDateTime(file.createdAt)}
                  </div>
                </div>
                <div className="p-3 rounded-xl bg-[#0D0F12] border border-white/[0.06]">
                  <div className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">
                    Signal Source
                  </div>
                  <div className="text-[12px] text-[#06B6D4] mt-1 font-medium">
                    {file.lastUsedSource}
                  </div>
                </div>
              </div>

              {/* Preview Box */}
              <div className="rounded-xl bg-[#0D0F12] border border-white/[0.07] p-4">
                <div className="flex items-center justify-between text-[11px] text-slate-400 mb-2">
                  <span className="font-semibold uppercase tracking-wider">
                    Quick Look Inspection
                  </span>
                  {preview?.sha256Prefix && (
                    <span className="font-mono text-slate-500">
                      SHA256[0..16]: {preview.sha256Prefix}
                    </span>
                  )}
                </div>

                {loading ? (
                  <div className="py-8 text-center text-[12px] text-slate-500">
                    Reading file header & forensic digest...
                  </div>
                ) : preview?.textSnippet ? (
                  <pre className="max-h-56 overflow-auto text-[11.5px] font-mono text-slate-300 leading-relaxed whitespace-pre-wrap select-text">
                    {preview.textSnippet}
                  </pre>
                ) : (
                  <div className="py-6 flex flex-col items-center justify-center text-center">
                    <HardDrive className="w-7 h-7 text-slate-600 mb-2" />
                    <div className="text-[13px] text-slate-300 font-medium">
                      {preview?.mimeHint || "Binary Asset"}
                    </div>
                    <div className="text-[11.5px] text-slate-500 mt-1">
                      {file.relativeLastUsed} • Impact Score {file.impactScore.toLocaleString()}
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Footer Actions */}
            <div className="px-5 py-3.5 bg-[#111419] border-t border-white/[0.08] flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <button
                  onClick={() => onReveal(file.path)}
                  className="px-3 py-2 rounded-lg bg-white/[0.05] hover:bg-white/[0.1] border border-white/[0.08] text-[12px] font-medium text-slate-200 flex items-center gap-1.5 cursor-pointer"
                >
                  <FolderOpen className="w-3.5 h-3.5 text-[#06B6D4]" />
                  Reveal in Explorer
                </button>
                <button
                  onClick={() => onOpenDefault(file.path)}
                  className="px-3 py-2 rounded-lg bg-white/[0.05] hover:bg-white/[0.1] border border-white/[0.08] text-[12px] font-medium text-slate-200 flex items-center gap-1.5 cursor-pointer"
                >
                  <ExternalLink className="w-3.5 h-3.5 text-slate-400" />
                  Open File
                </button>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    onWhitelist(file.path);
                    onClose();
                  }}
                  className="px-3 py-2 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/25 text-[12px] font-medium text-emerald-300 flex items-center gap-1.5 cursor-pointer"
                >
                  <ShieldCheck className="w-3.5 h-3.5" />
                  Keep / Ignore
                </button>
                <button
                  onClick={() => {
                    onDelete(file.path);
                    onClose();
                  }}
                  className={`px-3.5 py-2 rounded-lg text-[12px] font-semibold flex items-center gap-1.5 cursor-pointer border ${
                    permanentShred
                      ? "bg-red-500/20 hover:bg-red-500/30 border-red-500/40 text-red-200"
                      : "bg-amber-500/15 hover:bg-amber-500/25 border-amber-500/35 text-amber-200"
                  }`}
                >
                  {permanentShred ? (
                    <Flame className="w-3.5 h-3.5" />
                  ) : (
                    <Trash2 className="w-3.5 h-3.5" />
                  )}
                  {permanentShred ? "Shred Permanently" : "Move to Trash"}
                </button>
              </div>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};
