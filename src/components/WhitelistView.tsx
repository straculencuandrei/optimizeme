import React from "react";
import { ShieldCheck, FolderPlus, Trash2, File, Folder } from "lucide-react";
import { WhitelistConfig } from "../types/forensics";

interface WhitelistViewProps {
  whitelist: WhitelistConfig;
  onAddIgnoredFolder: () => void;
  onRemoveItem: (path: string, isFolder: boolean) => void;
}

export const WhitelistView: React.FC<WhitelistViewProps> = ({
  whitelist,
  onAddIgnoredFolder,
  onRemoveItem,
}) => {
  const totalCount =
    whitelist.ignoredFolders.length + whitelist.ignoredFiles.length;

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-6">
      <div className="p-5 rounded-2xl bg-[#161920] border border-white/[0.08] flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/25 flex items-center justify-center">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
          </div>
          <div>
            <h2 className="text-[15px] font-semibold text-white">
              Protected Files & Excluded Folders
            </h2>
            <p className="text-[12px] text-slate-400 mt-0.5">
              Items listed here are automatically skipped during Deep Forensics scans.
            </p>
          </div>
        </div>

        <button
          onClick={onAddIgnoredFolder}
          className="px-4 py-2 rounded-xl bg-white/[0.05] hover:bg-white/[0.1] border border-white/[0.1] text-[12.5px] font-medium text-white flex items-center gap-2 cursor-pointer"
        >
          <FolderPlus className="w-4 h-4 text-[#06B6D4]" />
          Exclude Folder
        </button>
      </div>

      {totalCount === 0 ? (
        <div className="p-10 rounded-2xl bg-[#161920]/60 border border-dashed border-white/[0.1] text-center">
          <p className="text-[13.5px] text-slate-300 font-medium">
            Your whitelist is currently empty.
          </p>
          <p className="text-[12px] text-slate-500 mt-1">
            Click the shield icon on any file in Deep Forensics or exclude a folder above to keep it safe.
          </p>
        </div>
      ) : (
        <div className="space-y-5">
          {whitelist.ignoredFolders.length > 0 && (
            <div className="space-y-2">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 px-1">
                Excluded Folders ({whitelist.ignoredFolders.length})
              </div>
              <div className="rounded-xl bg-[#161920] border border-white/[0.08] divide-y divide-white/[0.06]">
                {whitelist.ignoredFolders.map((folder) => (
                  <div
                    key={folder}
                    className="px-4 py-3 flex items-center justify-between gap-3"
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      <Folder className="w-4 h-4 text-[#06B6D4] shrink-0" />
                      <span className="text-[12.5px] font-mono text-slate-200 truncate">
                        {folder}
                      </span>
                    </div>
                    <button
                      onClick={() => onRemoveItem(folder, true)}
                      className="p-1.5 rounded-lg text-slate-400 hover:text-red-300 hover:bg-red-500/10 cursor-pointer"
                      title="Remove from whitelist"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {whitelist.ignoredFiles.length > 0 && (
            <div className="space-y-2">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 px-1">
                Protected Files ({whitelist.ignoredFiles.length})
              </div>
              <div className="rounded-xl bg-[#161920] border border-white/[0.08] divide-y divide-white/[0.06]">
                {whitelist.ignoredFiles.map((file) => (
                  <div
                    key={file}
                    className="px-4 py-3 flex items-center justify-between gap-3"
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      <File className="w-4 h-4 text-emerald-400 shrink-0" />
                      <span className="text-[12.5px] font-mono text-slate-200 truncate">
                        {file}
                      </span>
                    </div>
                    <button
                      onClick={() => onRemoveItem(file, false)}
                      className="p-1.5 rounded-lg text-slate-400 hover:text-red-300 hover:bg-red-500/10 cursor-pointer"
                      title="Remove from whitelist"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
