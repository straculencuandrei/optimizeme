import React, { useMemo } from "react";
import { motion } from "framer-motion";
import {
  Lightbulb,
  Trash2,
  Flame,
  FolderOpen,
  CheckCircle2,
  AlertTriangle,
  Loader2,
  ShieldCheck,
  Sparkles,
  Eye,
} from "lucide-react";
import { Insight, InsightReport } from "../types/forensics";
import { formatBytes } from "../utils/format";

interface InsightsViewProps {
  report: InsightReport | null;
  isScanning: boolean;
  permanentShred: boolean;
  applyingIds: Set<string>;
  onRun: () => void;
  onApply: (insight: Insight) => void;
  onApplyAll: () => void;
  onReveal: (path: string) => void;
}

function DispositionBadge({ disposition }: { disposition: Insight["disposition"] }) {
  switch (disposition) {
    case "remove":
      return (
        <span className="shrink-0 inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-semibold bg-amber-500/15 text-amber-300 border border-amber-500/30">
          <Trash2 className="w-3 h-3" /> Recommended to remove
        </span>
      );
    case "review":
      return (
        <span className="shrink-0 inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-semibold bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
          <Eye className="w-3 h-3" /> Review
        </span>
      );
    default:
      return (
        <span className="shrink-0 inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-semibold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
          <ShieldCheck className="w-3 h-3" /> Keep
        </span>
      );
  }
}

function InsightCard({
  insight,
  permanentShred,
  applying,
  onApply,
  onReveal,
}: {
  insight: Insight;
  permanentShred: boolean;
  applying: boolean;
  onApply: (insight: Insight) => void;
  onReveal: (path: string) => void;
}) {
  const isRemove = insight.disposition === "remove";
  const isKeep = insight.disposition === "keep";

  const canReveal = !isKeep && insight.path;
  const revealLabel =
    insight.kind === "app" && insight.action === "reveal"
      ? "Reveal / Uninstall"
      : "Reveal";

  return (
    <motion.div
      layout
      className="rounded-xl bg-[#161920] border border-white/[0.08] p-4"
    >
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[13.5px] font-semibold text-white truncate">
              {insight.title}
            </span>
            <DispositionBadge disposition={insight.disposition} />
            {insight.sizeBytes > 0 && (
              <span className="text-[11px] font-mono font-semibold text-slate-300 tabular-nums">
                {formatBytes(insight.sizeBytes)}
              </span>
            )}
          </div>

          {insight.subtitle && (
            <div
              className="text-[11px] font-mono text-slate-500 truncate mt-1"
              title={insight.subtitle}
            >
              {insight.subtitle}
            </div>
          )}

          {/* Reasons */}
          <ul className="mt-2.5 space-y-1">
            {insight.reasons.map((reason, idx) => (
              <li key={idx} className="flex items-start gap-2 text-[12px] text-slate-300 leading-relaxed">
                <span className="mt-[7px] w-1 h-1 rounded-full bg-[#06B6D4] shrink-0" />
                <span>{reason}</span>
              </li>
            ))}
          </ul>

          {/* Confidence */}
          {insight.disposition !== "keep" && (
            <div className="mt-3 flex items-center gap-2 max-w-[240px]">
              <div className="h-1.5 flex-1 rounded-full bg-white/[0.06] overflow-hidden">
                <div
                  className={`h-full rounded-full ${
                    isRemove
                      ? "bg-gradient-to-r from-amber-500 to-red-500"
                      : "bg-gradient-to-r from-[#06B6D4] to-[#3B82F6]"
                  }`}
                  style={{ width: `${insight.confidence}%` }}
                />
              </div>
              <span className="text-[10px] font-mono text-slate-500 tabular-nums">
                {insight.confidence}% confidence
              </span>
            </div>
          )}
        </div>

        {/* Actions */}
        <div className="shrink-0 flex items-center gap-2">
          {canReveal && (
            <button
              onClick={() => onReveal(insight.path!)}
              className="p-2 rounded-lg hover:bg-white/[0.08] text-slate-400 hover:text-[#06B6D4] cursor-pointer"
              title={revealLabel}
            >
              <FolderOpen className="w-4 h-4" />
            </button>
          )}
          {isRemove && (
            <button
              onClick={() => onApply(insight)}
              disabled={applying}
              className={`px-3.5 py-2 rounded-lg text-[12px] font-semibold flex items-center gap-1.5 cursor-pointer border transition-colors ${
                permanentShred && insight.action === "delete_file"
                  ? "bg-red-500/25 hover:bg-red-500/35 border-red-500/50 text-red-100"
                  : "bg-gradient-to-r from-[#06B6D4] to-[#3B82F6] border-transparent text-white hover:brightness-110"
              } disabled:opacity-40 disabled:cursor-not-allowed`}
            >
              {applying ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : permanentShred && insight.action === "delete_file" ? (
                <Flame className="w-3.5 h-3.5" />
              ) : (
                <Trash2 className="w-3.5 h-3.5" />
              )}
              {applying ? "Working..." : insight.actionLabel}
            </button>
          )}
          {!isRemove && !isKeep && insight.action === "reveal" && (
            <button
              onClick={() => insight.path && onReveal(insight.path)}
              className="px-3.5 py-2 rounded-lg text-[12px] font-medium bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.1] text-slate-200 cursor-pointer"
            >
              {revealLabel}
            </button>
          )}
        </div>
      </div>
    </motion.div>
  );
}

export const InsightsView: React.FC<InsightsViewProps> = ({
  report,
  isScanning,
  permanentShred,
  applyingIds,
  onRun,
  onApply,
  onApplyAll,
  onReveal,
}) => {
  const { remove, review, keep } = useMemo(() => {
    if (!report) return { remove: [] as Insight[], review: [] as Insight[], keep: [] as Insight[] };
    return {
      remove: report.insights.filter((i) => i.disposition === "remove"),
      review: report.insights.filter((i) => i.disposition === "review"),
      keep: report.insights.filter((i) => i.disposition === "keep"),
    };
  }, [report]);

  if (!report && !isScanning) {
    return (
      <div className="h-full flex items-center justify-center p-8">
        <div className="max-w-md w-full p-7 rounded-2xl bg-[#161920] border border-white/[0.08] text-center">
          <div className="w-12 h-12 rounded-2xl bg-[#06B6D4]/10 border border-[#06B6D4]/25 flex items-center justify-center mx-auto mb-4">
            <Lightbulb className="w-6 h-6 text-[#06B6D4]" />
          </div>
          <h2 className="text-[16px] font-semibold text-white">
            Smart Recommendations
          </h2>
          <p className="text-[13px] text-slate-400 mt-1.5 leading-relaxed">
            I'll look at what's on your PC — file sizes, how long since things were
            used, launch history, installers, and leftover uninstall entries — then tell
            you what to clear, what to check, and what to keep, each with its reasons.
          </p>
          <button
            onClick={onRun}
            className="mt-5 w-full py-2.5 px-4 rounded-xl bg-gradient-to-r from-[#06B6D4] to-[#3B82F6] text-white text-[13px] font-medium hover:brightness-110 transition-all flex items-center justify-center gap-2 cursor-pointer"
          >
            <Sparkles className="w-4 h-4" />
            Analyze My PC
          </button>
        </div>
      </div>
    );
  }

  if (isScanning && !report) {
    return (
      <div className="h-full flex items-center justify-center p-8">
        <div className="text-center">
          <Loader2 className="w-8 h-8 text-[#06B6D4] animate-spin mx-auto mb-3" />
          <p className="text-[14px] text-slate-300">
            Analyzing your usage data and filesystem...
          </p>
          <p className="text-[12px] text-slate-500 mt-1">
            Scanning junk, installed apps, launch history, and large files.
          </p>
        </div>
      </div>
    );
  }

  if (!report) return null;

  const removeBytes = remove.reduce((s, i) => s + i.sizeBytes, 0);
  const applyingAny = remove.some((i) => applyingIds.has(i.id));

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto">
      {/* Summary */}
      <div className="p-4 rounded-2xl bg-[#161920] border border-white/[0.08] flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-6">
          <div>
            <div className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold">
              Recommended to Reclaim
            </div>
            <div className="text-[22px] font-semibold font-mono text-white tabular-nums">
              {formatBytes(removeBytes)}
            </div>
          </div>
          <div className="h-9 w-[1px] bg-white/[0.08]" />
          <div className="text-[12px] text-slate-400 leading-relaxed">
            <span className="text-amber-300 font-semibold">{remove.length} remove</span>
            {" · "}
            <span className="text-cyan-300 font-semibold">{review.length} review</span>
            {" · "}
            <span className="text-emerald-300 font-semibold">{keep.length} keep</span>
          </div>
        </div>

        <button
          onClick={onApplyAll}
          disabled={remove.length === 0 || applyingAny}
          className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-[#06B6D4] to-[#3B82F6] disabled:opacity-40 disabled:cursor-not-allowed text-white text-[13px] font-semibold flex items-center gap-2 hover:brightness-110 transition-all cursor-pointer"
        >
          {applyingAny ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <Trash2 className="w-4 h-4" />
          )}
          {applyingAny
            ? "Applying..."
            : `Apply all recommended (${formatBytes(removeBytes)})`}
        </button>
      </div>

      {/* Recommended to remove */}
      {remove.length > 0 && (
        <section className="space-y-2.5">
          <div className="flex items-center gap-2 px-1">
            <CheckCircle2 className="w-4 h-4 text-amber-400" />
            <h3 className="text-[12px] font-semibold uppercase tracking-wider text-amber-300">
              Recommended to remove
            </h3>
          </div>
          {remove.map((insight) => (
            <InsightCard
              key={insight.id}
              insight={insight}
              permanentShred={permanentShred}
              applying={applyingIds.has(insight.id)}
              onApply={onApply}
              onReveal={onReveal}
            />
          ))}
        </section>
      )}

      {/* Review */}
      {review.length > 0 && (
        <section className="space-y-2.5">
          <div className="flex items-center gap-2 px-1">
            <AlertTriangle className="w-4 h-4 text-cyan-400" />
            <h3 className="text-[12px] font-semibold uppercase tracking-wider text-cyan-300">
              Worth a second look
            </h3>
          </div>
          {review.map((insight) => (
            <InsightCard
              key={insight.id}
              insight={insight}
              permanentShred={permanentShred}
              applying={false}
              onApply={onApply}
              onReveal={onReveal}
            />
          ))}
        </section>
      )}

      {/* Keep */}
      {keep.length > 0 && (
        <section className="space-y-2.5">
          <div className="flex items-center gap-2 px-1">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <h3 className="text-[12px] font-semibold uppercase tracking-wider text-emerald-300">
              Keep — still in active use
            </h3>
          </div>
          {keep.map((insight) => (
            <InsightCard
              key={insight.id}
              insight={insight}
              permanentShred={permanentShred}
              applying={false}
              onApply={onApply}
              onReveal={onReveal}
            />
          ))}
        </section>
      )}
    </div>
  );
};
