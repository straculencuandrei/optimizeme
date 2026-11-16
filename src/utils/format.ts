import { FileCategory } from "../types/forensics";

export function formatBytes(bytes: number, decimals = 1): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), sizes.length - 1);
  const value = bytes / Math.pow(k, i);
  return `${value.toFixed(i === 0 ? 0 : dm)} ${sizes[i]}`;
}

export function formatDateTime(epochSeconds: number): string {
  if (!epochSeconds || epochSeconds <= 0) return "Unknown";
  return new Date(epochSeconds * 1000).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function getCategoryMeta(category: FileCategory): {
  label: string;
  color: string;
  bgClass: string;
  textClass: string;
} {
  switch (category) {
    case "installer":
      return {
        label: "Installer",
        color: "#F59E0B",
        bgClass: "bg-amber-500/12 border-amber-500/25",
        textClass: "text-amber-300",
      };
    case "archive":
      return {
        label: "Archive",
        color: "#8B5CF6",
        bgClass: "bg-violet-500/12 border-violet-500/25",
        textClass: "text-violet-300",
      };
    case "media":
      return {
        label: "Media",
        color: "#06B6D4",
        bgClass: "bg-cyan-500/12 border-cyan-500/25",
        textClass: "text-cyan-300",
      };
    case "disk_image":
      return {
        label: "Disk Image",
        color: "#EF4444",
        bgClass: "bg-red-500/12 border-red-500/25",
        textClass: "text-red-300",
      };
    case "document":
      return {
        label: "Document",
        color: "#3B82F6",
        bgClass: "bg-blue-500/12 border-blue-500/25",
        textClass: "text-blue-300",
      };
    case "application":
      return {
        label: "Application",
        color: "#10B981",
        bgClass: "bg-emerald-500/12 border-emerald-500/25",
        textClass: "text-emerald-300",
      };
    case "code":
      return {
        label: "Code / Data",
        color: "#6366F1",
        bgClass: "bg-indigo-500/12 border-indigo-500/25",
        textClass: "text-indigo-300",
      };
    default:
      return {
        label: "Other",
        color: "#64748B",
        bgClass: "bg-slate-500/12 border-slate-500/25",
        textClass: "text-slate-300",
      };
  }
}

export function getStalenessSeverity(daysUnused: number): {
  badgeClass: string;
  dotClass: string;
} {
  if (daysUnused >= 365) {
    return {
      badgeClass: "bg-red-500/10 text-red-300 border-red-500/25",
      dotClass: "bg-red-400",
    };
  }
  if (daysUnused >= 180) {
    return {
      badgeClass: "bg-amber-500/10 text-amber-300 border-amber-500/25",
      dotClass: "bg-amber-400",
    };
  }
  if (daysUnused >= 30) {
    return {
      badgeClass: "bg-cyan-500/10 text-cyan-300 border-cyan-500/25",
      dotClass: "bg-cyan-400",
    };
  }
  return {
    badgeClass: "bg-white/5 text-slate-300 border-white/10",
    dotClass: "bg-slate-400",
  };
}
