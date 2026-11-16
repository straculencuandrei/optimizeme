export type FileCategory =
  | "installer"
  | "archive"
  | "media"
  | "disk_image"
  | "document"
  | "application"
  | "code"
  | "other";

export interface FileRecord {
  id: string;
  name: string;
  path: string;
  parentDir: string;
  extension: string;
  category: FileCategory;
  sizeBytes: number;
  createdAt: number;
  modifiedAt: number;
  accessedAt: number;
  lastUsedAt: number;
  lastUsedSource: string;
  daysUnused: number;
  relativeLastUsed: string;
  impactScore: number;
  tags: string[];
  isIgnored: boolean;
}

export interface StorageBreakdownItem {
  category: string;
  sizeBytes: number;
  fileCount: number;
  color: string;
}

export interface ForensicsScanResult {
  scanId: string;
  totalFilesScanned: number;
  totalBytesScanned: number;
  staleFilesCount: number;
  reclaimableBytes: number;
  durationMs: number;
  breakdown: StorageBreakdownItem[];
  files: FileRecord[];
}

export interface ForensicsBatchEvent {
  scanId: string;
  files: FileRecord[];
}

export interface ScanProgressEvent {
  scanId: string;
  phase: string;
  scannedFiles: number;
  scannedBytes: number;
  currentPath: string;
  completed: boolean;
}

export interface QuickCleanCategory {
  id: string;
  name: string;
  description: string;
  group: string;
  sizeBytes: number;
  fileCount: number;
  samplePaths: string[];
  targetPaths: string[];
  supportsCookieToggle: boolean;
  cookiePaths: string[];
  cookieSizeBytes: number;
  enabledByDefault: boolean;
  isRecycleBin: boolean;
}

export interface QuickCleanScanResult {
  totalReclaimableBytes: number;
  totalFiles: number;
  categories: QuickCleanCategory[];
  durationMs: number;
}

export interface CleanRequestItem {
  categoryId: string;
  targetPaths: string[];
  includeCookies: boolean;
  cookiePaths: string[];
  isRecycleBin: boolean;
}

export interface CleanExecutionResult {
  freedBytes: number;
  deletedCount: number;
  skippedCount: number;
  errors: string[];
}

export type AppInstallStatus = "installed" | "orphaned" | "broken" | "unknown";

export interface AppUsageRecord {
  id: string;
  name: string;
  publisher: string;
  installLocation: string;
  executablePath: string | null;
  estimatedSizeBytes: number;
  lastLaunchedAt: number | null;
  lastLaunchedSource: string;
  daysUnused: number;
  relativeLastUsed: string;
  isBloatedUnused: boolean;
  exists: boolean;
  status: AppInstallStatus;
  registryPath: string | null;
  uninstallString: string | null;
  launchCount: number | null;
}

export interface AppCleanupResult {
  removedKeys: string[];
  failed: { path: string; reason: string }[];
}

export interface DeleteResult {
  deletedPaths: string[];
  freedBytes: number;
  failed: { path: string; reason: string }[];
  shredded: boolean;
}

export interface FilePreviewInfo {
  path: string;
  name: string;
  extension: string;
  sizeBytes: number;
  mimeHint: string;
  textSnippet: string | null;
  isBinary: boolean;
  createdAt: number;
  modifiedAt: number;
  accessedAt: number;
  sha256Prefix: string | null;
}

export interface WhitelistConfig {
  ignoredFiles: string[];
  ignoredFolders: string[];
}

export interface DefaultScanTarget {
  id: string;
  label: string;
  path: string;
  exists: boolean;
}

export type NavTab = "quick_clean" | "forensics" | "apps" | "whitelist";
export type StalePresetDays = 0 | 30 | 180 | 365 | 730;
export type SortField = "impact" | "size" | "unused" | "name";
export type SortDirection = "desc" | "asc";
