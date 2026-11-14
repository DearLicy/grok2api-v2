import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  Archive,
  CheckCircle2,
  CircleAlert,
  ClipboardPaste,
  Download,
  FileUp,
  History,
  KeyRound,
  LoaderCircle,
  LogIn,
  Minus,
  Monitor,
  Play,
  Plus,
  RefreshCw,
  Search,
  Settings2,
  ShieldCheck,
  Square,
  Trash2,
  Users,
  XCircle,
  Zap,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState, type ChangeEvent, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Spinner } from "@/components/ui/spinner";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { EmptyState, ErrorState, LoadingState } from "@/shared/components/data-state";
import { useDebouncedValue } from "@/shared/hooks/use-debounced-value";
import { cn } from "@/shared/lib/cn";
import { formatCompactDateTime } from "@/shared/lib/format";
import {
  cancelRegistrationTask,
  createRegistrationTask,
  deleteRegistrationAccounts,
  downloadRegistrationAccounts,
  getLatestRegistrationTask,
  getRegistrationConfig,
  getRegistrationStatus,
  getRegistrationTask,
  importRegistrationAccounts,
  listRegistrationAccounts,
  listRegistrationLogs,
  updateRegistrationConfig,
  type RegistrationConfigDTO,
  type RegistrationTaskStatus,
} from "@/features/registration/registration-api";

type SettingsDraft = {
  emailProvider: string;
  duckmailApiKey: string;
  cloudflareApiBase: string;
  cloudflareApiKey: string;
  cloudflareAuthMode: string;
  cloudmailApiBase: string;
  cloudmailPublicToken: string;
  cloudmailDomains: string;
  yydsApiKey: string;
  yydsJwt: string;
  proxyMode: string;
  proxy: string;
  browserDebugPort: string;
  registrationMode: string;
  protocolBrowserFallback: boolean;
  protocolRequestTimeout: string;
  turnstileSolverKind: string;
  turnstileSitekey: string;
  turnstileSolverTimeout: string;
  boterdropUrl: string;
  capsolverApiKey: string;
  enableNSFW: boolean;
  riskGate: boolean;
};

const terminalTaskStatuses = new Set<RegistrationTaskStatus>(["completed", "failed", "cancelled", "interrupted"]);

function copyFor(language: string) {
  const zh = language.toLowerCase().startsWith("zh");
  return zh ? {
    title: "注册工作台",
    description: "浏览器注册、加密账号库与 Web / Build / Console 入库闭环。",
    runtimeReady: "注册引擎就绪",
    runtimeStarting: "注册引擎启动中",
    runtimeUnavailable: "注册引擎不可用",
    browserUnavailable: "未检测到可自动控制的 Chromium 浏览器",
    configure: "运行配置",
    refresh: "刷新状态",
    startTitle: "启动新批次",
    startDescription: "严格串行执行。每个账号使用独立无痕上下文，完成后立即释放。",
    quantity: "本批数量",
    browser: "浏览器",
    registrationMode: "注册方式",
    modeAuto: "自动：协议优先，安全回退",
    modeProtocol: "仅协议",
    modeBrowser: "仅浏览器",
    noBrowser: "未检测到 Chromium 浏览器",
    nsfw: "自动开启 NSFW",
    serial: "单进程串行",
    start: "开始注册",
    starting: "正在启动",
    cancel: "停止本批",
    cancelAction: "取消",
    taskProgress: "本批进度",
    noTask: "还没有注册任务",
    currentAccount: "当前账号",
    waiting: "等待任务",
    batchLogs: "本批日志",
    logsDescription: "仅显示当前任务，不混入历史批次。",
    noLogs: "任务启动后，日志会实时显示在这里。",
    accountVault: "本地账号库",
    accountVaultDescription: "邮箱、密码和 SSO 使用 AES-GCM 加密保存在本机。",
    searchAccounts: "搜索邮箱",
    import: "导入",
    pasteImport: "粘贴导入",
    export: "导出",
    exportText: "快速文本备份",
    exportCSV: "CSV 表格",
    exportJSON: "JSON 完整备份",
    relogin: "重新登录并入库",
    reloginDescription: "按列表顺序逐账号执行，不设单次上限；Web、Build、Console 均已存在时自动跳过。",
    delete: "删除选中",
    selected: "已选择 {{count}} 个账号",
    email: "邮箱",
    credentials: "本地凭据",
    source: "来源",
    updated: "更新时间",
    password: "密码",
    sso: "SSO",
    saveSettings: "保存配置",
    settingsTitle: "注册运行配置",
    settingsDescription: "邮箱服务、代理和浏览器参数会加密保存在本机。",
    mailService: "邮箱服务",
    proxyMode: "代理模式",
    direct: "直连",
    auto: "自动",
    single: "单一代理",
    pool: "代理池",
    proxyAddress: "代理地址",
    protocolTitle: "协议注册与 Turnstile",
    protocolDescription: "协议优先使用 gRPC-Web；仅安全失败会按设置回退到当前浏览器。",
    browserFallback: "允许浏览器安全回退",
    solverKind: "Turnstile 求解器",
    solverAuto: "自动",
    solverBoterdrop: "Boterdrop",
    solverCapsolver: "Capsolver",
    solverNone: "不求解",
    boterdropUrl: "Boterdrop 地址",
    capsolverKey: "Capsolver API Key",
    sitekey: "Turnstile Sitekey",
    protocolTimeout: "协议请求超时（秒）",
    solverTimeout: "求解超时（秒）",
    debugPort: "调试端口（留空自动分配）",
    secretSaved: "已保存，留空不修改",
    importTitle: "粘贴账号备份",
    importDescription: "支持 JSON、CSV 或邮箱----密码----SSO 文本；邮箱用于重新登录与完整备份。",
    importPlaceholder: "email@example.com----password----sso-token",
    startImport: "开始导入",
    imported: "导入完成：新增 {{imported}}，更新 {{updated}}，跳过 {{skipped}}",
    taskStarted: "注册任务已启动",
    reloginStarted: "重新登录任务已启动",
    cancelled: "已请求停止当前任务",
    exported: "账号备份已导出",
    deleted: "已删除 {{count}} 个本地账号",
    settingsSaved: "注册配置已保存",
    deleteTitle: "删除本地账号？",
    deleteDescription: "将从本机加密账号库删除所选账号；不会删除 Grok2API 中已入库的 Web、Build 或 Console 账号。",
    deleteConfirm: "确认删除",
    workerMissing: "注册 Worker 尚未就绪。请检查 Python、DrissionPage、curl_cffi 和浏览器。",
    selectAccount: "请先选择账号",
    invalidCount: "本批数量必须在 1 到 5000 之间",
    succeeded: "成功",
    failed: "失败",
    skipped: "跳过",
    processed: "已处理",
    status: {
      queued: "排队中",
      running: "执行中",
      cancelling: "正在停止",
      completed: "已完成",
      failed: "失败",
      cancelled: "已停止",
      interrupted: "已中断",
    },
  } : {
    title: "Registration workspace",
    description: "Browser registration, encrypted local storage, and Web / Build / Console ingestion.",
    runtimeReady: "Registration engine ready",
    runtimeStarting: "Registration engine starting",
    runtimeUnavailable: "Registration engine unavailable",
    browserUnavailable: "No automatable Chromium browser detected",
    configure: "Runtime config",
    refresh: "Refresh status",
    startTitle: "Start a batch",
    startDescription: "Strictly serial. Each account gets an isolated incognito context that is disposed immediately.",
    quantity: "Batch quantity",
    browser: "Browser",
    registrationMode: "Registration mode",
    modeAuto: "Auto: protocol first, safe fallback",
    modeProtocol: "Protocol only",
    modeBrowser: "Browser only",
    noBrowser: "No Chromium browser detected",
    nsfw: "Enable NSFW automatically",
    serial: "Single-process serial",
    start: "Start registration",
    starting: "Starting",
    cancel: "Stop batch",
    cancelAction: "Cancel",
    taskProgress: "Batch progress",
    noTask: "No registration task yet",
    currentAccount: "Current account",
    waiting: "Waiting for a task",
    batchLogs: "Batch logs",
    logsDescription: "Only the selected task is shown; historical batches never mix in.",
    noLogs: "Logs appear here as soon as the task starts.",
    accountVault: "Local account vault",
    accountVaultDescription: "Email, password, and SSO are encrypted locally with AES-GCM.",
    searchAccounts: "Search email",
    import: "Import",
    pasteImport: "Paste import",
    export: "Export",
    exportText: "Quick text backup",
    exportCSV: "CSV spreadsheet",
    exportJSON: "Full JSON backup",
    relogin: "Relogin and ingest",
    reloginDescription: "Runs one account at a time in list order without a 100-account cap; accounts complete in Web, Build, and Console are skipped.",
    delete: "Delete selected",
    selected: "{{count}} accounts selected",
    email: "Email",
    credentials: "Local credentials",
    source: "Source",
    updated: "Updated",
    password: "Password",
    sso: "SSO",
    saveSettings: "Save config",
    settingsTitle: "Registration runtime config",
    settingsDescription: "Mail, proxy, and browser settings are encrypted locally.",
    mailService: "Mail service",
    proxyMode: "Proxy mode",
    direct: "Direct",
    auto: "Auto",
    single: "Single proxy",
    pool: "Proxy pool",
    proxyAddress: "Proxy address",
    protocolTitle: "Protocol registration and Turnstile",
    protocolDescription: "gRPC-Web runs first; only safe failures fall back to the selected browser.",
    browserFallback: "Allow safe browser fallback",
    solverKind: "Turnstile solver",
    solverAuto: "Automatic",
    solverBoterdrop: "Boterdrop",
    solverCapsolver: "Capsolver",
    solverNone: "No solver",
    boterdropUrl: "Boterdrop URL",
    capsolverKey: "Capsolver API key",
    sitekey: "Turnstile sitekey",
    protocolTimeout: "Protocol timeout (seconds)",
    solverTimeout: "Solver timeout (seconds)",
    debugPort: "Debug port (blank = automatic)",
    secretSaved: "Saved; leave blank to keep",
    importTitle: "Paste account backup",
    importDescription: "Supports JSON, CSV, or email----password----SSO text. Email is required for relogin and full backups.",
    importPlaceholder: "email@example.com----password----sso-token",
    startImport: "Start import",
    imported: "Import complete: {{imported}} added, {{updated}} updated, {{skipped}} skipped",
    taskStarted: "Registration task started",
    reloginStarted: "Relogin task started",
    cancelled: "Cancellation requested",
    exported: "Account backup exported",
    deleted: "Deleted {{count}} local accounts",
    settingsSaved: "Registration config saved",
    deleteTitle: "Delete local accounts?",
    deleteDescription: "The selected accounts will be removed from the local encrypted vault. Web, Build, and Console accounts already in Grok2API are not deleted.",
    deleteConfirm: "Delete",
    workerMissing: "The registration worker is not ready. Check Python, DrissionPage, curl_cffi, and the browser installation.",
    selectAccount: "Select at least one account",
    invalidCount: "Batch quantity must be between 1 and 5000",
    succeeded: "Succeeded",
    failed: "Failed",
    skipped: "Skipped",
    processed: "Processed",
    status: {
      queued: "Queued",
      running: "Running",
      cancelling: "Stopping",
      completed: "Completed",
      failed: "Failed",
      cancelled: "Cancelled",
      interrupted: "Interrupted",
    },
  };
}

function textConfig(config: RegistrationConfigDTO | undefined, key: string, fallback = ""): string {
  const value = config?.config[key];
  return typeof value === "string" ? value : fallback;
}

function boolConfig(config: RegistrationConfigDTO | undefined, key: string, fallback: boolean): boolean {
  const value = config?.config[key];
  return typeof value === "boolean" ? value : fallback;
}

function settingsDraftFromConfig(config: RegistrationConfigDTO | undefined): SettingsDraft {
  return {
    emailProvider: textConfig(config, "email_provider", "duckmail"),
    duckmailApiKey: "",
    cloudflareApiBase: textConfig(config, "cloudflare_api_base"),
    cloudflareApiKey: "",
    cloudflareAuthMode: textConfig(config, "cloudflare_auth_mode", "none"),
    cloudmailApiBase: textConfig(config, "cloudmail_api_base"),
    cloudmailPublicToken: "",
    cloudmailDomains: textConfig(config, "cloudmail_domains"),
    yydsApiKey: "",
    yydsJwt: "",
    proxyMode: textConfig(config, "proxy_mode", "auto"),
    proxy: textConfig(config, "proxy"),
    browserDebugPort: textConfig(config, "browser_debug_port"),
    registrationMode: textConfig(config, "registration_mode", "auto"),
    protocolBrowserFallback: boolConfig(config, "protocol_browser_fallback", true),
    protocolRequestTimeout: String(config?.config.protocol_request_timeout_sec ?? 35),
    turnstileSolverKind: textConfig(config, "turnstile_solver_kind", "auto"),
    turnstileSitekey: textConfig(config, "turnstile_sitekey", "0x4AAAAAAAhr9JGVDZbrZOo0"),
    turnstileSolverTimeout: String(config?.config.turnstile_solver_timeout_sec ?? 90),
    boterdropUrl: textConfig(config, "boterdrop_url"),
    capsolverApiKey: "",
    enableNSFW: boolConfig(config, "enable_nsfw", true),
    riskGate: boolConfig(config, "sso_risk_gate_enabled", true),
  };
}

function formatTaskTime(seconds: number | undefined, locale: string): string {
  return seconds ? formatCompactDateTime(new Date(seconds * 1000).toISOString(), locale) : "-";
}

function taskTone(status: RegistrationTaskStatus): string {
  switch (status) {
    case "running":
    case "queued":
      return "text-sky-600 dark:text-sky-400";
    case "completed":
      return "text-emerald-600 dark:text-emerald-400";
    case "cancelling":
      return "text-amber-600 dark:text-amber-400";
    default:
      return "text-destructive";
  }
}

export function RegistrationPage() {
  const { i18n } = useTranslation();
  const queryClient = useQueryClient();
  const copy = copyFor(i18n.language);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const logViewportRef = useRef<HTMLDivElement>(null);
  const [count, setCount] = useState("1");
  const [browserId, setBrowserId] = useState("");
  const [registrationMode, setRegistrationMode] = useState("");
  const [enableNSFW, setEnableNSFW] = useState(true);
  const [selectedTaskId, setSelectedTaskId] = useState("");
  const [search, setSearch] = useState("");
  const [selectedEmails, setSelectedEmails] = useState<Set<string>>(() => new Set());
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [pasteOpen, setPasteOpen] = useState(false);
  const [pasteContent, setPasteContent] = useState("");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settingsDraft, setSettingsDraft] = useState<SettingsDraft>(() => settingsDraftFromConfig(undefined));
  const debouncedSearch = useDebouncedValue(search);

  const statusQuery = useQuery({
    queryKey: ["registration", "status"],
    queryFn: getRegistrationStatus,
    refetchInterval: 5000,
    retry: 1,
  });
  const configQuery = useQuery({
    queryKey: ["registration", "config"],
    queryFn: getRegistrationConfig,
    refetchInterval: statusQuery.data?.available ? false : 5000,
    retry: 2,
  });
  const latestTaskQuery = useQuery({
    queryKey: ["registration", "task", "latest"],
    queryFn: getLatestRegistrationTask,
    refetchInterval: 3000,
  });
  const currentTaskQuery = useQuery({
    queryKey: ["registration", "task", selectedTaskId],
    queryFn: () => getRegistrationTask(selectedTaskId),
    enabled: Boolean(selectedTaskId),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status && terminalTaskStatuses.has(status) ? false : 1200;
    },
  });
  const activeTask = selectedTaskId
    ? currentTaskQuery.data ?? (latestTaskQuery.data?.id === selectedTaskId ? latestTaskQuery.data : undefined)
    : latestTaskQuery.data;
  const logsQuery = useQuery({
    queryKey: ["registration", "logs", activeTask?.id ?? ""],
    queryFn: () => listRegistrationLogs(activeTask?.id ?? "", 0),
    enabled: Boolean(activeTask?.id),
    refetchInterval: activeTask && !terminalTaskStatuses.has(activeTask.status) ? 1200 : false,
  });
  const accountsQuery = useQuery({
    queryKey: ["registration", "accounts", debouncedSearch],
    queryFn: () => listRegistrationAccounts(debouncedSearch),
  });

  const browsers = configQuery.data?.browsers ?? [];
  const configuredBrowser = textConfig(configQuery.data, "browser_choice");
  const effectiveBrowser = browserId || (browsers.some((browser) => browser.id === configuredBrowser) ? configuredBrowser : browsers[0]?.id ?? "");
  const configuredMode = textConfig(configQuery.data, "registration_mode", "auto");
  const effectiveMode = registrationMode || configuredMode;
  const browserReady = browsers.some((browser) => browser.automatable && browser.path);
  const runtimeReady = Boolean(statusQuery.data?.available && configQuery.data?.runtime.ready && browserReady);
  const taskBusy = Boolean(activeTask && !terminalTaskStatuses.has(activeTask.status));
  const accounts = useMemo(() => accountsQuery.data ?? [], [accountsQuery.data]);
  const allSelected = accounts.length > 0 && accounts.every((account) => selectedEmails.has(account.email));
  const selectedCount = selectedEmails.size;

  useEffect(() => {
    const viewport = logViewportRef.current;
    if (viewport) viewport.scrollTop = viewport.scrollHeight;
  }, [logsQuery.data?.length, activeTask?.id]);

  const startMutation = useMutation({
    mutationFn: createRegistrationTask,
    onSuccess: (task) => {
      setSelectedTaskId(task.id);
      toast.success(copy.taskStarted);
      void queryClient.invalidateQueries({ queryKey: ["registration", "task"] });
      void queryClient.invalidateQueries({ queryKey: ["registration", "logs"] });
    },
    onError: (error: Error) => toast.error(error.message),
  });
  const cancelMutation = useMutation({
    mutationFn: cancelRegistrationTask,
    onSuccess: () => {
      toast.success(copy.cancelled);
      void queryClient.invalidateQueries({ queryKey: ["registration", "task"] });
    },
    onError: (error: Error) => toast.error(error.message),
  });
  const reloginMutation = useMutation({
    mutationFn: () => createRegistrationTask({ kind: "relogin", emails: Array.from(selectedEmails), browser: effectiveBrowser }),
    onSuccess: (task) => {
      setSelectedTaskId(task.id);
      toast.success(copy.reloginStarted);
      void queryClient.invalidateQueries({ queryKey: ["registration", "task"] });
    },
    onError: (error: Error) => toast.error(error.message),
  });
  const importMutation = useMutation({
    mutationFn: ({ content, source }: { content: string; source: string }) => importRegistrationAccounts(content, source),
    onSuccess: (result) => {
      toast.success(copy.imported.replace("{{imported}}", String(result.imported)).replace("{{updated}}", String(result.updated)).replace("{{skipped}}", String(result.skipped)));
      setPasteContent("");
      setPasteOpen(false);
      void queryClient.invalidateQueries({ queryKey: ["registration", "accounts"] });
    },
    onError: (error: Error) => toast.error(error.message),
  });
  const deleteMutation = useMutation({
    mutationFn: deleteRegistrationAccounts,
    onSuccess: (result) => {
      toast.success(copy.deleted.replace("{{count}}", String(result.deleted)));
      setSelectedEmails(new Set());
      setDeleteOpen(false);
      void queryClient.invalidateQueries({ queryKey: ["registration", "accounts"] });
    },
    onError: (error: Error) => toast.error(error.message),
  });
  const settingsMutation = useMutation({
    mutationFn: updateRegistrationConfig,
    onSuccess: (data) => {
      queryClient.setQueryData(["registration", "config"], data);
      toast.success(copy.settingsSaved);
      setSettingsOpen(false);
    },
    onError: (error: Error) => toast.error(error.message),
  });

  const metrics = useMemo(() => {
    const total = accounts.length;
    return {
      total,
      passwords: accounts.filter((account) => account.hasPassword).length,
      sso: accounts.filter((account) => account.hasSso).length,
    };
  }, [accounts]);

  function changeCount(delta: number) {
    const numeric = Number(count);
    const next = Math.max(1, Math.min(5000, Number.isFinite(numeric) ? numeric + delta : 1));
    setCount(String(next));
  }

  function handleStart() {
    const numeric = Number(count);
    if (!Number.isInteger(numeric) || numeric < 1 || numeric > 5000) {
      toast.error(copy.invalidCount);
      return;
    }
    if (!runtimeReady) {
      toast.error(copy.workerMissing);
      return;
    }
    startMutation.mutate({ kind: "registration", count: numeric, browser: effectiveBrowser, registrationMode: effectiveMode as "auto" | "protocol" | "browser", enableNSFW });
  }

  function toggleAccount(email: string) {
    setSelectedEmails((current) => {
      const next = new Set(current);
      if (next.has(email)) next.delete(email);
      else next.add(email);
      return next;
    });
  }

  function toggleAll() {
    setSelectedEmails((current) => {
      const next = new Set(current);
      if (allSelected) accounts.forEach((account) => next.delete(account.email));
      else accounts.forEach((account) => next.add(account.email));
      return next;
    });
  }

  async function handleExport(format: "text" | "csv" | "json") {
    try {
      await downloadRegistrationAccounts(Array.from(selectedEmails), format);
      toast.success(copy.exported);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : String(error));
    }
  }

  async function handleFiles(event: ChangeEvent<HTMLInputElement>) {
    const files = Array.from(event.target.files ?? []);
    event.target.value = "";
    for (const file of files) {
      const content = await file.text();
      await importMutation.mutateAsync({ content, source: "file-import" });
    }
  }

  function handleRelogin() {
    if (!runtimeReady) {
      toast.error(copy.workerMissing);
      return;
    }
    if (selectedEmails.size === 0) {
      toast.error(copy.selectAccount);
      return;
    }
    reloginMutation.mutate();
  }

  function openSettings() {
    setSettingsDraft(settingsDraftFromConfig(configQuery.data));
    setSettingsOpen(true);
  }

  function handleSaveSettings() {
    const config: Record<string, unknown> = {
      email_provider: settingsDraft.emailProvider,
      cloudflare_api_base: settingsDraft.cloudflareApiBase,
      cloudflare_auth_mode: settingsDraft.cloudflareAuthMode,
      cloudmail_api_base: settingsDraft.cloudmailApiBase,
      cloudmail_domains: settingsDraft.cloudmailDomains,
      proxy_mode: settingsDraft.proxyMode,
      proxy: settingsDraft.proxy,
      browser_choice: effectiveBrowser,
      browser_debug_port: settingsDraft.browserDebugPort,
      registration_mode: settingsDraft.registrationMode,
      protocol_browser_fallback: settingsDraft.protocolBrowserFallback,
      protocol_request_timeout_sec: Number(settingsDraft.protocolRequestTimeout) || 35,
      turnstile_solver_kind: settingsDraft.turnstileSolverKind,
      turnstile_sitekey: settingsDraft.turnstileSitekey,
      turnstile_solver_timeout_sec: Number(settingsDraft.turnstileSolverTimeout) || 90,
      boterdrop_url: settingsDraft.boterdropUrl,
      enable_nsfw: settingsDraft.enableNSFW,
      sso_risk_gate_enabled: settingsDraft.riskGate,
    };
    const secrets: Array<[string, string]> = [
      ["duckmail_api_key", settingsDraft.duckmailApiKey],
      ["cloudflare_api_key", settingsDraft.cloudflareApiKey],
      ["cloudmail_public_token", settingsDraft.cloudmailPublicToken],
      ["yyds_api_key", settingsDraft.yydsApiKey],
      ["yyds_jwt", settingsDraft.yydsJwt],
      ["capsolver_api_key", settingsDraft.capsolverApiKey],
    ];
    secrets.forEach(([key, value]) => {
      if (value.trim()) config[key] = value.trim();
    });
    settingsMutation.mutate({ config });
  }

  const progress = Math.max(0, Math.min(100, activeTask?.progress ?? 0));
  const logs = logsQuery.data ?? [];
  const workerLabel = !statusQuery.data?.available
    ? copy.runtimeUnavailable
    : !configQuery.data?.runtime.ready
      ? copy.runtimeStarting
      : !browserReady
        ? copy.browserUnavailable
        : copy.runtimeReady;

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <header className="flex flex-col gap-5 sm:flex-row sm:items-end sm:justify-between">
        <div className="min-w-0">
          <h1 className="text-xl font-medium leading-7">{copy.title}</h1>
          <p className="mt-1 max-w-2xl text-xs leading-5 text-muted-foreground">{copy.description}</p>
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-2">
          <div className={cn(
            "flex h-8 items-center gap-2 rounded-full border px-3 text-xs",
            runtimeReady ? "border-emerald-500/25 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300" : "border-amber-500/25 bg-amber-500/10 text-amber-700 dark:text-amber-300",
          )}>
            <span className={cn("size-1.5 rounded-full", runtimeReady ? "bg-emerald-500" : "bg-amber-500 animate-pulse")} />
            {workerLabel}
          </div>
          <Button variant="outline" size="sm" onClick={() => { void statusQuery.refetch(); void configQuery.refetch(); }}>
            <RefreshCw className={cn(statusQuery.isFetching && "animate-spin")} />
            {copy.refresh}
          </Button>
          <Button variant="secondary" size="sm" onClick={openSettings}>
            <Settings2 />
            {copy.configure}
          </Button>
        </div>
      </header>

      <section className="relative overflow-hidden rounded-lg border bg-card px-5 py-5 shadow-sm sm:px-6 sm:py-6">
        <div className="pointer-events-none absolute inset-y-0 right-0 hidden w-64 border-l border-border/50 bg-secondary/20 lg:block" />
        <div className="relative grid gap-6 lg:grid-cols-[minmax(0,1fr)_260px] lg:items-end">
          <div className="min-w-0">
            <div className="mb-5 flex items-center gap-3">
              <span className="flex size-9 items-center justify-center rounded-md bg-primary text-primary-foreground">
                <Zap className="size-4" fill="currentColor" fillOpacity={0.2} />
              </span>
              <div>
                <h2 className="text-base font-medium">{copy.startTitle}</h2>
                <p className="mt-1 text-xs leading-5 text-muted-foreground">{copy.startDescription}</p>
              </div>
            </div>

            <div className="grid gap-4 sm:grid-cols-2 2xl:grid-cols-[150px_minmax(170px,1fr)_minmax(170px,1fr)_190px]">
              <div className="space-y-2">
                <Label htmlFor="registration-count">{copy.quantity}</Label>
                <div className="flex h-11 items-center rounded-md border bg-background focus-within:ring-1 focus-within:ring-ring">
                  <Button type="button" variant="ghost" size="icon" className="size-10 shrink-0 rounded-none" onClick={() => changeCount(-1)} aria-label="decrease">
                    <Minus />
                  </Button>
                  <Input
                    id="registration-count"
                    type="number"
                    inputMode="numeric"
                    min={1}
                    max={5000}
                    value={count}
                    onChange={(event) => setCount(event.target.value)}
                    onBlur={() => {
                      const numeric = Number(count);
                      if (!Number.isInteger(numeric)) setCount("1");
                    }}
                    className="h-10 min-w-0 border-0 bg-transparent px-0 text-center text-lg font-medium tabular-nums shadow-none focus-visible:ring-0"
                  />
                  <Button type="button" variant="ghost" size="icon" className="size-10 shrink-0 rounded-none" onClick={() => changeCount(1)} aria-label="increase">
                    <Plus />
                  </Button>
                </div>
              </div>

              <div className="space-y-2">
                <Label>{copy.browser}</Label>
                <Select value={effectiveBrowser} onValueChange={setBrowserId} disabled={browsers.length === 0}>
                  <SelectTrigger className="h-11 border bg-background px-3 text-sm">
                    <div className="flex min-w-0 items-center gap-2">
                      <Monitor className="size-4 shrink-0 text-muted-foreground" />
                      <SelectValue placeholder={copy.noBrowser} />
                    </div>
                  </SelectTrigger>
                  <SelectContent>
                    {browsers.map((browser) => (
                      <SelectItem key={browser.id} value={browser.id}>{browser.name}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label>{copy.registrationMode}</Label>
                <Select value={effectiveMode} onValueChange={setRegistrationMode}>
                  <SelectTrigger className="h-11 border bg-background px-3 text-sm">
                    <div className="flex min-w-0 items-center gap-2">
                      <Zap className="size-4 shrink-0 text-muted-foreground" />
                      <SelectValue />
                    </div>
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="auto">{copy.modeAuto}</SelectItem>
                    <SelectItem value="protocol">{copy.modeProtocol}</SelectItem>
                    <SelectItem value="browser">{copy.modeBrowser}</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label>{copy.nsfw}</Label>
                <div className="flex h-11 items-center justify-between rounded-md border bg-background px-3">
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <ShieldCheck className="size-4" />
                    {copy.serial}
                  </div>
                  <Switch checked={enableNSFW} onCheckedChange={setEnableNSFW} />
                </div>
              </div>
            </div>
          </div>

          <Button
            type="button"
            className="h-12 w-full rounded-lg text-sm shadow-sm transition-[transform,box-shadow] hover:-translate-y-0.5 hover:shadow-md active:translate-y-0"
            disabled={!runtimeReady || taskBusy || startMutation.isPending}
            onClick={handleStart}
          >
            {startMutation.isPending ? <LoaderCircle className="animate-spin" /> : <Play className="fill-current" />}
            {startMutation.isPending ? copy.starting : copy.start}
          </Button>
        </div>

        <div className="relative mt-6 border-t pt-4">
          <div className="flex flex-wrap items-center justify-between gap-3 text-xs">
            <div className="flex items-center gap-2">
              <Activity className="size-4 text-muted-foreground" />
              <span className="font-medium">{copy.taskProgress}</span>
              {activeTask ? <Badge variant="secondary" className={taskTone(activeTask.status)}>{copy.status[activeTask.status]}</Badge> : null}
            </div>
            <span className="tabular-nums text-muted-foreground">{activeTask ? `${activeTask.processed} / ${activeTask.requested}` : copy.noTask}</span>
          </div>
          <div className="mt-3 h-2 overflow-hidden rounded-full bg-secondary">
            <div
              className={cn(
                "h-full rounded-full bg-primary transition-[width] duration-700 ease-out",
                activeTask && !terminalTaskStatuses.has(activeTask.status) && "animate-pulse",
              )}
              style={{ width: `${progress}%` }}
            />
          </div>
          <div className="mt-3 grid grid-cols-2 gap-2 text-xs sm:grid-cols-4">
            <Metric label={copy.processed} value={activeTask?.processed ?? 0} />
            <Metric label={copy.succeeded} value={activeTask?.succeeded ?? 0} tone="text-emerald-600 dark:text-emerald-400" />
            <Metric label={copy.failed} value={activeTask?.failed ?? 0} tone="text-destructive" />
            <Metric label={copy.skipped} value={activeTask?.skipped ?? 0} />
          </div>
        </div>
      </section>

      {configQuery.data && (!configQuery.data.runtime.ready || !browserReady) ? (
        <section className="flex flex-col gap-3 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-xs sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-start gap-2">
            <CircleAlert className="mt-0.5 size-4 shrink-0 text-amber-600 dark:text-amber-400" />
            <span>{copy.workerMissing}</span>
          </div>
          <RuntimeDependencies config={configQuery.data} browserReady={browserReady} />
        </section>
      ) : null}

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1.45fr)_minmax(300px,.55fr)]">
        <section className="min-w-0 overflow-hidden rounded-lg border bg-card">
          <div className="flex min-h-14 flex-wrap items-center justify-between gap-3 border-b px-4 py-3">
            <div>
              <div className="flex items-center gap-2">
                <History className="size-4 text-muted-foreground" />
                <h2 className="text-sm font-medium">{copy.batchLogs}</h2>
              </div>
              <p className="mt-1 text-xs text-muted-foreground">{copy.logsDescription}</p>
            </div>
            <div className="flex items-center gap-2">
              {activeTask?.current_email ? (
                <span className="max-w-52 truncate rounded-full bg-secondary/60 px-2.5 py-1 text-[11px] text-muted-foreground">{activeTask.current_email}</span>
              ) : null}
              <Button
                variant="outline"
                size="sm"
                disabled={!activeTask || terminalTaskStatuses.has(activeTask.status) || cancelMutation.isPending}
                onClick={() => activeTask && cancelMutation.mutate(activeTask.id)}
              >
                {cancelMutation.isPending ? <LoaderCircle className="animate-spin" /> : <Square className="fill-current" />}
                {copy.cancel}
              </Button>
            </div>
          </div>
          <div ref={logViewportRef} className="h-[360px] overflow-y-auto bg-[color-mix(in_oklab,var(--background)_84%,var(--card))] p-4 font-mono text-[11px] leading-5">
            {logsQuery.isLoading ? (
              <div className="flex h-full items-center justify-center"><Spinner className="size-4" /></div>
            ) : logs.length === 0 ? (
              <div className="flex h-full flex-col items-center justify-center gap-3 text-center text-muted-foreground">
                <Archive className="size-8 opacity-35" />
                <span className="max-w-sm font-sans text-xs">{copy.noLogs}</span>
              </div>
            ) : (
              <div className="space-y-1">
                {logs.map((log) => (
                  <div key={log.id} className="grid grid-cols-[66px_minmax(0,1fr)] gap-3">
                    <span className="select-none text-muted-foreground/55">{new Date(log.createdAt * 1000).toLocaleTimeString(i18n.language, { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</span>
                    <span className={cn(
                      "min-w-0 whitespace-pre-wrap break-words",
                      log.message.startsWith("[+]") && "text-emerald-700 dark:text-emerald-300",
                      log.message.startsWith("[!]") && "text-amber-700 dark:text-amber-300",
                      log.message.startsWith("[-]") && "text-destructive",
                    )}>{log.message}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </section>

        <aside className="min-w-0 rounded-lg border bg-card p-4">
          <div className="flex items-start justify-between gap-3">
            <div>
              <div className="flex items-center gap-2">
                <KeyRound className="size-4 text-muted-foreground" />
                <h2 className="text-sm font-medium">{copy.accountVault}</h2>
              </div>
              <p className="mt-1 text-xs leading-5 text-muted-foreground">{copy.accountVaultDescription}</p>
            </div>
            <Badge variant="secondary">{metrics.total}</Badge>
          </div>
          <div className="mt-5 grid grid-cols-2 gap-3">
            <VaultMetric icon={<KeyRound />} label={copy.password} value={metrics.passwords} total={metrics.total} />
            <VaultMetric icon={<ShieldCheck />} label={copy.sso} value={metrics.sso} total={metrics.total} />
          </div>
          <div className="mt-5 space-y-2 border-t pt-4 text-xs">
            <div className="flex items-center justify-between gap-3">
              <span className="text-muted-foreground">{copy.currentAccount}</span>
              <span className="min-w-0 truncate font-medium">{activeTask?.current_email || copy.waiting}</span>
            </div>
            <div className="flex items-center justify-between gap-3">
              <span className="text-muted-foreground">{copy.updated}</span>
              <span className="tabular-nums">{formatTaskTime(activeTask?.finishedAt ?? activeTask?.createdAt, i18n.language)}</span>
            </div>
            {activeTask?.error ? <p className="rounded-md bg-destructive/10 px-2.5 py-2 leading-5 text-destructive">{activeTask.error}</p> : null}
          </div>
        </aside>
      </div>

      <section className="overflow-hidden rounded-lg border bg-card">
        <div className="flex flex-col gap-4 border-b px-4 py-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <div className="flex items-center gap-2">
              <Users className="size-4 text-muted-foreground" />
              <h2 className="text-sm font-medium">{copy.accountVault}</h2>
              <Badge variant="secondary">{metrics.total}</Badge>
              {selectedCount > 0 ? <Badge>{copy.selected.replace("{{count}}", String(selectedCount))}</Badge> : null}
            </div>
            <p className="mt-1 text-xs text-muted-foreground">{copy.reloginDescription}</p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative min-w-[180px] flex-1 sm:flex-none">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
              <Input value={search} onChange={(event) => setSearch(event.target.value)} placeholder={copy.searchAccounts} className="h-8 pl-8 text-xs" />
            </div>
            <input ref={fileInputRef} type="file" multiple accept=".txt,.csv,.json,text/plain,application/json,text/csv" className="hidden" onChange={(event) => void handleFiles(event)} />
            <Button variant="outline" size="sm" disabled={importMutation.isPending} onClick={() => fileInputRef.current?.click()}>
              <FileUp />
              {copy.import}
            </Button>
            <Button variant="outline" size="sm" onClick={() => setPasteOpen(true)}>
              <ClipboardPaste />
              {copy.pasteImport}
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm">
                  <Download />
                  {copy.export}
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => void handleExport("text")}>{copy.exportText}</DropdownMenuItem>
                <DropdownMenuItem onClick={() => void handleExport("csv")}>{copy.exportCSV}</DropdownMenuItem>
                <DropdownMenuItem onClick={() => void handleExport("json")}>{copy.exportJSON}</DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
            <Button size="sm" disabled={!runtimeReady || taskBusy || selectedCount === 0 || reloginMutation.isPending} onClick={handleRelogin}>
              {reloginMutation.isPending ? <LoaderCircle className="animate-spin" /> : <LogIn />}
              {copy.relogin}
            </Button>
            <Button variant="ghost" size="icon" className="text-muted-foreground hover:text-destructive" disabled={selectedCount === 0} onClick={() => setDeleteOpen(true)} aria-label={copy.delete}>
              <Trash2 />
            </Button>
          </div>
        </div>

        {accountsQuery.isError ? (
          <div className="p-8">
            <ErrorState message={accountsQuery.error.message} onRetry={() => void accountsQuery.refetch()} />
          </div>
        ) : accountsQuery.isLoading ? (
          <div className="p-8"><LoadingState /></div>
        ) : accounts.length === 0 ? (
          <div className="p-8"><EmptyState message={copy.accountVaultDescription} /></div>
        ) : (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-10"><Checkbox checked={allSelected} onCheckedChange={toggleAll} aria-label={copy.email} /></TableHead>
                  <TableHead>{copy.email}</TableHead>
                  <TableHead>{copy.credentials}</TableHead>
                  <TableHead className="hidden md:table-cell">{copy.source}</TableHead>
                  <TableHead className="hidden text-right sm:table-cell">{copy.updated}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {accounts.map((account) => (
                  <TableRow key={account.email} data-state={selectedEmails.has(account.email) ? "selected" : undefined} className="data-[state=selected]:bg-secondary/35">
                    <TableCell><Checkbox checked={selectedEmails.has(account.email)} onCheckedChange={() => toggleAccount(account.email)} aria-label={account.email} /></TableCell>
                    <TableCell className="max-w-[360px]"><div className="truncate font-medium">{account.email}</div></TableCell>
                    <TableCell>
                      <div className="flex flex-wrap items-center gap-1.5">
                        <CredentialBadge present={account.hasPassword} label={copy.password} />
                        <CredentialBadge present={account.hasSso} label={copy.sso} />
                      </div>
                    </TableCell>
                    <TableCell className="hidden md:table-cell"><Badge variant="secondary">{account.source}</Badge></TableCell>
                    <TableCell className="hidden text-right text-xs text-muted-foreground sm:table-cell">{formatTaskTime(account.updatedAt, i18n.language)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </section>

      <Dialog open={pasteOpen} onOpenChange={setPasteOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>{copy.importTitle}</DialogTitle>
            <DialogDescription>{copy.importDescription}</DialogDescription>
          </DialogHeader>
          <Textarea value={pasteContent} onChange={(event) => setPasteContent(event.target.value)} placeholder={copy.importPlaceholder} className="min-h-64 font-mono text-xs" />
          <DialogFooter>
            <Button variant="secondary" size="sm" onClick={() => setPasteOpen(false)}>{copy.cancelAction}</Button>
            <Button size="sm" disabled={!pasteContent.trim() || importMutation.isPending} onClick={() => importMutation.mutate({ content: pasteContent, source: "paste-import" })}>
              {importMutation.isPending ? <LoaderCircle className="animate-spin" /> : <ClipboardPaste />}
              {copy.startImport}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={settingsOpen} onOpenChange={setSettingsOpen}>
        <DialogContent className="max-h-[90vh] max-w-3xl overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{copy.settingsTitle}</DialogTitle>
            <DialogDescription>{copy.settingsDescription}</DialogDescription>
          </DialogHeader>
          <div className="grid gap-5 sm:grid-cols-2">
            <FieldBlock label={copy.mailService}>
              <Select value={settingsDraft.emailProvider} onValueChange={(emailProvider) => setSettingsDraft((draft) => ({ ...draft, emailProvider }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="duckmail">DuckMail</SelectItem>
                  <SelectItem value="cloudflare">Cloudflare</SelectItem>
                  <SelectItem value="cloudmail">Cloud Mail</SelectItem>
                  <SelectItem value="yyds">YYDS</SelectItem>
                </SelectContent>
              </Select>
            </FieldBlock>
            <FieldBlock label={copy.proxyMode}>
              <Select value={settingsDraft.proxyMode} onValueChange={(proxyMode) => setSettingsDraft((draft) => ({ ...draft, proxyMode }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="auto">{copy.auto}</SelectItem>
                  <SelectItem value="direct">{copy.direct}</SelectItem>
                  <SelectItem value="single">{copy.single}</SelectItem>
                  <SelectItem value="pool">{copy.pool}</SelectItem>
                </SelectContent>
              </Select>
            </FieldBlock>

            {settingsDraft.emailProvider === "duckmail" ? (
              <SecretField
                label="DuckMail API Key"
                configured={configQuery.data?.secretConfigured.duckmail_api_key}
                value={settingsDraft.duckmailApiKey}
                onChange={(duckmailApiKey) => setSettingsDraft((draft) => ({ ...draft, duckmailApiKey }))}
                savedLabel={copy.secretSaved}
              />
            ) : null}
            {settingsDraft.emailProvider === "cloudflare" ? (
              <>
                <FieldBlock label="Cloudflare API Base">
                  <Input value={settingsDraft.cloudflareApiBase} onChange={(event) => setSettingsDraft((draft) => ({ ...draft, cloudflareApiBase: event.target.value }))} />
                </FieldBlock>
                <SecretField label="Cloudflare API Key" configured={configQuery.data?.secretConfigured.cloudflare_api_key} value={settingsDraft.cloudflareApiKey} onChange={(cloudflareApiKey) => setSettingsDraft((draft) => ({ ...draft, cloudflareApiKey }))} savedLabel={copy.secretSaved} />
              </>
            ) : null}
            {settingsDraft.emailProvider === "cloudmail" ? (
              <>
                <FieldBlock label="Cloud Mail API Base">
                  <Input value={settingsDraft.cloudmailApiBase} onChange={(event) => setSettingsDraft((draft) => ({ ...draft, cloudmailApiBase: event.target.value }))} />
                </FieldBlock>
                <SecretField label="Cloud Mail Public Token" configured={configQuery.data?.secretConfigured.cloudmail_public_token} value={settingsDraft.cloudmailPublicToken} onChange={(cloudmailPublicToken) => setSettingsDraft((draft) => ({ ...draft, cloudmailPublicToken }))} savedLabel={copy.secretSaved} />
                <FieldBlock label="Cloud Mail Domains">
                  <Input value={settingsDraft.cloudmailDomains} onChange={(event) => setSettingsDraft((draft) => ({ ...draft, cloudmailDomains: event.target.value }))} />
                </FieldBlock>
              </>
            ) : null}
            {settingsDraft.emailProvider === "yyds" ? (
              <>
                <SecretField label="YYDS API Key" configured={configQuery.data?.secretConfigured.yyds_api_key} value={settingsDraft.yydsApiKey} onChange={(yydsApiKey) => setSettingsDraft((draft) => ({ ...draft, yydsApiKey }))} savedLabel={copy.secretSaved} />
                <SecretField label="YYDS JWT" configured={configQuery.data?.secretConfigured.yyds_jwt} value={settingsDraft.yydsJwt} onChange={(yydsJwt) => setSettingsDraft((draft) => ({ ...draft, yydsJwt }))} savedLabel={copy.secretSaved} />
              </>
            ) : null}

            {settingsDraft.proxyMode === "single" || settingsDraft.proxyMode === "auto" ? (
              <FieldBlock label={copy.proxyAddress}>
                <Input value={settingsDraft.proxy} onChange={(event) => setSettingsDraft((draft) => ({ ...draft, proxy: event.target.value }))} placeholder="http://127.0.0.1:7890" />
              </FieldBlock>
            ) : null}
            <FieldBlock label={copy.debugPort}>
              <Input value={settingsDraft.browserDebugPort} onChange={(event) => setSettingsDraft((draft) => ({ ...draft, browserDebugPort: event.target.value }))} placeholder="auto" inputMode="numeric" />
            </FieldBlock>

            <div className="sm:col-span-2 border-t pt-5">
              <div className="flex items-start gap-3">
                <span className="mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-md bg-secondary text-muted-foreground">
                  <ShieldCheck className="size-4" />
                </span>
                <div>
                  <h3 className="text-sm font-medium">{copy.protocolTitle}</h3>
                  <p className="mt-1 text-xs leading-5 text-muted-foreground">{copy.protocolDescription}</p>
                </div>
              </div>
            </div>

            <FieldBlock label={copy.registrationMode}>
              <Select value={settingsDraft.registrationMode} onValueChange={(registrationMode) => setSettingsDraft((draft) => ({ ...draft, registrationMode }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="auto">{copy.modeAuto}</SelectItem>
                  <SelectItem value="protocol">{copy.modeProtocol}</SelectItem>
                  <SelectItem value="browser">{copy.modeBrowser}</SelectItem>
                </SelectContent>
              </Select>
            </FieldBlock>
            <FieldBlock label={copy.solverKind}>
              <Select value={settingsDraft.turnstileSolverKind} onValueChange={(turnstileSolverKind) => setSettingsDraft((draft) => ({ ...draft, turnstileSolverKind }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="auto">{copy.solverAuto}</SelectItem>
                  <SelectItem value="boterdrop">{copy.solverBoterdrop}</SelectItem>
                  <SelectItem value="capsolver">{copy.solverCapsolver}</SelectItem>
                  <SelectItem value="none">{copy.solverNone}</SelectItem>
                </SelectContent>
              </Select>
            </FieldBlock>
            <FieldBlock label={copy.boterdropUrl}>
              <Input value={settingsDraft.boterdropUrl} onChange={(event) => setSettingsDraft((draft) => ({ ...draft, boterdropUrl: event.target.value }))} placeholder="http://127.0.0.1:8005" />
            </FieldBlock>
            <SecretField
              label={copy.capsolverKey}
              configured={configQuery.data?.secretConfigured.capsolver_api_key}
              value={settingsDraft.capsolverApiKey}
              onChange={(capsolverApiKey) => setSettingsDraft((draft) => ({ ...draft, capsolverApiKey }))}
              savedLabel={copy.secretSaved}
            />
            <FieldBlock label={copy.sitekey}>
              <Input value={settingsDraft.turnstileSitekey} onChange={(event) => setSettingsDraft((draft) => ({ ...draft, turnstileSitekey: event.target.value }))} />
            </FieldBlock>
            <FieldBlock label={copy.protocolTimeout}>
              <Input type="number" inputMode="numeric" min={10} max={180} value={settingsDraft.protocolRequestTimeout} onChange={(event) => setSettingsDraft((draft) => ({ ...draft, protocolRequestTimeout: event.target.value }))} />
            </FieldBlock>
            <FieldBlock label={copy.solverTimeout}>
              <Input type="number" inputMode="numeric" min={10} max={300} value={settingsDraft.turnstileSolverTimeout} onChange={(event) => setSettingsDraft((draft) => ({ ...draft, turnstileSolverTimeout: event.target.value }))} />
            </FieldBlock>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <ToggleSetting label={copy.browserFallback} checked={settingsDraft.protocolBrowserFallback} onCheckedChange={(protocolBrowserFallback) => setSettingsDraft((draft) => ({ ...draft, protocolBrowserFallback }))} />
            <ToggleSetting label={copy.nsfw} checked={settingsDraft.enableNSFW} onCheckedChange={(enableNSFW) => setSettingsDraft((draft) => ({ ...draft, enableNSFW }))} />
            <ToggleSetting label="SSO 风控筛查" checked={settingsDraft.riskGate} onCheckedChange={(riskGate) => setSettingsDraft((draft) => ({ ...draft, riskGate }))} />
          </div>
          <DialogFooter>
            <Button variant="secondary" size="sm" onClick={() => setSettingsOpen(false)}>{copy.cancelAction}</Button>
            <Button size="sm" disabled={settingsMutation.isPending} onClick={handleSaveSettings}>
              {settingsMutation.isPending ? <LoaderCircle className="animate-spin" /> : <CheckCircle2 />}
              {copy.saveSettings}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AlertDialog open={deleteOpen} onOpenChange={setDeleteOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{copy.deleteTitle}</AlertDialogTitle>
            <AlertDialogDescription>{copy.deleteDescription}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{copy.cancelAction}</AlertDialogCancel>
            <AlertDialogAction className="bg-destructive hover:bg-destructive/90" disabled={deleteMutation.isPending} onClick={(event) => { event.preventDefault(); deleteMutation.mutate(Array.from(selectedEmails)); }}>
              {deleteMutation.isPending ? <LoaderCircle className="animate-spin" /> : <Trash2 />}
              {copy.deleteConfirm}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

function Metric({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return (
    <div className="flex items-center justify-between rounded-md bg-secondary/45 px-3 py-2">
      <span className="text-muted-foreground">{label}</span>
      <span className={cn("font-medium tabular-nums", tone)}>{value}</span>
    </div>
  );
}

function VaultMetric({ icon, label, value, total }: { icon: ReactNode; label: string; value: number; total: number }) {
  const ratio = total > 0 ? Math.round((value / total) * 100) : 0;
  return (
    <div className="rounded-md border bg-background/60 p-3">
      <div className="flex items-center gap-2 text-xs text-muted-foreground [&_svg]:size-3.5">{icon}{label}</div>
      <div className="mt-3 text-xl font-medium tabular-nums">{value}</div>
      <div className="mt-2 h-1 overflow-hidden rounded-full bg-secondary">
        <div className="h-full rounded-full bg-primary transition-[width] duration-500" style={{ width: `${ratio}%` }} />
      </div>
    </div>
  );
}

function CredentialBadge({ present, label }: { present: boolean; label: string }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Badge variant={present ? "secondary" : "outline"} className={cn("gap-1", present ? "text-foreground" : "text-muted-foreground opacity-60")}>
          {present ? <CheckCircle2 className="size-3 text-emerald-600 dark:text-emerald-400" /> : <XCircle className="size-3" />}
          {label}
        </Badge>
      </TooltipTrigger>
      <TooltipContent>{present ? `${label}: available` : `${label}: missing`}</TooltipContent>
    </Tooltip>
  );
}

function RuntimeDependencies({ config, browserReady }: { config: RegistrationConfigDTO; browserReady: boolean }) {
  const entries = [
    ["Chromium", browserReady],
    ["DrissionPage", config.runtime.components.browserAutomation],
    ["curl_cffi", config.runtime.components.httpImpersonation],
    ["cryptography", config.runtime.components.vaultEncryption],
  ] as const;
  return (
    <div className="flex flex-wrap gap-1.5">
      {entries.map(([label, ready]) => (
        <Badge key={label} variant="outline" className={cn("gap-1", ready ? "border-emerald-500/30 text-emerald-700 dark:text-emerald-300" : "border-destructive/30 text-destructive")}>
          {ready ? <CheckCircle2 className="size-3" /> : <XCircle className="size-3" />}
          {label}
        </Badge>
      ))}
    </div>
  );
}

function FieldBlock({ label, children }: { label: string; children: ReactNode }) {
  return <div className="space-y-2"><Label>{label}</Label>{children}</div>;
}

function SecretField({ label, configured, value, onChange, savedLabel }: { label: string; configured?: boolean; value: string; onChange: (value: string) => void; savedLabel: string }) {
  return (
    <FieldBlock label={label}>
      <Input type="password" autoComplete="off" value={value} onChange={(event) => onChange(event.target.value)} placeholder={configured ? savedLabel : ""} />
    </FieldBlock>
  );
}

function ToggleSetting({ label, checked, onCheckedChange }: { label: string; checked: boolean; onCheckedChange: (checked: boolean) => void }) {
  return (
    <div className="flex min-h-10 items-center justify-between gap-4 rounded-md border bg-background px-3 py-2">
      <span className="text-xs">{label}</span>
      <Switch checked={checked} onCheckedChange={onCheckedChange} />
    </div>
  );
}
