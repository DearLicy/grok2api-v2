import { apiDownloadResponse, apiRequest } from "@/shared/api/client";
import { createObjectDecoder, hasShape, isArrayOf, isBoolean, isNumber, isObject, isOneOf, isOptional, isRecordOf, isString } from "@/shared/api/decoder";

export type RegistrationRuntimeComponent = {
  browserAutomation: boolean;
  httpImpersonation: boolean;
  vaultEncryption: boolean;
};

export type RegistrationBrowser = {
  id: string;
  name: string;
  path: string;
  automatable: boolean;
};

export type RegistrationConfigDTO = {
  config: Record<string, unknown>;
  secretConfigured: Record<string, boolean>;
  browsers: RegistrationBrowser[];
  runtime: {
    ready: boolean;
    components: RegistrationRuntimeComponent;
  };
};

export type RegistrationStatusDTO = {
  available: boolean;
  startedAt?: string;
  error?: string;
};

export type RegistrationAccountDTO = {
  email: string;
  hasPassword: boolean;
  hasSso: boolean;
  source: string;
  createdAt: number;
  updatedAt: number;
};

export type RegistrationTaskStatus = "queued" | "running" | "cancelling" | "completed" | "failed" | "cancelled" | "interrupted";

export type RegistrationTaskDTO = {
  id: string;
  kind: "registration" | "relogin";
  status: RegistrationTaskStatus;
  requested: number;
  processed: number;
  succeeded: number;
  failed: number;
  skipped: number;
  current_email: string;
  error: string;
  createdAt: number;
  startedAt?: number;
  finishedAt?: number;
  progress: number;
  cancelRequested: boolean;
};

export type RegistrationLogDTO = {
  id: number;
  createdAt: number;
  message: string;
};

export type RegistrationImportResultDTO = {
  imported: number;
  updated: number;
  skipped: number;
  total: number;
};

export type CreateRegistrationTaskInput = {
  kind: "registration" | "relogin";
  count?: number;
  browser?: string;
  registrationMode?: "auto" | "protocol" | "browser";
  enableNSFW?: boolean;
  emails?: string[];
};

export type RegistrationConfigInput = {
  config: Record<string, unknown>;
  clearSecrets?: string[];
};

const browserValidator = hasShape({
  id: isString,
  name: isString,
  path: isString,
  automatable: isBoolean,
});

const decodeConfig = createObjectDecoder<RegistrationConfigDTO>("registration config", {
  config: isObject,
  secretConfigured: isRecordOf(isBoolean),
  browsers: isArrayOf(browserValidator),
  runtime: hasShape({
    ready: isBoolean,
    components: hasShape({
      browserAutomation: isBoolean,
      httpImpersonation: isBoolean,
      vaultEncryption: isBoolean,
    }),
  }),
});

const decodeStatus = createObjectDecoder<RegistrationStatusDTO>("registration status", {
  available: isBoolean,
  startedAt: isOptional(isString),
  error: isOptional(isString),
});

const accountValidator = hasShape({
  email: isString,
  hasPassword: isBoolean,
  hasSso: isBoolean,
  source: isString,
  createdAt: isNumber,
  updatedAt: isNumber,
});

const decodeAccounts = createObjectDecoder<{ items: RegistrationAccountDTO[] }>("registration accounts", {
  items: isArrayOf(accountValidator),
});

const taskValidator = hasShape({
  id: isString,
  kind: isOneOf("registration", "relogin"),
  status: isOneOf("queued", "running", "cancelling", "completed", "failed", "cancelled", "interrupted"),
  requested: isNumber,
  processed: isNumber,
  succeeded: isNumber,
  failed: isNumber,
  skipped: isNumber,
  current_email: isString,
  error: isString,
  createdAt: isNumber,
  startedAt: isOptional(isNumber),
  finishedAt: isOptional(isNumber),
  progress: isNumber,
  cancelRequested: isBoolean,
});

const decodeTask = createObjectDecoder<RegistrationTaskDTO>("registration task", {
  id: isString, kind: isOneOf("registration", "relogin"),
  status: isOneOf("queued", "running", "cancelling", "completed", "failed", "cancelled", "interrupted"),
  requested: isNumber, processed: isNumber, succeeded: isNumber, failed: isNumber, skipped: isNumber,
  current_email: isString, error: isString, createdAt: isNumber, startedAt: isOptional(isNumber),
  finishedAt: isOptional(isNumber), progress: isNumber, cancelRequested: isBoolean,
});

const decodeTasks = createObjectDecoder<{ items: RegistrationTaskDTO[] }>("registration tasks", {
  items: isArrayOf(taskValidator),
});

const decodeLatestTask = (value: unknown): RegistrationTaskDTO | null => {
  if (value === null) return null;
  return decodeTask(value);
};

const decodeLogs = createObjectDecoder<{ items: RegistrationLogDTO[] }>("registration logs", {
  items: isArrayOf(hasShape({ id: isNumber, createdAt: isNumber, message: isString })),
});

const decodeImportResult = createObjectDecoder<RegistrationImportResultDTO>("registration import", {
  imported: isNumber,
  updated: isNumber,
  skipped: isNumber,
  total: isNumber,
});

export function getRegistrationStatus(): Promise<RegistrationStatusDTO> {
  return apiRequest("/api/admin/v1/registration/status", {}, decodeStatus);
}

export function getRegistrationConfig(): Promise<RegistrationConfigDTO> {
  return apiRequest("/api/admin/v1/registration/config", {}, decodeConfig);
}

export function updateRegistrationConfig(input: RegistrationConfigInput): Promise<RegistrationConfigDTO> {
  return apiRequest("/api/admin/v1/registration/config", { method: "PUT", body: input }, decodeConfig);
}

export async function listRegistrationAccounts(search = ""): Promise<RegistrationAccountDTO[]> {
  const query = new URLSearchParams({ limit: "2000" });
  if (search.trim()) query.set("search", search.trim());
  const result = await apiRequest(`/api/admin/v1/registration/accounts?${query}`, {}, decodeAccounts);
  return result.items;
}

export function importRegistrationAccounts(content: string, source = "import"): Promise<RegistrationImportResultDTO> {
  return apiRequest("/api/admin/v1/registration/accounts/import", {
    method: "POST",
    body: { content, source },
  }, decodeImportResult);
}

export function deleteRegistrationAccounts(emails: string[]): Promise<{ deleted: number }> {
  return apiRequest("/api/admin/v1/registration/accounts/delete", {
    method: "POST",
    body: { emails },
  }, createObjectDecoder("deleted accounts", { deleted: isNumber }));
}

export function createRegistrationTask(input: CreateRegistrationTaskInput): Promise<RegistrationTaskDTO> {
  return apiRequest("/api/admin/v1/registration/tasks", {
    method: "POST",
    body: input,
  }, decodeTask);
}

export function getRegistrationTask(id: string): Promise<RegistrationTaskDTO> {
  return apiRequest(`/api/admin/v1/registration/tasks/${encodeURIComponent(id)}`, {}, decodeTask);
}

export function getLatestRegistrationTask(): Promise<RegistrationTaskDTO | null> {
  return apiRequest("/api/admin/v1/registration/tasks/latest", {}, decodeLatestTask);
}

export function listRegistrationTasks(): Promise<RegistrationTaskDTO[]> {
  return apiRequest("/api/admin/v1/registration/tasks", {}, decodeTasks).then((value) => value.items);
}

export function listRegistrationLogs(id: string, afterId = 0): Promise<RegistrationLogDTO[]> {
  const query = new URLSearchParams({ afterId: String(afterId), limit: "2000" });
  return apiRequest(`/api/admin/v1/registration/tasks/${encodeURIComponent(id)}/logs?${query}`, {}, decodeLogs).then((value) => value.items);
}

export function cancelRegistrationTask(id: string): Promise<RegistrationTaskDTO> {
  return apiRequest(`/api/admin/v1/registration/tasks/${encodeURIComponent(id)}/cancel`, { method: "POST", body: {} }, decodeTask);
}

export async function downloadRegistrationAccounts(emails: string[], format: "text" | "csv" | "json"): Promise<void> {
  const query = new URLSearchParams({ format });
  emails.forEach((email) => query.append("email", email));
  const { blob, headers } = await apiDownloadResponse(`/api/admin/v1/registration/accounts/export?${query}`, {});
  const disposition = headers.get("Content-Disposition") ?? "";
  const matched = /filename="([^"]+)"/i.exec(disposition);
  const filename = matched?.[1] || `grok2api-v2-accounts.${format === "text" ? "txt" : format}`;
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}
