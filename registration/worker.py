#!/usr/bin/env python3
"""Internal registration worker managed by the Grok2API Go server."""
from __future__ import annotations

import argparse
import csv
import importlib.util
import io
import json
import os
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import app_config
from registration_runtime import (
    AccountRetryNeeded,
    RegistrationCancelled,
    log_exception,
    raise_if_cancelled,
    sleep_with_cancel,
)
from vault import Vault, VaultError
from worker_store import WorkerStore, redact_log_message


MAX_REQUEST_BYTES = 32 << 20
SECRET_CONFIG_FIELDS = {
    "duckmail_api_key",
    "cloudflare_api_key",
    "cloudmail_public_token",
    "yyds_api_key",
    "yyds_jwt",
    "capsolver_api_key",
}
CONFIG_FIELDS = (
    "email_provider",
    "enable_nsfw",
    "sso_risk_gate_enabled",
    "browser_choice",
    "browser_debug_port",
    "proxy_mode",
    "proxy",
    "proxy_fallback",
    "proxy_pool_file",
    "proxy_pool_subscription_url",
    "proxy_pool_max_concurrent_per_node",
    "duckmail_api_key",
    "cloudflare_api_base",
    "cloudflare_api_key",
    "cloudflare_auth_mode",
    "cloudflare_path_domains",
    "cloudflare_path_accounts",
    "cloudflare_path_token",
    "cloudflare_path_messages",
    "cloudmail_api_base",
    "cloudmail_public_token",
    "cloudmail_domains",
    "cloudmail_path_messages",
    "yyds_api_key",
    "yyds_jwt",
    "user_agent",
    "registration_mode",
    "protocol_browser_fallback",
    "protocol_request_timeout_sec",
    "turnstile_solver_kind",
    "turnstile_sitekey",
    "turnstile_solver_timeout_sec",
    "boterdrop_url",
    "capsolver_api_key",
)


def _configured_python_modules() -> dict[str, bool]:
    return {
        "browserAutomation": importlib.util.find_spec("DrissionPage") is not None,
        "httpImpersonation": importlib.util.find_spec("curl_cffi") is not None,
        "vaultEncryption": importlib.util.find_spec("cryptography") is not None,
    }


def _config_with_defaults(values: dict[str, Any] | None = None) -> dict[str, Any]:
    result = dict(app_config.DEFAULT_CONFIG)
    if isinstance(values, dict):
        result.update(values)
    result["multi_thread_enabled"] = False
    result["multi_thread_workers"] = 1
    return result


def _public_config(config: dict[str, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key in CONFIG_FIELDS:
        value = config.get(key, app_config.DEFAULT_CONFIG.get(key, ""))
        output[key] = "" if key in SECRET_CONFIG_FIELDS else value
    return output


def _secret_status(config: dict[str, Any]) -> dict[str, bool]:
    return {
        key: bool(str(config.get(key) or "").strip())
        for key in sorted(SECRET_CONFIG_FIELDS)
    }


def _normalize_import_payload(payload: dict[str, Any]) -> list[dict[str, str]]:
    content = payload.get("content")
    if content is None and isinstance(payload.get("accounts"), list):
        entries = payload["accounts"]
    elif isinstance(content, list):
        entries = content
    elif isinstance(content, dict):
        entries = content.get("accounts") if isinstance(content.get("accounts"), list) else [content]
    elif isinstance(content, str):
        text = content.lstrip("\ufeff").strip()
        if not text:
            return []
        if text.startswith("[") or text.startswith("{"):
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                entries = parsed.get("accounts") if isinstance(parsed.get("accounts"), list) else [parsed]
            elif isinstance(parsed, list):
                entries = parsed
            else:
                raise ValueError("导入文件不是账号列表")
        elif re.search(r"(?m)^\s*email\s*,", text):
            entries = list(csv.DictReader(io.StringIO(text)))
        else:
            entries = []
            for line in text.splitlines():
                raw = line.strip()
                if not raw or raw.startswith("#"):
                    continue
                parts = raw.split("----", 2)
                if len(parts) == 1:
                    entries.append({"sso": parts[0]})
                else:
                    entries.append(
                        {
                            "email": parts[0],
                            "password": parts[1] if len(parts) > 1 else "",
                            "sso": parts[2] if len(parts) > 2 else "",
                        }
                    )
    else:
        raise ValueError("导入参数无效")

    result: list[dict[str, str]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        email = str(entry.get("email") or entry.get("mail") or "").strip()
        password = str(entry.get("password") or entry.get("passwd") or "")
        sso = str(entry.get("sso") or entry.get("sso_token") or entry.get("token") or "").strip()
        if sso.lower().startswith("sso="):
            sso = sso[4:].strip()
        if not email and not sso:
            continue
        result.append({"email": email, "password": password, "sso": sso})
    return result


class GoBridge:
    def __init__(self, ingest_url: str, token: str):
        self.ingest_url = str(ingest_url or "").strip()
        self.token = str(token or "").strip()
        if not self.ingest_url:
            raise RuntimeError("缺少 Go 入库回调地址")
        parsed = urllib.parse.urlsplit(self.ingest_url)
        path = parsed.path
        if path.endswith("/accounts/ingest"):
            path = path[: -len("/accounts/ingest")]
        self.base_url = urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, path.rstrip("/"), "", "")
        )

    def _request(
        self,
        path: str,
        method: str = "GET",
        payload: dict[str, Any] | None = None,
        timeout: float = 45,
    ) -> dict[str, Any]:
        data = None
        headers = {
            "Authorization": "Bearer %s" % self.token,
            "Accept": "application/json",
        }
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read(2048).decode("utf-8", "replace")
            raise RuntimeError("Go 主服务返回 HTTP %s: %s" % (exc.code, detail)) from exc
        except Exception as exc:
            raise RuntimeError("无法连接 Go 主服务: %s" % exc) from exc
        try:
            decoded = json.loads(body.decode("utf-8"))
        except Exception as exc:
            raise RuntimeError("Go 主服务返回了无效 JSON") from exc
        if not isinstance(decoded, dict):
            raise RuntimeError("Go 主服务响应格式无效")
        if "data" in decoded and isinstance(decoded["data"], dict):
            return decoded["data"]
        return decoded

    def exists(self, email: str) -> dict[str, Any]:
        query = urllib.parse.urlencode({"email": email})
        return self._request("/accounts/exists?" + query)

    def ingest(
        self,
        email: str,
        password: str,
        sso: str,
        build_tokens: dict[str, Any] | None,
        source: str,
    ) -> dict[str, Any]:
        return self._request(
            "/accounts/ingest",
            method="POST",
            payload={
                "email": email,
                "password": password,
                "sso": sso,
                "build": build_tokens or {},
                "source": source,
            },
            timeout=150,
        )


class Worker:
    def __init__(self, data_dir: str, callback_url: str, callback_token: str):
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.vault = Vault(str(self.data_dir))
        self.store = WorkerStore(str(self.data_dir))
        interrupted = self.store.mark_interrupted()
        self.bridge = GoBridge(callback_url, callback_token)
        stored = self.vault.get_settings() or {}
        self.config = _config_with_defaults(stored)
        self._config_lock = threading.RLock()
        self.task_lock = threading.RLock()
        self.active_task_id = ""
        self.cancel_event: threading.Event | None = None
        if interrupted:
            self._startup_note = "已标记 %s 个中断任务" % interrupted
        else:
            self._startup_note = ""

    def _save_config(self, value: dict[str, Any]) -> dict[str, Any]:
        validated = app_config.validate_config_structure(value)
        with self._config_lock:
            self.config = validated
            self.vault.save_settings(validated)
        return validated

    def config_payload(self) -> dict[str, Any]:
        from browser_runtime import list_installed_browsers

        with self._config_lock:
            snapshot = dict(self.config)
        return {
            "config": _public_config(snapshot),
            "secretConfigured": _secret_status(snapshot),
            "browsers": list_installed_browsers(),
            "runtime": {
                "ready": all(_configured_python_modules().values()),
                "components": _configured_python_modules(),
            },
        }

    def update_config(self, payload: dict[str, Any]) -> dict[str, Any]:
        incoming = payload.get("config") if isinstance(payload.get("config"), dict) else payload
        clear_secrets = {
            str(item)
            for item in (payload.get("clearSecrets") or [])
            if str(item) in SECRET_CONFIG_FIELDS
        }
        with self._config_lock:
            next_config = dict(self.config)
        for key in CONFIG_FIELDS:
            if key not in incoming:
                continue
            value = incoming[key]
            if key in SECRET_CONFIG_FIELDS:
                if key in clear_secrets:
                    next_config[key] = ""
                elif str(value or "").strip():
                    next_config[key] = str(value).strip()
            else:
                next_config[key] = value
        self._save_config(next_config)
        return self.config_payload()

    def _task_logger(self, task_id: str):
        def write(message: Any) -> None:
            self.store.append_log(task_id, message)

        return write

    def _update_config_for_task(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._config_lock:
            next_config = dict(self.config)
        browser = str(payload.get("browser") or "").strip()
        if browser:
            next_config["browser_choice"] = browser
        if "enableNSFW" in payload:
            next_config["enable_nsfw"] = bool(payload.get("enableNSFW"))
        registration_mode = str(payload.get("registrationMode") or "").strip().lower()
        if registration_mode:
            if registration_mode not in ("auto", "protocol", "browser"):
                raise ValueError("注册方式无效")
            next_config["registration_mode"] = registration_mode
        validated = app_config.validate_run_requirements(next_config)
        with self._config_lock:
            self.config = validated
            self.vault.save_settings(validated)
        return validated

    def start_registration(self, payload: dict[str, Any]) -> dict[str, Any]:
        count = int(payload.get("count") or 0)
        if not 1 <= count <= 5000:
            raise ValueError("本批数量必须在 1 到 5000 之间")
        with self.task_lock:
            if self.active_task_id:
                active = self.store.get_task(self.active_task_id)
                if active and active.get("status") in ("queued", "running", "cancelling"):
                    raise RuntimeError("已有注册任务正在执行")
            task = self.store.create_task("registration", count, payload)
            task_id = str(task["id"])
            self.active_task_id = task_id
            self.cancel_event = threading.Event()
            thread = threading.Thread(
                target=self._run_registration,
                args=(task_id, count, payload),
                name="registration-task-%s" % task_id[:8],
                daemon=True,
            )
            thread.start()
        return task

    def start_relogin(self, payload: dict[str, Any]) -> dict[str, Any]:
        emails = payload.get("emails")
        if not isinstance(emails, list) or not emails:
            raise ValueError("请选择需要重新登录的账号")
        normalized = []
        seen = set()
        for value in emails:
            email = str(value or "").strip()
            key = email.casefold()
            if email and key not in seen:
                normalized.append(email)
                seen.add(key)
        if not normalized:
            raise ValueError("请选择需要重新登录的账号")
        with self.task_lock:
            if self.active_task_id:
                active = self.store.get_task(self.active_task_id)
                if active and active.get("status") in ("queued", "running", "cancelling"):
                    raise RuntimeError("已有注册任务正在执行")
            task = self.store.create_task(
                "relogin",
                len(normalized),
                {**payload, "emails": normalized},
            )
            task_id = str(task["id"])
            self.active_task_id = task_id
            self.cancel_event = threading.Event()
            thread = threading.Thread(
                target=self._run_relogin,
                args=(task_id, normalized, payload),
                name="relogin-task-%s" % task_id[:8],
                daemon=True,
            )
            thread.start()
        return task

    def cancel_task(self, task_id: str) -> dict[str, Any]:
        with self.task_lock:
            if task_id != self.active_task_id or self.cancel_event is None:
                task = self.store.get_task(task_id)
                if task is None:
                    raise KeyError("任务不存在")
                return task
            self.cancel_event.set()
        self.store.update_task(task_id, status="cancelling", cancel_requested=1)
        return self.store.get_task(task_id) or {}

    def _finish_task(self, task_id: str, status: str, error: str = "") -> None:
        self.store.update_task(
            task_id,
            status=status,
            error=error[:4000],
            finished_at=time.time(),
        )
        with self.task_lock:
            if self.active_task_id == task_id:
                self.active_task_id = ""
                self.cancel_event = None

    def _run_registration(
        self,
        task_id: str,
        count: int,
        payload: dict[str, Any],
    ) -> None:
        log = self._task_logger(task_id)
        self.store.update_task(task_id, status="running", started_at=time.time())
        succeeded = 0
        processed = 0
        try:
            config = self._update_config_for_task(payload)
            log("[*] Grok2API v2 注册任务已启动")
            log(
                "[*] 注册模式: %s；协议模式按需启动单个 Chromium 进程"
                % str(config.get("registration_mode") or "auto")
            )
            setup = self._setup_engine(config, log)
            if str(config.get("email_provider") or "").lower() == "cloudmail":
                setup["mail_service"].cloudmail_preflight(
                    log_callback=log,
                    cancel_callback=lambda: bool(self.cancel_event and self.cancel_event.is_set()),
                    defer_until_slot=False,
                )

            browser = setup["browser_runtime"]
            browser_module = setup["browser_module"]
            flow = setup["flow"]

            callbacks = flow.RegistrationCallbacks(
                log=log,
                cancelled=lambda: bool(self.cancel_event and self.cancel_event.is_set()),
            )

            def close_window() -> None:
                browser_module.stop_browser()

            def persist_line(email: str, password: str, sso: str) -> None:
                self.vault.upsert_account(
                    email,
                    password=password,
                    sso=sso,
                    source="registration",
                )

            def queue_unsaved(account: dict[str, Any], error: str) -> bool:
                pending = self.data_dir / "registration-pending.jsonl"
                record = dict(account)
                record["error"] = str(error or "")
                record["created_at"] = time.time()
                with open(pending, "a", encoding="utf-8") as handle:
                    handle.write(json.dumps(record, ensure_ascii=False) + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(pending, 0o600)
                return True

            def add_tokens(sso: str, email: str) -> dict[str, dict[str, Any]]:
                record = self.vault.get_account(email) or {}
                password = str(record.get("password") or "")
                build_tokens: dict[str, Any] = {}
                build_state: dict[str, Any] = {
                    "enabled": True,
                    "ok": False,
                    "error": "",
                }
                def mint_build_tokens() -> dict[str, Any]:
                    if not password:
                        raise RuntimeError("账号库缺少密码，无法完成 Build OAuth")
                    if browser_module.browser is None or browser_module.page is None:
                        log("[*] Build 需要浏览器校验，打开当前账号的无痕上下文")
                        browser_module.start_browser(log_callback=log)
                    page = browser_module.page
                    browser_handle = browser_module.browser
                    context_id = str(
                        getattr(page, "_grok_context_id", "")
                        or browser_module.private_context_id
                    )
                    cookies = browser.cookies_for_context(browser_handle, context_id)
                    if not cookies:
                        cookies = {
                            "sso": sso,
                            "sso-rw": sso,
                        }
                    from xai_auth.browser_confirm import mint_with_browser

                    tokens = mint_with_browser(
                        email=email,
                        password=password,
                        page=page,
                        headless=False,
                        browser_timeout_sec=180,
                        poll_log=log,
                        cancel=lambda: bool(
                            self.cancel_event and self.cancel_event.is_set()
                        ),
                        force_standalone=False,
                        cookies=cookies,
                        reuse_browser=True,
                        request_timeout_sec=20,
                        poll_timeout_sec=20,
                    )
                    if not (
                        tokens.get("access_token")
                        and tokens.get("refresh_token")
                    ):
                        raise RuntimeError("Build OAuth 未返回完整 token")
                    return tokens

                ingest = self.bridge.ingest(
                    email=email,
                    password=password,
                    sso=sso,
                    build_tokens={},
                    source="registration",
                )
                if not bool(ingest.get("buildOk")) and bool(
                    ingest.get("buildNeedsBrowser")
                ):
                    try:
                        log(
                            "[*] 纯 HTTP Build 转换要求浏览器校验，执行一次条件回退"
                        )
                        build_tokens = mint_build_tokens()
                        build_state["ok"] = True
                        ingest = self.bridge.ingest(
                            email=email,
                            password=password,
                            sso=sso,
                            build_tokens=build_tokens,
                            source="registration",
                        )
                    except RegistrationCancelled:
                        raise
                    except Exception as exc:
                        build_state["error"] = redact_log_message(exc)
                        log("[!] Build OAuth 失败，保留 Web/Console 入库: %s" % exc)
                elif not bool(ingest.get("buildOk")):
                    build_state["error"] = "纯 HTTP Build 转换未返回完整 OAuth token"

                build_state["ok"] = bool(ingest.get("buildOk"))
                web_ok = bool(ingest.get("webOk"))
                console_ok = bool(ingest.get("consoleOk"))
                build_ok = bool(ingest.get("buildOk"))
                ingest_ok = web_ok and build_ok and console_ok
                error = "; ".join(
                    str(value)
                    for value in (ingest.get("errors") or [])
                    if str(value or "").strip()
                )
                if build_state["error"] and not build_ok:
                    error = "; ".join(filter(None, (error, build_state["error"])))
                return {
                    "grok2api": {
                        "enabled": True,
                        "ok": ingest_ok,
                        "webOk": web_ok,
                        "buildOk": build_ok,
                        "consoleOk": console_ok,
                        "accountIds": ingest.get("accountIds") or {},
                        "warning": bool(web_ok and console_ok and not build_ok),
                        "error": error,
                    }
                }

            def observe(_batch, account, output, _callbacks) -> None:
                nonlocal succeeded, processed
                if account is None:
                    return
                processed += 1
                self.store.increment_task(task_id, current_email=account.email)
                state = output.pools.get("grok2api", {}) if output is not None else {}
                if account.ok and output is not None and output.saved and state.get("ok"):
                    succeeded += 1
                self.store.update_task(
                    task_id,
                    processed=processed,
                    succeeded=succeeded,
                    failed=max(0, processed - succeeded),
                )

            def preflight_mail() -> Any:
                provider = str(config.get("email_provider") or "").lower()
                if provider != "cloudmail":
                    return True
                return setup["mail_service"].cloudmail_preflight(
                    log_callback=log,
                    cancel_callback=cancel,
                    defer_until_slot=False,
                )

            def cancel() -> bool:
                return bool(self.cancel_event and self.cancel_event.is_set())

            protocol_callback = None
            registration_mode = str(
                config.get("registration_mode") or "auto"
            ).lower()
            if registration_mode in ("auto", "protocol"):
                protocol_module = setup["protocol_registration"]

                def protocol_session_factory(_config: dict[str, Any]) -> Any:
                    from curl_cffi import requests as curl_requests

                    proxies = browser_runtime.get_proxies()
                    return curl_requests.Session(
                        impersonate="chrome",
                        proxies=proxies or None,
                    )

                def register_by_protocol() -> Any:
                    registrar = protocol_module.ProtocolRegistrar(
                        config,
                        log=log,
                        cancelled=cancel,
                        get_email_and_token=setup["mail_service"].get_email_and_token,
                        get_oai_code=setup["mail_service"].get_oai_code,
                        build_profile=browser_module.build_profile,
                        enable_nsfw=lambda sso: browser_module.enable_nsfw_for_token(
                            sso,
                            log_callback=log,
                        ),
                        stage=flow._set_registration_stage,
                        session_factory=protocol_session_factory,
                    )
                    result_value = registrar.register_safely()
                    return flow.RegistrationResult(
                        ok=True,
                        email=result_value.email,
                        password=result_value.password,
                        sso=result_value.sso,
                        profile={
                            **dict(result_value.profile or {}),
                            "registration_mode": "protocol",
                        },
                    )

                protocol_callback = register_by_protocol

            operations = flow.RegistrationOperations(
                start_browser=lambda: browser_module.start_browser(log_callback=log),
                restart_browser=lambda: browser_module.restart_browser(log_callback=log),
                browser_missing=lambda: browser_module.browser is None,
                open_signup_page=lambda: browser_module.open_signup_page(
                    log_callback=log,
                    cancel_callback=cancel,
                ),
                fill_email_and_submit=lambda: browser_module.fill_email_and_submit(
                    log_callback=log,
                    cancel_callback=cancel,
                ),
                save_mail_credential=lambda _email, _token: True,
                fill_code_and_submit=lambda email, token: browser_module.fill_code_and_submit(
                    email,
                    token,
                    log_callback=log,
                    cancel_callback=cancel,
                ),
                fill_profile_and_submit=lambda: browser_module.fill_profile_and_submit(
                    log_callback=log,
                    cancel_callback=cancel,
                ),
                wait_for_sso_cookie=lambda: browser_module.wait_for_sso_cookie(
                    log_callback=log,
                    cancel_callback=cancel,
                ),
                enable_nsfw=lambda sso: browser_module.enable_nsfw_for_token(
                    sso,
                    log_callback=log,
                ),
                persist_account_line=persist_line,
                queue_unsaved_result=queue_unsaved,
                add_tokens=add_tokens,
                cleanup=lambda reason: browser_module.cleanup_runtime_memory(
                    log_callback=log,
                    reason=reason,
                ),
                close_browser_window=close_window,
                sleep=lambda seconds: sleep_with_cancel(seconds, cancel),
                cancelled_exception=RegistrationCancelled,
                retry_exception=AccountRetryNeeded,
                internal_stage_markers=True,
                screen_sso=setup["screen_sso"],
                preflight_mail=preflight_mail,
                register_by_protocol=protocol_callback,
                protocol_browser_fallback=bool(
                    config.get("protocol_browser_fallback", True)
                ),
            )
            result = flow.run_batch(
                count=count,
                callbacks=callbacks,
                observer=observe,
                ops=operations,
                enable_nsfw=bool(config.get("enable_nsfw", True)),
                cleanup_interval=5,
                max_slot_retry=3,
                max_mail_retry=3,
            )
            processed = int(result.processed_count or processed)
            succeeded = min(processed, succeeded)
            self.store.update_task(
                task_id,
                processed=processed,
                succeeded=succeeded,
                failed=max(0, processed - succeeded),
            )
            if result.cancelled or (self.cancel_event and self.cancel_event.is_set()):
                status = "cancelled"
                log("[!] 注册任务已停止")
            else:
                status = "completed"
                log(
                    "[*] 任务完成：成功 %s，失败 %s，结果不确定 %s"
                    % (
                        succeeded,
                        max(0, processed - succeeded),
                        int(result.uncertain_count or 0),
                    )
                )
            self._finish_task(task_id, status)
        except RegistrationCancelled:
            self._finish_task(task_id, "cancelled")
            log("[!] 注册任务已停止")
        except Exception as exc:
            message = log_exception("注册任务失败", exc, log) or str(exc)
            self.store.update_task(
                task_id,
                processed=processed,
                succeeded=succeeded,
                failed=max(0, processed - succeeded),
            )
            self._finish_task(task_id, "failed", message)
        finally:
            try:
                from browser_runtime import shutdown_shared_browser

                shutdown_shared_browser()
            except Exception as exc:
                log("[Debug] 关闭共享浏览器失败: %s" % exc)

    def _setup_engine(self, config: dict[str, Any], log) -> dict[str, Any]:
        app_config.config.clear()
        app_config.config.update(config)

        import browser_runtime
        import mail_service
        import protocol_registration
        import registration_browser
        import registration_flow

        browser_runtime.configure_runtime(config)
        namespace: dict[str, Any] = {
            "config": config,
            "http_get": browser_runtime.http_get,
            "http_post": browser_runtime.http_post,
            "get_proxies": browser_runtime.get_proxies,
            "get_configured_proxy": browser_runtime.get_configured_proxy,
            "is_proxy_connection_error": browser_runtime.is_proxy_connection_error,
            "page_has_proxy_error": browser_runtime.page_has_proxy_error,
            "raise_if_cancelled": raise_if_cancelled,
            "sleep_with_cancel": sleep_with_cancel,
            "log_exception": log_exception,
            "RegistrationCancelled": RegistrationCancelled,
            "AccountRetryNeeded": AccountRetryNeeded,
            "get_user_agent": mail_service.get_user_agent,
            "get_email_and_token": mail_service.get_email_and_token,
            "get_oai_code": mail_service.get_oai_code,
        }
        mail_service.bind_runtime(namespace)
        namespace["get_user_agent"] = mail_service.get_user_agent
        namespace["get_email_and_token"] = mail_service.get_email_and_token
        namespace["get_oai_code"] = mail_service.get_oai_code
        registration_browser.bind_runtime(namespace)

        screen_sso = None
        if bool(config.get("sso_risk_gate_enabled", True)):
            import sso_risk

            sso_risk.configure_risk_runtime(config, browser_runtime.http_get)

            def screen_sso(sso: str, email: str) -> Any:
                return sso_risk.ensure_sso_eligible(
                    sso,
                    email=email,
                    log_callback=log,
                )

        return {
            "browser_runtime": browser_runtime,
            "browser_module": registration_browser,
            "flow": registration_flow,
            "mail_service": mail_service,
            "screen_sso": screen_sso,
            "protocol_registration": protocol_registration,
        }

    def _run_relogin(
        self,
        task_id: str,
        emails: list[str],
        payload: dict[str, Any],
    ) -> None:
        log = self._task_logger(task_id)
        self.store.update_task(task_id, status="running", started_at=time.time())
        succeeded = 0
        failed = 0
        skipped = 0
        browser_module = None
        browser_runtime = None
        try:
            config = self._update_config_for_task(payload)
            setup = self._setup_engine(config, log)
            browser_runtime = setup["browser_runtime"]
            browser_module = setup["browser_module"]
            from xai_auth.browser_confirm import login_with_email_password, mint_with_browser
            required_providers = {"grok_web", "grok_build", "grok_console"}

            def ensure_browser() -> None:
                if browser_module.browser is None or browser_module.page is None:
                    browser_module.start_browser(log_callback=log)

            def ingest_account(
                email: str,
                password: str,
                sso: str,
                build_tokens: dict[str, Any] | None = None,
            ) -> dict[str, Any]:
                return self.bridge.ingest(
                    email=email,
                    password=password,
                    sso=sso,
                    build_tokens=build_tokens or {},
                    source="relogin",
                )

            def mint_build_tokens(email: str, password: str, sso: str) -> dict[str, Any]:
                if not password:
                    raise RuntimeError("账号缺少密码，无法完成 Build 浏览器授权")
                ensure_browser()
                page = browser_module.page
                browser_handle = browser_module.browser
                context_id = str(
                    getattr(page, "_grok_context_id", "")
                    or browser_module.private_context_id
                )
                cookies = browser_runtime.cookies_for_context(
                    browser_handle, context_id
                )
                if not cookies:
                    cookies = {"sso": sso, "sso-rw": sso}
                tokens = mint_with_browser(
                    email=email,
                    password=password,
                    page=page,
                    headless=False,
                    browser_timeout_sec=180,
                    poll_log=log,
                    cancel=lambda: bool(
                        self.cancel_event and self.cancel_event.is_set()
                    ),
                    force_standalone=False,
                    cookies=cookies,
                    reuse_browser=True,
                    request_timeout_sec=20,
                    poll_timeout_sec=20,
                )
                if not (
                    tokens.get("access_token")
                    and tokens.get("refresh_token")
                ):
                    raise RuntimeError("Build OAuth 未返回完整 token")
                return tokens

            def ingest_with_build_fallback(
                email: str,
                password: str,
                sso: str,
            ) -> dict[str, Any]:
                ingest = ingest_account(email, password, sso)
                if bool(ingest.get("buildOk")) or not bool(
                    ingest.get("buildNeedsBrowser")
                ):
                    return ingest
                log("[*] 入库要求浏览器校验 Build，执行条件回退")
                tokens = mint_build_tokens(email, password, sso)
                return ingest_account(email, password, sso, build_tokens=tokens)

            def complete(ingest: dict[str, Any]) -> bool:
                return bool(
                    ingest.get("webOk")
                    and ingest.get("buildOk")
                    and ingest.get("consoleOk")
                )

            for index, email in enumerate(emails, start=1):
                if self.cancel_event and self.cancel_event.is_set():
                    raise RegistrationCancelled("任务已停止")
                self.store.increment_task(task_id, current_email=email)
                log("--- 重新登录 %s/%s: %s ---" % (index, len(emails), email))
                record = self.vault.get_account(email)
                if not record:
                    skipped += 1
                    self.store.increment_task(task_id, processed=1, skipped=1)
                    log("[!] 本地账号库不存在该账号，已跳过")
                    continue
                password = str(record.get("password") or "")
                sso = str(record.get("sso") or "")
                if not password and not sso:
                    skipped += 1
                    self.store.increment_task(task_id, processed=1, skipped=1)
                    log("[!] 账号缺少密码和 SSO，无法重新登录，已跳过")
                    continue
                try:
                    exists = self.bridge.exists(email)
                    providers = {
                        str(value or "").strip()
                        for value in (exists.get("providers") or [])
                        if str(value or "").strip()
                    }
                    if required_providers.issubset(providers):
                        skipped += 1
                        self.store.increment_task(task_id, processed=1, skipped=1)
                        log("[*] Grok2API 的 Web / Build / Console 均完整，已跳过")
                        continue
                    missing = sorted(required_providers - providers)
                    if missing:
                        log("[*] Grok2API 缺失渠道，将补全: %s" % ", ".join(missing))
                except Exception as exc:
                    failed += 1
                    self.store.increment_task(task_id, processed=1, failed=1)
                    log("[!] 检查 Grok2API 账号失败: %s" % exc)
                    continue

                page = None
                context_id = ""
                try:
                    ingest: dict[str, Any] | None = None
                    if sso:
                        log("[*] 先复用现有 SSO 进行纯 HTTP 入库")
                        try:
                            ingest = ingest_with_build_fallback(email, password, sso)
                            if complete(ingest):
                                succeeded += 1
                                self.vault.upsert_account(
                                    email,
                                    password=password,
                                    sso=sso,
                                    source="relogin",
                                )
                                log("[+] 已使用现有 SSO 补全 Web / Build / Console")
                                self.store.increment_task(
                                    task_id, processed=1, succeeded=1
                                )
                                continue
                            log(
                                "[!] 现有 SSO 未能补全渠道: %s"
                                % (
                                    "; ".join(ingest.get("errors") or [])
                                    or "unknown error"
                                )
                            )
                        except RegistrationCancelled:
                            raise
                        except Exception as exc:
                            log("[!] 现有 SSO 入库失败，尝试重新登录: %s" % exc)

                    if not password:
                        failed += 1
                        self.store.increment_task(task_id, processed=1, failed=1)
                        log("[!] 现有 SSO 未能补全且账号缺少密码，无法重新登录")
                        continue

                    ensure_browser()
                    page = browser_module.page
                    browser_handle = browser_module.browser
                    context_id = str(
                        getattr(page, "_grok_context_id", "")
                        or browser_module.private_context_id
                    )

                    def cookie_reader() -> Any:
                        return browser_runtime.cookies_for_context(
                            browser_handle, context_id
                        )

                    refreshed_sso = login_with_email_password(
                        page,
                        email,
                        password,
                        cookie_reader=cookie_reader,
                        timeout_sec=240,
                        stop_event=self.cancel_event,
                        log=log,
                    )
                    if not refreshed_sso:
                        raise RuntimeError("登录流程未返回 SSO")
                    sso = refreshed_sso
                    self.vault.upsert_account(
                        email,
                        password=password,
                        sso=sso,
                        source="relogin",
                    )
                    log("[+] 已刷新 Web SSO 并更新本地加密账号库")
                    ingest = ingest_with_build_fallback(email, password, sso)
                    ok = complete(ingest)
                    if ok:
                        succeeded += 1
                        log(
                            "[+] 已入库 Grok Web / Build / Console: %s"
                            % email
                        )
                    else:
                        failed += 1
                        log(
                            "[!] 入库未完整完成: %s"
                            % (
                                "; ".join(ingest.get("errors") or [])
                                or "unknown error"
                            )
                        )
                    self.store.increment_task(
                        task_id,
                        processed=1,
                        succeeded=1 if ok else 0,
                        failed=0 if ok else 1,
                    )
                except RegistrationCancelled:
                    raise
                except Exception as exc:
                    failed += 1
                    self.store.increment_task(task_id, processed=1, failed=1)
                    log_exception("重新登录失败 %s" % email, exc, log)
                finally:
                    if page is not None and browser_module.browser is not None:
                        try:
                            browser_runtime.close_private_window(
                                browser_module.browser, page, context_id
                            )
                        except Exception as exc:
                            log("[Debug] 关闭重新登录无痕窗口失败: %s" % exc)
                    try:
                        browser_module.stop_browser()
                    except Exception:
                        pass
                    try:
                        browser_module.stop_browser_proxy_bridge()
                    except Exception:
                        pass
                time.sleep(0.4)
            status = "completed"
            if self.cancel_event and self.cancel_event.is_set():
                status = "cancelled"
            log(
                "[*] 重新登录任务结束：成功 %s，失败 %s，跳过 %s"
                % (succeeded, failed, skipped)
            )
            self._finish_task(task_id, status)
        except RegistrationCancelled:
            self._finish_task(task_id, "cancelled")
            log("[!] 重新登录任务已停止")
        except Exception as exc:
            message = log_exception("重新登录任务失败", exc, log) or str(exc)
            self._finish_task(task_id, "failed", message)
        finally:
            if browser_module is not None:
                try:
                    browser_module.stop_browser()
                except Exception:
                    pass
            if browser_runtime is not None:
                try:
                    browser_runtime.shutdown_shared_browser()
                except Exception:
                    pass

    def import_accounts(self, payload: dict[str, Any]) -> dict[str, Any]:
        entries = _normalize_import_payload(payload)
        imported = 0
        updated = 0
        skipped = 0
        for entry in entries:
            email = entry["email"]
            if not email or "@" not in email:
                skipped += 1
                continue
            existed = self.vault.get_account(email, include_secrets=False) is not None
            self.vault.upsert_account(
                email,
                password=entry["password"],
                sso=entry["sso"],
                source=str(payload.get("source") or "import"),
            )
            if existed:
                updated += 1
            else:
                imported += 1
        return {
            "imported": imported,
            "updated": updated,
            "skipped": skipped,
            "total": len(entries),
        }

    def delete_accounts(self, emails: list[Any]) -> dict[str, Any]:
        return {"deleted": self.vault.delete_accounts(str(item) for item in emails)}

    def export_accounts(self, emails: list[Any], format_name: str) -> tuple[bytes, str, str]:
        if emails:
            records, missing = self.vault.select_accounts(str(item) for item in emails)
            if missing:
                raise ValueError("有 %s 个所选账号不存在" % missing)
        else:
            records = self.vault.list_accounts(include_secrets=True, limit=10000)
        format_name = str(format_name or "text").lower()
        stamp = time.strftime("%Y%m%d-%H%M%S")
        if format_name == "json":
            body = json.dumps(
                {"version": 2, "accounts": records},
                ensure_ascii=False,
                indent=2,
            ).encode("utf-8")
            return body, "application/json", "grok2api-v2-accounts-%s.json" % stamp
        if format_name == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(("email", "password", "sso", "source", "updatedAt"))
            for record in records:
                writer.writerow(
                    (
                        record.get("email", ""),
                        record.get("password", ""),
                        record.get("sso", ""),
                        record.get("source", ""),
                        record.get("updatedAt", ""),
                    )
                )
            return (
                output.getvalue().encode("utf-8"),
                "text/csv; charset=utf-8",
                "grok2api-v2-accounts-%s.csv" % stamp,
            )
        lines = [
            "%s----%s----%s"
            % (
                record.get("email", ""),
                record.get("password", ""),
                record.get("sso", ""),
            )
            for record in records
        ]
        return (
            ("\n".join(lines) + "\n").encode("utf-8"),
            "text/plain; charset=utf-8",
            "grok2api-v2-accounts-%s.txt" % stamp,
        )

    def close(self) -> None:
        with self.task_lock:
            if self.cancel_event is not None:
                self.cancel_event.set()
        try:
            from browser_runtime import shutdown_shared_browser

            shutdown_shared_browser()
        except Exception:
            pass
        self.store.close()
        self.vault.close()


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "Grok2APIv2Registration/1.0"
    protocol_version = "HTTP/1.1"

    @property
    def worker(self) -> Worker:
        return self.server.worker  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _authorized(self) -> bool:
        header = str(self.headers.get("Authorization") or "")
        expected = str(self.server.token)  # type: ignore[attr-defined]
        provided = header[7:].strip() if header.lower().startswith("bearer ") else ""
        return bool(provided) and secrets.compare_digest(provided, expected)

    def _json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length < 0 or length > MAX_REQUEST_BYTES:
            raise ValueError("请求体过大")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            value = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise ValueError("请求 JSON 无效") from exc
        if not isinstance(value, dict):
            raise ValueError("请求 JSON 必须是对象")
        return value

    def _send_json(self, status: int, data: Any, envelope: bool = True) -> None:
        payload = {"data": data} if envelope else data
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status: int, code: str, message: str) -> None:
        self._send_json(
            status,
            {"error": {"code": code, "message": redact_log_message(message)}},
            envelope=False,
        )

    def _send_bytes(
        self,
        status: int,
        body: bytes,
        content_type: str,
        filename: str = "",
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if filename:
            self.send_header(
                "Content-Disposition",
                'attachment; filename="%s"' % filename.replace('"', ""),
            )
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = urllib.parse.parse_qs(parsed.query)
        if path == "/healthz":
            self._send_json(
                200,
                {
                    "ok": True,
                    "configured": all(_configured_python_modules().values()),
                    "components": _configured_python_modules(),
                    "note": self.worker._startup_note,
                },
            )
            return
        if not self._authorized():
            self._send_error(401, "registrationWorkerUnauthorized", "内部认证失败")
            return
        try:
            if path == "/config":
                self._send_json(200, self.worker.config_payload())
                return
            if path == "/browsers":
                from browser_runtime import list_installed_browsers

                self._send_json(200, {"items": list_installed_browsers()})
                return
            if path == "/tasks":
                self._send_json(200, {"items": self.worker.store.list_tasks()})
                return
            if path == "/tasks/latest":
                self._send_json(200, self.worker.store.latest_task())
                return
            if path.startswith("/tasks/"):
                parts = path.split("/")
                task_id = parts[2]
                if len(parts) == 3:
                    task = self.worker.store.get_task(task_id)
                    if task is None:
                        raise KeyError("任务不存在")
                    self._send_json(200, task)
                    return
                if len(parts) == 4 and parts[3] == "logs":
                    after_id = int((query.get("afterId") or ["0"])[0])
                    limit = int((query.get("limit") or ["1000"])[0])
                    self._send_json(
                        200,
                        {
                            "items": self.worker.store.list_logs(
                                task_id,
                                after_id=after_id,
                                limit=limit,
                            )
                        },
                    )
                    return
            if path == "/accounts":
                search = (query.get("search") or [""])[0]
                limit = int((query.get("limit") or ["2000"])[0])
                self._send_json(
                    200,
                    {
                        "items": self.worker.vault.list_accounts(
                            search=search,
                            limit=limit,
                            include_secrets=False,
                        )
                    },
                )
                return
            if path == "/accounts/export":
                emails = query.get("email") or []
                body, content_type, filename = self.worker.export_accounts(
                    emails,
                    (query.get("format") or ["text"])[0],
                )
                self._send_bytes(200, body, content_type, filename)
                return
            self._send_error(404, "notFound", "接口不存在")
        except KeyError as exc:
            self._send_error(404, "notFound", str(exc))
        except (ValueError, VaultError) as exc:
            self._send_error(400, "invalidRequest", str(exc))
        except Exception as exc:
            self._send_error(500, "registrationWorkerError", str(exc))

    def do_PUT(self) -> None:
        path = urllib.parse.urlsplit(self.path).path.rstrip("/") or "/"
        if not self._authorized():
            self._send_error(401, "registrationWorkerUnauthorized", "内部认证失败")
            return
        try:
            if path == "/config":
                self._send_json(200, self.worker.update_config(self._json_body()))
                return
            self._send_error(404, "notFound", "接口不存在")
        except (ValueError, VaultError, app_config.ConfigError) as exc:
            self._send_error(400, "invalidConfig", str(exc))
        except Exception as exc:
            self._send_error(500, "registrationWorkerError", str(exc))

    def do_POST(self) -> None:
        path = urllib.parse.urlsplit(self.path).path.rstrip("/") or "/"
        if not self._authorized():
            self._send_error(401, "registrationWorkerUnauthorized", "内部认证失败")
            return
        try:
            payload = self._json_body()
            if path == "/tasks":
                kind = str(payload.get("kind") or "registration").strip().lower()
                if kind == "registration":
                    task = self.worker.start_registration(payload)
                elif kind == "relogin":
                    task = self.worker.start_relogin(payload)
                else:
                    raise ValueError("不支持的任务类型")
                self._send_json(202, task)
                return
            if path.startswith("/tasks/") and path.endswith("/cancel"):
                task_id = path.split("/")[2]
                self._send_json(200, self.worker.cancel_task(task_id))
                return
            if path == "/accounts/import":
                self._send_json(200, self.worker.import_accounts(payload))
                return
            if path == "/accounts/relogin":
                task = self.worker.start_relogin(payload)
                self._send_json(202, task)
                return
            if path == "/accounts/delete":
                emails = payload.get("emails")
                if not isinstance(emails, list):
                    raise ValueError("账号列表无效")
                self._send_json(200, self.worker.delete_accounts(emails))
                return
            self._send_error(404, "notFound", "接口不存在")
        except KeyError as exc:
            self._send_error(404, "notFound", str(exc))
        except (ValueError, VaultError, app_config.ConfigError, RuntimeError) as exc:
            self._send_error(400, "registrationRequestFailed", str(exc))
        except Exception as exc:
            self._send_error(500, "registrationWorkerError", str(exc))


class WorkerServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        worker: Worker,
        token: str,
    ):
        super().__init__(address, ApiHandler)
        self.worker = worker
        self.token = token


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Grok2API v2 registration worker")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--callback-url", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    token = str(os.environ.get("GROK2API_REGISTRATION_WORKER_TOKEN") or "").strip()
    callback_token = str(
        os.environ.get("GROK2API_REGISTRATION_CALLBACK_TOKEN") or ""
    ).strip()
    if len(token) < 24 or len(callback_token) < 24:
        raise SystemExit("registration worker tokens are missing or too short")
    worker = Worker(args.data_dir, args.callback_url, callback_token)
    server = WorkerServer((args.host, int(args.port)), worker, token)
    port = int(server.server_address[1])
    print(
        json.dumps(
            {"event": "registration_worker_ready", "host": args.host, "port": port},
            ensure_ascii=False,
        ),
        flush=True,
    )
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.shutdown()
        server.server_close()
        worker.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
