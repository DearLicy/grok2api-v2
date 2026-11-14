"""提供共享的 HTTP 请求、代理处理和 Chromium 启动参数。"""
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
import urllib.parse

from DrissionPage import Chromium, ChromiumOptions
from curl_cffi import requests
from xai_auth.proxyutil import (
    LocalAuthProxyBridge,
    prepare_chromium_proxy,
    proxy_for_chromium,
)
from proxy_pool import (
    ProxyTransportError,
    current_proxy_lease,
    managed_proxy_active,
    safe_proxy_error_text,
)

_config = {}
_extension_path = ""


def _legacy_extension_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "turnstilePatch")


def _resolve_extension_path(explicit=None):
    if explicit is not None:
        candidate = str(explicit or "").strip()
        return candidate if candidate and os.path.isdir(candidate) else ""
    configured = str(_extension_path or "").strip()
    if configured and os.path.isdir(configured):
        return configured
    legacy = _legacy_extension_path()
    return legacy if os.path.isdir(legacy) else ""


def configure_runtime(config_ref, extension_path=""):
    global _config, _extension_path
    _config = config_ref
    _extension_path = str(extension_path or "")


def get_configured_proxy():
    lease = current_proxy_lease()
    if lease is not None:
        return str(lease.proxy_url or "").strip()
    mode = str(_config.get("proxy_mode", "auto") or "auto").strip().lower()
    if mode == "direct" or mode in ("single", "pool"):
        return ""
    return str(_config.get("proxy", "") or "").strip()


def get_proxies():
    proxy = get_configured_proxy()
    return {"http": proxy, "https": proxy} if proxy else {}


def _parse_proxy_url(proxy):
    raw = str(proxy or "").strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = "http://" + raw
    try:
        return urllib.parse.urlsplit(raw)
    except Exception:
        return None


def _safe_proxy_port(parsed):
    try:
        return parsed.port
    except Exception:
        return None


def _proxy_has_auth(proxy):
    parsed = _parse_proxy_url(proxy)
    return bool(parsed and parsed.hostname and (parsed.username is not None or parsed.password is not None))


def _strip_proxy_auth(proxy):
    raw = str(proxy or "").strip()
    parsed = _parse_proxy_url(raw)
    if not parsed or not parsed.hostname:
        return raw
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = "[%s]" % host
    port = _safe_proxy_port(parsed)
    netloc = "%s:%s" % (host, port) if port else host
    stripped = urllib.parse.urlunsplit((parsed.scheme or "http", netloc, parsed.path, parsed.query, parsed.fragment))
    return stripped.split("://", 1)[1] if "://" not in raw else stripped


def _proxy_endpoint_terms(proxy=None):
    parsed = _parse_proxy_url(proxy or get_configured_proxy())
    if not parsed or not parsed.hostname:
        return []
    terms = [parsed.hostname]
    port = _safe_proxy_port(parsed)
    if port:
        terms.extend(["%s:%s" % (parsed.hostname, port), "port %s" % port])
    return [item.lower() for item in terms if item]


def is_proxy_connection_error(exc):
    if not get_configured_proxy():
        return False
    err = str(exc or "").lower()
    if not err:
        return False
    if any(item in err for item in ("proxy", "tunnel", "socks")):
        return True
    markers = (
        "could not connect", "failed to connect", "connection refused",
        "connection reset", "connect error", "timed out", "timeout",
    )
    if any(item in err for item in markers):
        terms = _proxy_endpoint_terms()
        return not terms or any(term in err for term in terms)
    return False


def page_has_proxy_error(page_obj):
    try:
        url = str(getattr(page_obj, "url", "") or "")
        title = str(page_obj.run_js("return document.title || ''") or "")
        body = str(page_obj.run_js("return document.body ? document.body.innerText.slice(0, 2000) : ''") or "")
    except Exception:
        return False
    text = "%s\n%s\n%s" % (url, title, body)
    text = text.lower()
    failed = any(marker in text for marker in (
        "err_proxy", "proxy connection failed", "proxy server",
        "proxy authentication", "tunnel connection failed",
        "无法连接到代理服务器", "代理服务器",
    ))
    if failed and managed_proxy_active():
        raise ProxyTransportError("Chromium 检测到代理连接错误页面")
    return failed


def prepare_browser_proxy(use_proxy=True, log_callback=None):
    # Managed registration leases must never silently switch to another IP in
    # the middle of an account. Legacy auto mode keeps the historical direct
    # fallback behavior when callers explicitly pass use_proxy=False.
    if managed_proxy_active():
        use_proxy = True
    proxy = get_configured_proxy()
    if not use_proxy or not proxy:
        return "", None
    logger = None
    if log_callback:
        logger = lambda message: log_callback("[*] 已为 Chromium启动本地认证代理桥: %s" % message.split(": ", 1)[-1]) if "started authenticated proxy bridge" in message else log_callback(message)
    return prepare_chromium_proxy(proxy, log=logger)


def apply_browser_proxy_option(options, proxy):
    if not proxy:
        return
    if hasattr(options, "set_proxy"):
        try:
            options.set_proxy(proxy)
            return
        except Exception:
            pass
    if not hasattr(options, "set_argument"):
        raise AttributeError("当前 DrissionPage ChromiumOptions 不支持设置浏览器代理")
    try:
        options.set_argument("--proxy-server=%s" % proxy)
    except TypeError:
        options.set_argument("--proxy-server", proxy)


_BROWSER_SPECS = (
    ("google-chrome", "Google Chrome", "Google Chrome.app", ("Contents", "MacOS", "Google Chrome")),
    ("microsoft-edge", "Microsoft Edge", "Microsoft Edge.app", ("Contents", "MacOS", "Microsoft Edge")),
    ("brave", "Brave", "Brave Browser.app", ("Contents", "MacOS", "Brave Browser")),
    ("chromium", "Chromium", "Chromium.app", ("Contents", "MacOS", "Chromium")),
)
_BROWSER_COMMANDS = {
    "google-chrome": ("google-chrome", "google-chrome-stable"),
    "microsoft-edge": ("microsoft-edge", "msedge"),
    "brave": ("brave-browser", "brave"),
    "chromium": ("chromium", "chromium-browser"),
}
_CHROMIUM_ORDER = ("google-chrome", "microsoft-edge", "brave", "chromium")
_browser_roots_override = None


def _browser_roots():
    if _browser_roots_override is not None:
        return list(_browser_roots_override)
    return [
        "/Applications",
        os.path.expanduser("~/Applications"),
        "/System/Applications",
    ]


def _installed_browser_path(app_name, executable_parts):
    for root in _browser_roots():
        path = os.path.join(root, app_name, *executable_parts)
        if os.path.isfile(path):
            return path
    return ""


def list_installed_browsers():
    found = []
    for ident, name, app_name, executable_parts in _BROWSER_SPECS:
        path = _installed_browser_path(app_name, executable_parts)
        if not path:
            for command in _BROWSER_COMMANDS.get(ident, ()):
                path = shutil.which(command) or ""
                if path:
                    break
        if path:
            found.append({
                "id": ident,
                "name": name,
                "path": path,
                "automatable": True,
            })
    forced = _forced_browser_choice()
    if forced:
        return [item for item in found if item["id"] == forced]
    return found


def _runtime_config():
    if _config:
        return _config
    import app_config
    return app_config.config


def _forced_browser_choice():
    return str(os.environ.get("GROK2API_REGISTRATION_BROWSER") or "").strip()


def browser_display_name(path):
    executable = os.path.basename(str(path or "")).lower()
    for ident, name, _app_name, _executable_parts in _BROWSER_SPECS:
        if executable in {
            command.lower() for command in _BROWSER_COMMANDS.get(ident, ())
        }:
            return name
    for part in str(path or "").split(os.sep):
        if part.endswith(".app"):
            return part[:-4]
    return "浏览器"


def resolve_browser_executable():
    # Only Chromium browsers can run this flow. A saved Safari choice is legacy.
    installed = {item["id"]: item for item in list_installed_browsers()}
    choice = _forced_browser_choice() or str(
        _runtime_config().get("browser_choice") or "google-chrome"
    ).strip() or "google-chrome"
    chosen = installed.get(choice)
    if chosen:
        return chosen["path"], ""
    for ident in _CHROMIUM_ORDER:
        item = installed.get(ident)
        if item:
            return item["path"], choice
    return "", choice


_shared_lock = threading.RLock()
_shared_browser = {"browser": None}
_active_browser_port = 0


def shared_browser_data_dir(port=None):
    port = int(port or browser_debug_port())
    path = os.path.join(tempfile.gettempdir(), "grok2api-v2-browser-%s" % port)
    os.makedirs(path, exist_ok=True)
    return path


def _port_open(port):
    sock = socket.socket()
    sock.settimeout(0.2)
    try:
        return sock.connect_ex(("127.0.0.1", int(port))) == 0
    except Exception:
        return False
    finally:
        try:
            sock.close()
        except Exception:
            pass


def browser_debug_port():
    global _active_browser_port
    with _shared_lock:
        # The Go-managed worker keeps one long-lived Chromium process for a
        # whole task. Its debug port must remain stable while that process is
        # alive; allocating a new port here would force a browser restart and
        # invalidate every private context.
        if _active_browser_port and _browser_alive(_shared_browser.get("browser")):
            return _active_browser_port
    configured = str(os.environ.get("GROK2API_BROWSER_DEBUG_PORT") or "").strip()
    if not configured and _config:
        configured = str(_config.get("browser_debug_port") or "").strip()
    if configured and configured != "0":
        try:
            port = int(configured)
        except ValueError as exc:
            raise RuntimeError("浏览器调试端口必须是整数") from exc
        if not 1024 <= port <= 65535:
            raise RuntimeError("浏览器调试端口必须在 1024 到 65535 之间")
        _active_browser_port = port
        return port
    with _shared_lock:
        if _active_browser_port and not _port_open(_active_browser_port):
            return _active_browser_port
        sock = socket.socket()
        try:
            sock.bind(("127.0.0.1", 0))
            _active_browser_port = int(sock.getsockname()[1])
            return _active_browser_port
        finally:
            sock.close()


def _browser_alive(browser):
    try:
        return bool(browser) and bool(browser.states.is_alive)
    except Exception:
        return False


def create_browser_options(browser_proxy="", extension_path=None):
    port = browser_debug_port()
    options = ChromiumOptions()
    # One process and one debugging port per running task; each account still
    # receives a disposable browser context.
    options.set_local_port(port)
    options.set_user_data_path(shared_browser_data_dir(port))
    options.set_timeouts(base=1)
    browser_path, _fallback = resolve_browser_executable()
    if browser_path:
        options.set_browser_path(browser_path)
    if str(os.environ.get("GROK2API_REGISTRATION_DISABLE_SANDBOX") or "").strip() == "1":
        options.set_argument("--no-sandbox")
        options.set_argument("--disable-dev-shm-usage")
    options.incognito(True)
    apply_browser_proxy_option(options, browser_proxy)
    effective_extension = _resolve_extension_path(extension_path)
    if effective_extension:
        options.add_extension(effective_extension)
    return options


def _listening_pids(port):
    try:
        output = subprocess.check_output(
            ["lsof", "-nP", "-iTCP:%s" % int(port), "-sTCP:LISTEN", "-t"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return []
    return [int(item) for item in output.split() if item.isdigit()]


def _command_for_pid(pid):
    try:
        output = subprocess.check_output(
            ["ps", "-p", str(int(pid)), "-o", "command="],
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return ""
    return output.strip()


def _stop_owned_debug_browser(port=None):
    # Attaching to an already open registration browser keeps its old windows.
    port = int(port or browser_debug_port())
    marker = os.path.basename(shared_browser_data_dir(port).rstrip(os.sep))
    deadline = time.time() + 4
    force = False
    while time.time() < deadline:
        owned = [
            pid for pid in _listening_pids(port)
            if marker and marker in _command_for_pid(pid)
        ]
        if not owned:
            return
        for pid in owned:
            try:
                os.kill(pid, signal.SIGKILL if force else signal.SIGTERM)
            except OSError:
                pass
        force = True
        time.sleep(0.2)


def _close_startup_windows(browser, keep_tab_id=""):
    """Drop the blank window created at launch. Worker windows stay open."""
    try:
        payload = browser._run_cdp("Target.getTargets")
    except Exception:
        return
    pages = [info for info in (payload or {}).get("targetInfos") or [] if info.get("type") == "page"]
    if len(pages) < 2:
        return
    for info in pages:
        if info.get("type") != "page":
            continue
        target_id = str(info.get("targetId") or "")
        if not target_id or target_id == keep_tab_id or info.get("browserContextId"):
            continue
        try:
            browser._run_cdp("Target.closeTarget", targetId=target_id)
        except Exception:
            pass


def get_shared_browser(log_callback=None, browser_proxy=""):
    with _shared_lock:
        browser_path, requested_choice = resolve_browser_executable()
        if not browser_path:
            raise RuntimeError("没有找到可自动操作的 Chromium 浏览器，请安装 Chrome、Edge、Brave 或 Chromium。")
        port = browser_debug_port()
        signature = (browser_path, port, str(browser_proxy or "").strip())
        browser = _shared_browser.get("browser")
        if _browser_alive(browser) and _shared_browser.get("signature") == signature:
            return browser
        if browser is not None:
            shutdown_shared_browser()
        _stop_owned_debug_browser(port)
        if _port_open(port):
            raise RuntimeError("浏览器调试端口 %s 已被其他程序占用，请更换端口。" % port)
        options = create_browser_options(browser_proxy=browser_proxy)
        browser = Chromium(options)
        _shared_browser["browser"] = browser
        _shared_browser["signature"] = signature
        if log_callback:
            name = browser_display_name(browser_path)
            requested = next(
                (item for item in list_installed_browsers() if item["id"] == requested_choice),
                None,
            )
            fallback = "" if requested and requested["path"] == browser_path else "（已自动选择可用浏览器）"
            log_callback("[*] 已启动 %s%s 无痕模式，调试端口 %s" % (name, fallback, port))
        return browser


def open_private_window(browser, url=""):
    with _shared_lock:
        page = browser.new_tab(url=None, new_window=True, new_context=True)
        context_id = ""
        try:
            info = browser._run_cdp("Target.getTargetInfo", targetId=page.tab_id)
            context_id = str((info.get("targetInfo") or {}).get("browserContextId") or "")
        except Exception:
            context_id = ""
        try:
            page._grok_context_id = context_id
        except Exception:
            pass
        try:
            info = browser._run_cdp("Browser.getWindowForTarget", targetId=page.tab_id)
            browser._run_cdp(
                "Browser.setWindowBounds",
                windowId=info["windowId"],
                bounds={"left": 80, "top": 40, "width": 1100, "height": 820, "windowState": "normal"},
            )
        except Exception:
            pass
        _close_startup_windows(browser, keep_tab_id=str(getattr(page, "tab_id", "") or ""))
        if url:
            try:
                page.get(url)
            except Exception:
                pass
        return page, context_id


def close_private_window(browser, page=None, context_id=""):
    context_id = str(context_id or getattr(page, "_grok_context_id", "") or "")
    with _shared_lock:
        if context_id:
            try:
                browser._run_cdp("Target.disposeBrowserContext", browserContextId=context_id)
                return
            except Exception:
                pass
        tab_id = getattr(page, "tab_id", None)
        if tab_id:
            try:
                browser._run_cdp("Target.closeTarget", targetId=tab_id)
            except Exception:
                pass


def cookies_for_context(browser, context_id):
    """Read cookies for one private window. Browser-level reads see the anchor profile."""
    if browser is None or not context_id:
        return []
    with _shared_lock:
        payload = browser._run_cdp("Storage.getCookies", browserContextId=str(context_id))
    return list((payload or {}).get("cookies") or [])


def is_shared_browser(browser):
    with _shared_lock:
        return browser is not None and browser is _shared_browser.get("browser")


def shutdown_shared_browser():
    with _shared_lock:
        browser = _shared_browser.get("browser")
        _shared_browser["browser"] = None
    if browser is None:
        return
    try:
        browser.quit(timeout=3, force=True)
    except Exception:
        pass


def _build_request_kwargs(**kwargs):
    request_kwargs = dict(kwargs)
    proxies = request_kwargs.pop("proxies", None)
    if proxies is None:
        proxies = get_proxies()
    if proxies:
        request_kwargs["proxies"] = proxies
    request_kwargs.setdefault("timeout", 15)
    return request_kwargs


def http_get(url, **kwargs):
    request_kwargs = _build_request_kwargs(**kwargs)
    try:
        return requests.get(url, **request_kwargs)
    except Exception as exc:
        if is_proxy_connection_error(exc):
            if managed_proxy_active():
                raise ProxyTransportError(safe_proxy_error_text(exc)) from exc
            direct = dict(request_kwargs)
            direct.pop("proxies", None)
            return requests.get(url, **direct)
        raise


def http_post(url, **kwargs):
    replay_safe = bool(kwargs.pop("replay_safe", False))
    request_kwargs = _build_request_kwargs(**kwargs)
    try:
        return requests.post(url, **request_kwargs)
    except Exception as exc:
        if is_proxy_connection_error(exc):
            if managed_proxy_active() or not replay_safe:
                raise ProxyTransportError(safe_proxy_error_text(exc)) from exc
            direct = dict(request_kwargs)
            direct.pop("proxies", None)
            return requests.post(url, **direct)
        raise
