"""Protocol-first xAI registration over gRPC-Web.

The module deliberately keeps protobuf and response classification pure so the
safety rules can be tested without a browser, proxy, or live xAI request.
"""
from __future__ import annotations

import json
import re
import secrets
import struct
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Sequence, Tuple

from registration_runtime import (
    AccountRetryNeeded,
    ProtocolFallback,
    ProtocolOutcomeUncertain,
    raise_if_cancelled,
    sleep_with_cancel,
)


DEFAULT_TURNSTILE_SITEKEY = "0x4AAAAAAAhr9JGVDZbrZOo0"
DEFAULT_SIGNUP_URL = "https://accounts.x.ai/sign-up?redirect=grok-com"
ACCOUNTS_ORIGIN = "https://accounts.x.ai"
GRPC_BASE_URL = (
    "https://accounts.x.ai/auth_mgmt.AuthManagement/"
)
CREATE_EMAIL_CODE_URL = GRPC_BASE_URL + "CreateEmailValidationCode"
VERIFY_EMAIL_CODE_URL = GRPC_BASE_URL + "VerifyEmailValidationCode"
CREATE_USER_V2_URL = GRPC_BASE_URL + "CreateUserAndSessionV2"
CREATE_USER_V1_URL = GRPC_BASE_URL + "CreateUserAndSession"
CAPSOLVER_CREATE_URL = "https://api.capsolver.com/createTask"
CAPSOLVER_RESULT_URL = "https://api.capsolver.com/getTaskResult"

_CHALLENGE_MARKERS = (
    "you have been blocked",
    "cloudflare",
    "cf-error",
    "__cf_chl",
    "challenge-platform",
    "just a moment",
    "attention required",
)
_TURNSTILE_MARKERS = (
    "turnstile",
    "anti-abuse",
    "anti abuse",
    "captcha",
    "verification failed",
    "request could not be verified",
)
_EXPLICIT_REJECTION_MARKERS = (
    "already exists",
    "duplicate email",
    "email already",
    "invalid email validation code",
    "invalid validation code",
    "verification code expired",
    "code expired",
    "permission denied",
    "invalid argument",
    "unauthenticated",
    "邮箱已存在",
    "验证码",
)
_UNCERTAIN_GRPC_CODES = {1, 2, 4, 8, 10, 13, 14, 15}
_EXPLICIT_GRPC_CODES = {3, 5, 6, 7, 9, 11, 12, 16}
_JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
)


def encode_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("varint cannot encode a negative value")
    output = bytearray()
    while value >= 0x80:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value & 0x7F)
    return bytes(output)


def encode_tag(field_number: int, wire_type: int) -> bytes:
    if field_number <= 0:
        raise ValueError("protobuf field number must be positive")
    return encode_varint((field_number << 3) | wire_type)


def encode_string_field(field_number: int, value: str) -> bytes:
    data = str(value or "").encode("utf-8")
    return encode_tag(field_number, 2) + encode_varint(len(data)) + data


def encode_bytes_field(field_number: int, value: bytes) -> bytes:
    return encode_tag(field_number, 2) + encode_varint(len(value)) + bytes(value)


def encode_varint_field(field_number: int, value: int) -> bytes:
    return encode_tag(field_number, 0) + encode_varint(int(value))


def encode_bool_field(field_number: int, value: bool) -> bytes:
    return encode_varint_field(field_number, 1 if value else 0)


def encode_grpc_frame(payload: bytes) -> bytes:
    return b"\x00" + struct.pack(">I", len(payload)) + payload


def encode_email_validation_request(email: str) -> bytes:
    return encode_grpc_frame(encode_string_field(1, email))


def encode_verify_email_request(email: str, code: str) -> bytes:
    payload = encode_string_field(1, email) + encode_string_field(2, code)
    return encode_grpc_frame(payload)


def encode_create_user_request(
    email: str,
    given_name: str,
    family_name: str,
    password: str,
    validation_code: str,
    turnstile_token: str = "",
) -> bytes:
    create_user = b"".join(
        (
            encode_string_field(1, given_name),
            encode_string_field(2, family_name),
            encode_string_field(3, email),
            encode_string_field(5, password),
        )
    )
    payload = bytearray(encode_bytes_field(1, create_user))
    if turnstile_token:
        anti_abuse = encode_string_field(1, turnstile_token)
        payload.extend(encode_bytes_field(6, anti_abuse))
    payload.extend(encode_string_field(9, validation_code))
    payload.extend(encode_bool_field(10, True))
    return encode_grpc_frame(bytes(payload))


def decode_varint(data: bytes, offset: int = 0) -> Tuple[int, int]:
    value = 0
    shift = 0
    for index in range(offset, len(data)):
        current = data[index]
        value |= (current & 0x7F) << shift
        if not current & 0x80:
            return value, index + 1
        shift += 7
        if shift >= 70:
            break
    raise ValueError("invalid protobuf varint")


def iter_protobuf_fields(data: bytes) -> Iterable[Tuple[int, int, Any]]:
    offset = 0
    while offset < len(data):
        tag, offset = decode_varint(data, offset)
        field_number = tag >> 3
        wire_type = tag & 0x07
        if wire_type == 0:
            value, offset = decode_varint(data, offset)
            yield field_number, wire_type, value
        elif wire_type == 1:
            end = offset + 8
            if end > len(data):
                raise ValueError("truncated fixed64 field")
            yield field_number, wire_type, data[offset:end]
            offset = end
        elif wire_type == 2:
            length, offset = decode_varint(data, offset)
            end = offset + length
            if end > len(data):
                raise ValueError("truncated length-delimited field")
            yield field_number, wire_type, data[offset:end]
            offset = end
        elif wire_type == 5:
            end = offset + 4
            if end > len(data):
                raise ValueError("truncated fixed32 field")
            yield field_number, wire_type, data[offset:end]
            offset = end
        else:
            raise ValueError("unsupported protobuf wire type %s" % wire_type)


def extract_bytes_field(data: bytes, target_field: int) -> Optional[bytes]:
    for field_number, wire_type, value in iter_protobuf_fields(data):
        if field_number == target_field and wire_type == 2:
            return bytes(value)
    return None


def parse_grpc_web_frames(body: bytes) -> Tuple[bytes, Dict[str, str]]:
    """Return the first unary data payload and all gRPC trailer metadata."""
    payload = b""
    trailers: Dict[str, str] = {}
    offset = 0
    while offset + 5 <= len(body):
        flag = body[offset]
        length = struct.unpack(">I", body[offset + 1 : offset + 5])[0]
        start = offset + 5
        end = start + length
        if end > len(body):
            raise ValueError("gRPC-Web frame length exceeds response")
        frame = body[start:end]
        if flag & 0x80:
            for line in frame.decode("latin-1", "replace").splitlines():
                name, separator, value = line.partition(":")
                if separator:
                    trailers[name.strip().lower()] = value.strip()
        elif flag & 0x7F == 0 and not payload:
            payload = frame
        offset = end
    if offset != len(body):
        raise ValueError("trailing bytes after gRPC-Web frames")
    return payload, trailers


class GrpcResponse:
    def __init__(
        self,
        status: int,
        body: bytes,
        headers: Optional[Mapping[str, Any]] = None,
    ):
        self.status = int(status)
        self.body = bytes(body or b"")
        self.headers = {
            str(key).lower(): str(value)
            for key, value in dict(headers or {}).items()
        }
        try:
            self.payload, self.trailers = parse_grpc_web_frames(self.body)
        except ValueError:
            self.payload, self.trailers = b"", {}
        self.text = self.body.decode("utf-8", "replace")

    def metadata(self, name: str) -> str:
        key = name.lower()
        return self.trailers.get(key, self.headers.get(key, "")).strip()

    @property
    def grpc_status(self) -> Optional[int]:
        raw = self.metadata("grpc-status")
        if raw == "":
            return None
        try:
            return int(raw)
        except ValueError:
            return None

    @property
    def grpc_message(self) -> str:
        return urllib.parse.unquote(self.metadata("grpc-message")).strip()


def response_from_http(response: Any) -> GrpcResponse:
    headers = getattr(response, "headers", {}) or {}
    content = getattr(response, "content", None)
    if content is None:
        content = str(getattr(response, "text", "") or "").encode("utf-8")
    return GrpcResponse(int(getattr(response, "status_code", 0) or 0), content, headers)


def decode_session_cookie(body: bytes, v2: bool = True) -> str:
    payload, _ = parse_grpc_web_frames(body)
    if not payload:
        payload = body
    if v2:
        session_response = extract_bytes_field(payload, 1)
        if session_response is None:
            if extract_bytes_field(payload, 2) is not None:
                raise ValueError("邮箱已存在，服务端要求确认其他登录方式")
            raise ValueError("响应缺少 CreateSessionResponse")
        raw = extract_bytes_field(session_response, 2)
    else:
        raw = extract_bytes_field(payload, 2)
    if raw is None:
        raise ValueError("响应缺少 session_cookie")
    token = raw.decode("utf-8", "replace").strip()
    if token.lower().startswith("sso="):
        token = token[4:].strip()
    if not token:
        raise ValueError("session_cookie 为空")
    return token


def classify_http_rejection(status: int, text: str) -> str:
    lower = str(text or "").lower()
    if status in (403, 429, 503):
        if any(marker in lower for marker in _TURNSTILE_MARKERS):
            return "turnstile"
        if any(marker in lower for marker in _CHALLENGE_MARKERS):
            return "challenge"
        return "transient"
    if status in (400, 401, 409, 422):
        if any(marker in lower for marker in _TURNSTILE_MARKERS):
            return "turnstile"
        return "explicit"
    if 500 <= status <= 599:
        return "transient"
    return ""


def classify_create_response(response: GrpcResponse, v2: bool = True) -> Tuple[str, str]:
    """Classify a create response as success, fallback, uncertain, or unimplemented."""
    if response.status == 404 and (
        "unimplemented" in response.text.lower()
        or "unknown service" in response.text.lower()
        or "not found" in response.text.lower()
    ):
        return "unimplemented", "注册端点未实现"

    status_rejection = classify_http_rejection(response.status, response.text)
    if status_rejection in ("challenge", "turnstile"):
        return "fallback", status_rejection
    if status_rejection == "explicit":
        return "fallback", "服务端明确拒绝创建账号"
    if status_rejection == "transient":
        return "uncertain", "创建账号请求返回 HTTP %s" % response.status

    grpc_status = response.grpc_status
    if grpc_status not in (None, 0):
        detail = response.grpc_message or response.text[:300] or "gRPC status %s" % grpc_status
        if grpc_status == 12:
            return "unimplemented", detail
        if grpc_status in _UNCERTAIN_GRPC_CODES:
            return "uncertain", detail
        if grpc_status in _EXPLICIT_GRPC_CODES:
            return "fallback", detail
        return "uncertain", detail

    if not 200 <= response.status < 300:
        return "uncertain", "创建账号请求返回 HTTP %s" % response.status

    try:
        token = decode_session_cookie(response.body, v2=v2)
        if token:
            return "success", token
    except ValueError as exc:
        detail = str(exc)
        lower = (detail + "\n" + response.grpc_message).lower()
        if "邮箱已存在" in detail:
            return "fallback", detail
        if any(marker in lower for marker in _TURNSTILE_MARKERS):
            return "fallback", detail
        if any(marker in lower for marker in _EXPLICIT_REJECTION_MARKERS):
            return "fallback", detail

    # A 2xx response can be a server crash after committing the account. Replaying
    # this request could create a duplicate or consume an unusable validation code.
    return "uncertain", "创建账号响应成功但未返回 session_cookie"


def _response_text(response: Any) -> str:
    content = getattr(response, "content", None)
    if isinstance(content, bytes):
        return content.decode("utf-8", "replace")
    return str(getattr(response, "text", "") or "")


@dataclass
class ProtocolRegistrationResult:
    email: str
    password: str
    sso: str
    profile: Dict[str, Any] = field(default_factory=dict)
    mode: str = "protocol"


class ProtocolRegistrar:
    """Register one account with protocol calls, opening no browser directly."""

    def __init__(
        self,
        config: Mapping[str, Any],
        *,
        log: Callable[[str], None],
        cancelled: Callable[[], bool],
        get_email_and_token: Callable[[], Tuple[str, str]],
        get_oai_code: Callable[..., str],
        build_profile: Callable[[], Tuple[str, str, str]],
        enable_nsfw: Callable[[str], Tuple[bool, str]],
        stage: Callable[[str], Any],
        session_factory: Optional[Callable[[Mapping[str, Any]], Any]] = None,
    ):
        self.config = dict(config)
        self.log = log
        self.cancelled = cancelled
        self.get_email_and_token = get_email_and_token
        self.get_oai_code = get_oai_code
        self.build_profile = build_profile
        self.enable_nsfw = enable_nsfw
        self.stage = stage
        self.session_factory = session_factory or self._default_session_factory
        self.close_session: Optional[Callable[[], None]] = None
        self.session = self.session_factory(self.config)
        close = getattr(self.session, "close", None)
        if callable(close):
            self.close_session = close
        headers = getattr(self.session, "headers", None)
        if headers is not None:
            headers.update(
                {
                    "User-Agent": str(
                        self.config.get("user_agent")
                        or "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/138.0.0.0 Safari/537.36"
                    ),
                    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                }
            )

    def _default_session_factory(self, config: Mapping[str, Any]) -> Any:
        from curl_cffi import requests as curl_requests

        proxy_mode = str(config.get("proxy_mode") or "auto").lower()
        proxy = ""
        if proxy_mode not in ("direct", "single", "pool"):
            proxy = str(config.get("proxy") or "").strip()
        proxies = {"http": proxy, "https": proxy} if proxy else None
        return curl_requests.Session(impersonate="chrome", proxies=proxies)

    def close(self) -> None:
        if self.close_session is not None:
            try:
                self.close_session()
            except Exception:
                pass

    def _request_headers(self, referer: str = DEFAULT_SIGNUP_URL) -> Dict[str, str]:
        return {
            "Content-Type": "application/grpc-web+proto",
            "Accept": "application/grpc-web+proto",
            "X-Grpc-Web": "1",
            "X-User-Agent": "connect-es/2.1.1",
            "Origin": ACCOUNTS_ORIGIN,
            "Referer": referer,
        }

    def _warmup(self) -> None:
        raise_if_cancelled(self.cancelled)
        try:
            self.log("[*] 协议模式预热 accounts.x.ai 会话")
            self.session.get(DEFAULT_SIGNUP_URL, timeout=20)
        except Exception as exc:
            raise ProtocolFallback("协议会话预热失败: %s" % exc) from exc

    def _grpc_post(self, url: str, data: bytes, timeout: float) -> GrpcResponse:
        response = self.session.post(
            url,
            data=data,
            headers=self._request_headers(),
            timeout=max(1.0, float(timeout)),
        )
        return response_from_http(response)

    def _grpc_call(
        self,
        url: str,
        data: bytes,
        *,
        timeout: float,
        replay_safe: bool,
        label: str,
    ) -> GrpcResponse:
        raise_if_cancelled(self.cancelled)
        try:
            response = self._grpc_post(url, data, timeout)
        except Exception as exc:
            raise_if_cancelled(self.cancelled)
            if replay_safe:
                raise ProtocolFallback("%s网络请求失败: %s" % (label, exc)) from exc
            raise ProtocolOutcomeUncertain(
                "%s请求传输中断，无法确认服务端是否已创建账号: %s"
                % (label, exc)
            ) from exc

        rejection = classify_http_rejection(response.status, response.text)
        if rejection in ("challenge", "turnstile", "explicit"):
            raise ProtocolFallback("%s被明确拒绝: %s" % (label, rejection))
        if rejection == "transient":
            if replay_safe:
                raise ProtocolFallback("%s返回 HTTP %s" % (label, response.status))
            raise ProtocolOutcomeUncertain(
                "%s返回 HTTP %s，无法确认账号是否已创建"
                % (label, response.status)
            )
        if not 200 <= response.status < 300:
            raise ProtocolFallback("%s返回 HTTP %s" % (label, response.status))
        if response.grpc_status not in (None, 0):
            detail = response.grpc_message or "gRPC status %s" % response.grpc_status
            if response.grpc_status in _UNCERTAIN_GRPC_CODES and not replay_safe:
                raise ProtocolOutcomeUncertain(
                    "%s结果不确定: %s" % (label, detail)
                )
            raise ProtocolFallback("%s失败: %s" % (label, detail))
        return response

    def _send_validation_code(self, email: str, timeout: float) -> None:
        self.stage("email_submit")
        self.log("[*] 协议模式发送邮箱验证码")
        self._grpc_call(
            CREATE_EMAIL_CODE_URL,
            encode_email_validation_request(email),
            timeout=timeout,
            replay_safe=True,
            label="发送验证码",
        )
        self.log("[+] 协议模式验证码已发送")

    def _verify_validation_code(self, email: str, code: str, timeout: float) -> None:
        self.stage("code_submit")
        self.log("[*] 协议模式验证邮箱验证码")
        self._grpc_call(
            VERIFY_EMAIL_CODE_URL,
            encode_verify_email_request(email, code),
            timeout=timeout,
            replay_safe=True,
            label="验证邮箱验证码",
        )
        self.log("[+] 协议模式邮箱验证成功")

    def _solve_boterdrop(self, timeout: float) -> str:
        solver_url = str(self.config.get("boterdrop_url") or "").strip().rstrip("/")
        if not solver_url:
            return ""
        sitekey = str(
            self.config.get("turnstile_sitekey") or DEFAULT_TURNSTILE_SITEKEY
        ).strip()
        query = urllib.parse.urlencode(
            {"url": "https://accounts.x.ai/sign-up", "sitekey": sitekey}
        )
        self.log("[*] 尝试 Boterdrop 求解 Turnstile")
        response = self.session.get(
            solver_url + "/turnstile?" + query,
            timeout=min(15.0, timeout),
        )
        payload = response.json()
        token = str(payload.get("token") or payload.get("value") or "").strip()
        if token:
            return token
        task_id = str(payload.get("taskId") or payload.get("task_id") or "").strip()
        if not task_id:
            raise RuntimeError("Boterdrop 未返回 task id")
        deadline = time.time() + timeout
        while time.time() < deadline:
            raise_if_cancelled(self.cancelled)
            result = self.session.get(
                solver_url + "/result?" + urllib.parse.urlencode({"id": task_id}),
                timeout=min(15.0, max(1.0, deadline - time.time())),
            ).json()
            token = str(
                result.get("token") or result.get("value") or ""
            ).strip()
            if token:
                return token
            solution = result.get("solution")
            if isinstance(solution, dict):
                token = str(solution.get("token") or "").strip()
                if token:
                    return token
            status = str(result.get("status") or "").lower()
            if status in ("error", "failed", "captcha_fail"):
                raise RuntimeError(
                    "Boterdrop 求解失败: %s"
                    % (result.get("error") or result.get("message") or status)
                )
            sleep_with_cancel(1.5, self.cancelled)
        raise TimeoutError("Boterdrop 求解超时")

    def _solve_capsolver(self, timeout: float) -> str:
        api_key = str(self.config.get("capsolver_api_key") or "").strip()
        if not api_key:
            return ""
        sitekey = str(
            self.config.get("turnstile_sitekey") or DEFAULT_TURNSTILE_SITEKEY
        ).strip()
        self.log("[*] 尝试 Capsolver 求解 Turnstile")
        payload = {
            "clientKey": api_key,
            "task": {
                "type": "AntiTurnstileTaskProxyLess",
                "websiteURL": "https://accounts.x.ai/sign-up",
                "websiteKey": sitekey,
            },
        }
        created = self.session.post(
            CAPSOLVER_CREATE_URL,
            json=payload,
            timeout=min(30.0, timeout),
        ).json()
        task_id = str(created.get("taskId") or "").strip()
        if not task_id:
            raise RuntimeError(
                "Capsolver 创建任务失败: %s"
                % (created.get("errorDescription") or created.get("errorCode") or created)
            )
        deadline = time.time() + timeout
        while time.time() < deadline:
            raise_if_cancelled(self.cancelled)
            sleep_with_cancel(2.0, self.cancelled)
            result = self.session.post(
                CAPSOLVER_RESULT_URL,
                json={"clientKey": api_key, "taskId": task_id},
                timeout=min(30.0, max(1.0, deadline - time.time())),
            ).json()
            if str(result.get("status") or "").lower() == "ready":
                token = str((result.get("solution") or {}).get("token") or "").strip()
                if token:
                    return token
            status = str(result.get("status") or "").lower()
            if status in ("failed", "error"):
                raise RuntimeError(
                    "Capsolver 求解失败: %s"
                    % (result.get("errorDescription") or status)
                )
        raise TimeoutError("Capsolver 求解超时")

    def _solve_turnstile(self, timeout: float) -> str:
        kind = str(self.config.get("turnstile_solver_kind") or "auto").lower()
        if kind == "none":
            return ""
        providers = []
        if kind in ("auto", "boterdrop"):
            providers.append(("Boterdrop", self._solve_boterdrop))
        if kind in ("auto", "capsolver"):
            providers.append(("Capsolver", self._solve_capsolver))
        last_error = ""
        for name, solver in providers:
            try:
                token = solver(timeout)
                if token:
                    self.log("[+] %s Turnstile 求解成功" % name)
                    return token
            except Exception as exc:
                last_error = "%s: %s" % (name, exc)
                self.log("[!] %s Turnstile 求解未完成: %s" % (name, exc))
        if last_error:
            self.log("[!] Turnstile 求解器不可用，将尝试无 token 提交并允许浏览器回退")
        return ""

    def _submit_create(self, request: bytes, timeout: float) -> str:
        self.stage("profile_submit")
        self.log("[*] 协议模式提交账号创建；提交后不会自动重放")
        response = self._grpc_call(
            CREATE_USER_V2_URL,
            request,
            timeout=timeout,
            replay_safe=False,
            label="创建账号 V2",
        )
        outcome, detail = classify_create_response(response, v2=True)
        if outcome == "success":
            return detail
        if outcome == "unimplemented":
            self.log("[!] CreateUserAndSessionV2 未实现，改用 V1 单次提交")
            response = self._grpc_call(
                CREATE_USER_V1_URL,
                request,
                timeout=timeout,
                replay_safe=False,
                label="创建账号 V1",
            )
            outcome, detail = classify_create_response(response, v2=False)
            if outcome == "success":
                return detail
            if outcome == "fallback":
                raise ProtocolFallback("创建账号被服务端明确拒绝: %s" % detail)
            raise ProtocolOutcomeUncertain(
                "创建账号 V1 结果不确定: %s" % detail
            )
        if outcome == "fallback":
            raise ProtocolFallback("创建账号被服务端明确拒绝: %s" % detail)
        raise ProtocolOutcomeUncertain("创建账号结果不确定: %s" % detail)

    def register(self) -> ProtocolRegistrationResult:
        self._warmup()
        email, dev_token = self.get_email_and_token()
        if not email or not dev_token:
            raise ProtocolFallback("邮箱服务未返回完整临时邮箱凭据")
        given_name, family_name, password = self.build_profile()
        self.log("[*] 协议模式临时邮箱已创建: %s" % email)

        timeout = float(self.config.get("protocol_request_timeout_sec") or 35)
        self._send_validation_code(email, timeout)
        self.stage("code_wait")

        def resend() -> None:
            self._send_validation_code(email, timeout)

        try:
            code = self.get_oai_code(
                dev_token,
                email,
                log_callback=self.log,
                cancel_callback=self.cancelled,
                resend_callback=resend,
            )
        except Exception as exc:
            raise_if_cancelled(self.cancelled)
            raise ProtocolFallback("协议模式等待验证码失败: %s" % exc) from exc
        if not code:
            raise ProtocolFallback("协议模式没有取得邮箱验证码")

        self._verify_validation_code(email, str(code), timeout)
        solver_timeout = float(
            self.config.get("turnstile_solver_timeout_sec") or 90
        )
        turnstile_token = self._solve_turnstile(solver_timeout)
        request = encode_create_user_request(
            email=email,
            given_name=given_name,
            family_name=family_name,
            password=password,
            validation_code=str(code),
            turnstile_token=turnstile_token,
        )
        sso = self._submit_create(request, timeout)
        self.stage("account_confirmed")
        self.log("[+] 协议模式注册成功，已取得 SSO")

        if bool(self.config.get("enable_nsfw", True)):
            self.log("[*] 协议模式开启 NSFW")
            try:
                enabled, message = self.enable_nsfw(sso)
                if enabled:
                    self.log("[+] NSFW 开启成功: %s" % message)
                else:
                    self.log("[!] NSFW 未开启，继续保存账号: %s" % message)
            except Exception as exc:
                self.log("[!] NSFW 开启异常，继续保存账号: %s" % exc)

        return ProtocolRegistrationResult(
            email=email,
            password=password,
            sso=sso,
            profile={
                "given_name": given_name,
                "family_name": family_name,
                "password": password,
            },
        )

    def register_safely(self) -> ProtocolRegistrationResult:
        try:
            return self.register()
        finally:
            self.close()
