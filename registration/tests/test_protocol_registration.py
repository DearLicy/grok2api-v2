from __future__ import annotations

import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from protocol_registration import (  # noqa: E402
    GrpcResponse,
    ProtocolRegistrar,
    classify_create_response,
    decode_session_cookie,
    encode_bytes_field,
    encode_create_user_request,
    encode_grpc_frame,
    encode_string_field,
    parse_grpc_web_frames,
)
from registration_runtime import ProtocolOutcomeUncertain  # noqa: E402


def v2_response(token: str) -> bytes:
    session = encode_string_field(2, token)
    message = encode_bytes_field(1, session)
    return encode_grpc_frame(message)


class FakeResponse:
    def __init__(self, status_code: int, content: bytes, headers=None):
        self.status_code = status_code
        self.content = content
        self.headers = headers or {}
        self.text = content.decode("utf-8", "replace")


class FakeSession:
    def __init__(self, response):
        self.response = response
        self.headers = {}
        self.calls = []
        self.closed = False

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.response

    def close(self):
        self.closed = True


class ProtocolEncodingTests(unittest.TestCase):
    def test_create_request_frame_contains_required_fields(self):
        frame = encode_create_user_request(
            "person@example.com",
            "Alex",
            "Chen",
            "secret-password",
            "ABC-123",
            "turnstile-token",
        )

        self.assertEqual(frame[0], 0)
        length = int.from_bytes(frame[1:5], "big")
        self.assertEqual(length, len(frame) - 5)
        self.assertIn(b"person@example.com", frame)
        self.assertIn(b"clear", b"clear")
        self.assertIn(b"secret-password", frame)
        self.assertIn(b"ABC-123", frame)
        self.assertIn(b"turnstile-token", frame)

    def test_parses_binary_and_trailer_frames(self):
        data = encode_grpc_frame(b"payload")
        trailer = b"grpc-status: 0\r\ngrpc-message: ok\r\n"
        body = data + b"\x80" + len(trailer).to_bytes(4, "big") + trailer

        payload, metadata = parse_grpc_web_frames(body)

        self.assertEqual(payload, b"payload")
        self.assertEqual(metadata["grpc-status"], "0")
        self.assertEqual(metadata["grpc-message"], "ok")

    def test_decodes_v2_session_cookie(self):
        self.assertEqual(decode_session_cookie(v2_response("sso-token"), v2=True), "sso-token")

    def test_detects_existing_email_response(self):
        response = GrpcResponse(200, encode_grpc_frame(encode_string_field(2, "existing")))
        result, detail = classify_create_response(response, v2=True)
        self.assertEqual(result, "fallback")
        self.assertIn("邮箱已存在", detail)


class ProtocolClassificationTests(unittest.TestCase):
    def test_v2_success_requires_grpc_status_zero_or_absent(self):
        success = GrpcResponse(200, v2_response("sso-token"))
        result, detail = classify_create_response(success, v2=True)
        self.assertEqual((result, detail), ("success", "sso-token"))

        trailer = b"grpc-status: 13\r\ngrpc-message: internal\r\n"
        failed = GrpcResponse(
            200,
            b"\x80" + len(trailer).to_bytes(4, "big") + trailer,
        )
        result, _ = classify_create_response(failed, v2=True)
        self.assertEqual(result, "uncertain")

        rejected_trailer = b"grpc-status: 7\r\ngrpc-message: permission denied\r\n"
        rejected = GrpcResponse(
            200,
            b"\x80" + len(rejected_trailer).to_bytes(4, "big") + rejected_trailer,
        )
        result, _ = classify_create_response(rejected, v2=True)
        self.assertEqual(result, "fallback")

    def test_cloudflare_and_turnstile_are_safe_fallbacks(self):
        cloudflare = GrpcResponse(403, b"<html>Cloudflare you have been blocked</html>")
        turnstile = GrpcResponse(403, b"Turnstile verification failed")
        self.assertEqual(classify_create_response(cloudflare)[0], "fallback")
        self.assertEqual(classify_create_response(turnstile)[0], "fallback")

    def test_http_5xx_after_submit_is_uncertain(self):
        response = GrpcResponse(503, b"upstream unavailable")
        result, detail = classify_create_response(response)
        self.assertEqual(result, "uncertain")
        self.assertIn("HTTP 503", detail)

    def test_ambiguous_2xx_is_uncertain(self):
        response = GrpcResponse(200, encode_grpc_frame(b""))
        result, _ = classify_create_response(response)
        self.assertEqual(result, "uncertain")

    def test_unimplemented_v2_allows_single_v1_attempt(self):
        trailer = b"grpc-status: 12\r\ngrpc-message: UNIMPLEMENTED\r\n"
        response = GrpcResponse(
            200,
            b"\x80" + len(trailer).to_bytes(4, "big") + trailer,
        )
        result, _ = classify_create_response(response, v2=True)
        self.assertEqual(result, "unimplemented")

    def test_uncertain_create_is_never_replayed_to_v1(self):
        fake = FakeSession(FakeResponse(500, b"upstream failed"))
        registrar = ProtocolRegistrar(
            {"turnstile_solver_kind": "none"},
            log=lambda _message: None,
            cancelled=lambda: False,
            get_email_and_token=lambda: ("person@example.com", "mail-token"),
            get_oai_code=lambda *_args, **_kwargs: "ABC-123",
            build_profile=lambda: ("Alex", "Chen", "password"),
            enable_nsfw=lambda _sso: (True, "ok"),
            stage=lambda _stage: None,
            session_factory=lambda _config: fake,
        )

        with self.assertRaises(ProtocolOutcomeUncertain):
            registrar._submit_create(b"request", 5)

        self.assertEqual(len(fake.calls), 1)
        self.assertIn("CreateUserAndSessionV2", fake.calls[0][0])


if __name__ == "__main__":
    unittest.main()
