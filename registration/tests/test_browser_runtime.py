from __future__ import annotations

import os
import pathlib
import sys
import unittest
from unittest.mock import patch


ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import browser_runtime  # noqa: E402


class DockerBrowserSelectionTests(unittest.TestCase):
    def test_environment_force_selects_bundled_chromium(self):
        original_config = dict(browser_runtime._config)
        original_roots = browser_runtime._browser_roots_override
        browser_runtime.configure_runtime({"browser_choice": "microsoft-edge"})
        browser_runtime._browser_roots_override = []

        def which(command: str) -> str | None:
            return "/usr/bin/chromium-browser" if command == "chromium" else None

        try:
            with patch.dict(
                os.environ,
                {"GROK2API_REGISTRATION_BROWSER": "chromium"},
                clear=False,
            ):
                with patch.object(browser_runtime.shutil, "which", side_effect=which):
                    installed = browser_runtime.list_installed_browsers()
                    executable, fallback = browser_runtime.resolve_browser_executable()
        finally:
            browser_runtime._config = original_config
            browser_runtime._browser_roots_override = original_roots

        self.assertEqual([item["id"] for item in installed], ["chromium"])
        self.assertEqual(executable, "/usr/bin/chromium-browser")
        self.assertEqual(fallback, "")
        self.assertEqual(
            browser_runtime.browser_display_name(executable),
            "Chromium",
        )


if __name__ == "__main__":
    unittest.main()
