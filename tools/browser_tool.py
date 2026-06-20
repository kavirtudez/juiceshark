"""
Browser Tool — JuiceShark
Playwright-based headless browser for JavaScript-rendered pages,
DOM XSS testing, and SPA interaction.
"""

from __future__ import annotations

import json
import re
from typing import Optional


class BrowserTool:
    """Headless browser using Playwright sync API."""

    def execute(self, args: dict) -> str:
        url         = args.get("url", "")
        wait_for    = args.get("wait_for", "networkidle")
        execute_js  = args.get("execute_js", "")
        click_sel   = args.get("click", "")
        screenshot  = args.get("screenshot", False)

        if not url:
            return "ERROR: No URL provided"

        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return "ERROR: Playwright not installed. Run: pip install playwright && playwright install chromium"

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    ignore_https_errors=True,
                )
                page = context.new_page()

                # Capture console messages and alerts
                console_msgs: list[str] = []
                alerts: list[str] = []
                page.on("console", lambda msg: console_msgs.append(f"[{msg.type}] {msg.text}"))
                page.on("dialog", lambda d: (alerts.append(d.message), d.dismiss()))

                page.goto(url, wait_until="domcontentloaded", timeout=20000)

                if wait_for == "networkidle":
                    try:
                        page.wait_for_load_state("networkidle", timeout=5000)
                    except Exception:
                        pass  # Don't fail if networkidle takes too long
                elif wait_for:
                    try:
                        page.wait_for_selector(wait_for, timeout=5000)
                    except Exception:
                        pass

                # Click element if requested
                if click_sel:
                    try:
                        page.click(click_sel, timeout=3000)
                        page.wait_for_timeout(500)
                    except Exception as e:
                        console_msgs.append(f"[click-error] {e}")

                # Execute JavaScript
                js_result = ""
                if execute_js:
                    try:
                        result = page.evaluate(execute_js)
                        js_result = str(result) if result is not None else ""
                    except Exception as e:
                        js_result = f"JS Error: {e}"

                # Get page content
                content = page.content()
                title   = page.title()
                current_url = page.url

                # Screenshot
                screenshot_path = ""
                if screenshot:
                    screenshot_path = f"/tmp/juiceshark_screenshot.png"
                    page.screenshot(path=screenshot_path, full_page=True)

                browser.close()

                # Build output
                lines = [
                    f"URL: {current_url}",
                    f"TITLE: {title}",
                    f"CONTENT_LENGTH: {len(content)} chars",
                ]

                if alerts:
                    lines.append(f"\nALERTS TRIGGERED: {json.dumps(alerts)}")
                    lines.append("*** XSS DETECTED: JavaScript alert() was triggered! ***")

                if console_msgs:
                    lines.append(f"\nCONSOLE ({len(console_msgs)} messages):")
                    for msg in console_msgs[:20]:  # first 20
                        lines.append(f"  {msg}")

                if js_result:
                    lines.append(f"\nJS RESULT:\n{js_result[:2000]}")

                # Strip <style>/<script> blocks (Juice Shop's admin page is ~185K
                # chars, mostly inlined font-awesome CSS) so the snippet we hand
                # back to the LLM is meaningful content, not noise that bloats the
                # next request and causes timeouts.
                cleaned = re.sub(r"(?is)<(style|script)[^>]*>.*?</\1>", " ", content)
                cleaned = re.sub(r"(?s)<[^>]+>", " ", cleaned)   # drop tags
                cleaned = re.sub(r"\s+", " ", cleaned).strip()
                lines.append(f"\nPAGE TEXT (first 2000 chars, tags/CSS stripped):\n{cleaned[:2000]}")

                if screenshot_path:
                    lines.append(f"\nSCREENSHOT: {screenshot_path}")

                return "\n".join(lines)

        except Exception as e:
            return f"ERROR: Browser execution failed: {e}"
