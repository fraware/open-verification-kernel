"""Smoke-test the no-backend site without relying on local network access.

Requires Python playwright and an installed Chromium executable. This is a
local/optional test; the static UI itself has no Python or browser dependency.
"""
from pathlib import Path
import os
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]


def setup(page):
    page.set_content((ROOT / "index.html").read_text(), wait_until="load")
    page.add_style_tag(content=(ROOT / "assets/styles.css").read_text())
    page.add_script_tag(content=(ROOT / "assets/catalog.js").read_text())
    page.add_script_tag(content=(ROOT / "assets/app.js").read_text())


def main():
    with sync_playwright() as p:
        executable = os.environ.get("OVK_SITE_CHROMIUM", "/usr/bin/chromium")
        kwargs = {"executable_path": executable} if Path(executable).exists() else {}
        browser = p.chromium.launch(headless=True, args=["--no-sandbox"], **kwargs)
        errors = []
        desktop = browser.new_page(viewport={"width": 1440, "height": 900})
        desktop.on("pageerror", lambda e: errors.append(str(e)))
        setup(desktop)
        assert desktop.locator("#totalCount").inner_text() == "51"
        assert desktop.locator(".resource-card").count() == 12
        desktop.locator("#resourceSearch").fill("source binding")
        assert desktop.locator("#quickResults").is_visible()
        assert desktop.locator("#quickResults .quick-link").count() >= 1
        titles = desktop.locator(".resource-card h3").all_text_contents()
        assert "PR source binding" in titles
        assert "Source-scoped PR report" in titles
        assert "Development draft" in desktop.locator(".resource-card").first.inner_text()
        desktop.locator("#resourceSearch").fill("wordthatexistsnowhere")
        assert desktop.locator("#emptyState").is_visible()
        desktop.locator("#resetAll").click()
        assert desktop.locator("#resourceSearch").input_value() == ""
        desktop.keyboard.press("Control+k")
        assert desktop.locator("#resourceSearch").evaluate("el => document.activeElement === el")
        desktop.keyboard.type("FastAPI")
        assert desktop.locator(".resource-card").count() >= 1
        desktop.keyboard.press("Escape")
        assert desktop.locator("#resourceSearch").input_value() == ""
        desktop.locator("#copyCode").click()
        assert desktop.locator("#copyLabel").inner_text() in ("Copied", "Select code")

        mobile = browser.new_page(viewport={"width": 390, "height": 844})
        mobile.on("pageerror", lambda e: errors.append(str(e)))
        setup(mobile)
        mobile.locator("#menuToggle").click()
        assert mobile.locator("#mobileNav").is_visible()
        mobile.locator('#mobileNav a[href="#explore"]').click()
        assert not mobile.locator("#mobileNav").is_visible()
        mobile.locator("#resourceSearch").fill("ci secrets")
        assert mobile.locator(".resource-card").count() >= 1
        assert mobile.evaluate("document.documentElement.scrollWidth - innerWidth") <= 0
        assert not errors, errors
        browser.close()
    print("PASS — desktop/mobile layout, search, accessible navigation, JS execution")


if __name__ == "__main__":
    main()
