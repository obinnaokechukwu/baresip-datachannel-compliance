from __future__ import annotations

import asyncio
import shutil
from pathlib import Path
from typing import Any

from playwright.async_api import Browser, Page, Playwright, async_playwright


class BrowserEndpoint:
    def __init__(self, profile: Path, engine: str) -> None:
        self._profile = profile
        self._engine = engine
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None
        self._page: Page | None = None

    async def start(
        self, *, media: bool, audio_only: bool = False
    ) -> None:
        self._profile.mkdir(parents=True, exist_ok=True)
        self._playwright = await async_playwright().start()
        if self._engine == "chromium":
            executable = (
                shutil.which("google-chrome")
                or shutil.which("chromium")
                or shutil.which("chromium-browser")
            )
            if executable is None:
                raise RuntimeError("stable Chromium executable not found")
            self._browser = await self._playwright.chromium.launch(
                executable_path=executable,
                headless=True,
                args=[
                    "--autoplay-policy=no-user-gesture-required",
                    "--use-fake-device-for-media-stream",
                    "--disable-dev-shm-usage",
                    "--no-sandbox",
                ],
            )
        elif self._engine == "firefox":
            self._browser = await self._playwright.firefox.launch(
                headless=True,
                firefox_user_prefs={
                    "media.autoplay.default": 0,
                    "media.navigator.streams.fake": True,
                },
            )
        else:
            raise ValueError(f"unknown browser engine {self._engine!r}")
        self._page = await self._browser.new_page()
        page = Path(__file__).parent / "web" / "endpoint.html"
        await self._page.goto(page.as_uri())
        await self._page.evaluate(
            "config => window.endpoint.start(config)",
            {"media": media, "audioOnly": audio_only},
        )

    def _require_page(self) -> Page:
        if self._page is None:
            raise RuntimeError(f"{self._engine} endpoint is not started")
        return self._page

    async def create_channel(self, label: str) -> dict[str, Any]:
        return await self._require_page().evaluate(
            "config => window.endpoint.createChannel(config)",
            {"label": label, "ordered": True},
        )

    async def create_offer(self) -> dict[str, str]:
        return await self._require_page().evaluate(
            "() => window.endpoint.createOffer()"
        )

    async def set_remote_description(self, description: dict[str, str]) -> None:
        await self._require_page().evaluate(
            "description => window.endpoint.setRemoteDescription(description)",
            description,
        )

    async def send(self, label: str, message_type: str, payload: bytes) -> None:
        await self._require_page().evaluate(
            "args => window.endpoint.send(args.label, args.type, args.payloadHex)",
            {
                "label": label,
                "type": message_type,
                "payloadHex": payload.hex(),
            },
        )

    async def events(self) -> list[dict[str, Any]]:
        return await self._require_page().evaluate(
            "() => window.endpoint.drainEvents()"
        )

    async def wait_channel_open(self, label: str, timeout: float = 15.0) -> None:
        deadline = asyncio.get_running_loop().time() + timeout
        while asyncio.get_running_loop().time() < deadline:
            state = await self._require_page().evaluate(
                "label => { const c = window.endpoint && "
                "window.endpoint.stats ? undefined : undefined; "
                "return null; }",
                label,
            )
            del state
            events = await self.events()
            if any(
                event["name"] == "channel"
                and event["body"].get("label") == label
                and event["body"].get("state") == "open"
                for event in events
            ):
                return
            await asyncio.sleep(0.05)
        raise TimeoutError(f"{self._engine} channel {label!r} did not open")

    async def stats(self) -> dict[str, Any]:
        return await self._require_page().evaluate(
            "() => window.endpoint.stats()"
        )

    async def close(self) -> None:
        if self._page is not None:
            try:
                await self._page.evaluate("() => window.endpoint.close()")
            except Exception:
                pass
        if self._browser is not None:
            await self._browser.close()
        if self._playwright is not None:
            await self._playwright.stop()
        self._page = None
        self._browser = None
        self._playwright = None


class ChromiumEndpoint(BrowserEndpoint):
    def __init__(self, profile: Path) -> None:
        super().__init__(profile, "chromium")


class FirefoxEndpoint(BrowserEndpoint):
    def __init__(self, profile: Path) -> None:
        super().__init__(profile, "firefox")
