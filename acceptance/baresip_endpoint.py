from __future__ import annotations

import asyncio
import json
import os
import socket
import urllib.request
from pathlib import Path
from typing import Any


class BaresipEndpoint:
    def __init__(
        self,
        executable: Path,
        source: Path,
        library_paths: tuple[Path, ...],
        log_path: Path,
        ice_server: str | None = None,
        ice_username: str | None = None,
        ice_password: str | None = None,
    ) -> None:
        self._executable = executable
        self._source = source
        self._library_paths = library_paths
        self._log_path = log_path
        self._ice_server = ice_server
        self._ice_username = ice_username
        self._ice_password = ice_password
        self._process: asyncio.subprocess.Process | None = None
        self._log_task: asyncio.Task[None] | None = None
        self._session_id: str | None = None

    async def start(self, timeout: float = 15.0) -> None:
        env = os.environ.copy()
        existing = env.get("LD_LIBRARY_PATH", "")
        paths = [str(path) for path in self._library_paths]
        if existing:
            paths.append(existing)
        env["LD_LIBRARY_PATH"] = ":".join(paths)
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        ice_arguments = ["-i", self._ice_server or "null"]
        if self._ice_username is not None:
            ice_arguments.extend(("-u", self._ice_username))
        if self._ice_password is not None:
            ice_arguments.extend(("-p", self._ice_password))
        self._process = await asyncio.create_subprocess_exec(
            str(self._executable),
            "-v",
            *ice_arguments,
            "-w",
            str(self._source / "webrtc" / "www"),
            cwd=self._log_path.parent,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        self._log_task = asyncio.create_task(self._capture_log())
        try:
            await asyncio.wait_for(self._wait_ready(), timeout)
        except BaseException:
            await self.close()
            raise

    async def _wait_ready(self) -> None:
        while True:
            self._check_process()
            try:
                connection = await asyncio.to_thread(
                    socket.create_connection, ("127.0.0.1", 9000), 0.2
                )
            except OSError:
                await asyncio.sleep(0.05)
                continue
            connection.close()
            return

    async def _capture_log(self) -> None:
        assert self._process is not None
        assert self._process.stdout is not None
        with self._log_path.open("wb") as output:
            while line := await self._process.stdout.readline():
                output.write(line)
                output.flush()

    @staticmethod
    def _request(
        method: str,
        path: str,
        body: dict[str, str] | None = None,
        session_id: str | None = None,
    ) -> tuple[dict[str, str], bytes]:
        headers = {}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if session_id is not None:
            headers["Session-ID"] = session_id
        request = urllib.request.Request(
            f"http://127.0.0.1:9000{path}",
            data=data,
            headers=headers,
            method=method,
        )
        with urllib.request.urlopen(request, timeout=30.0) as response:
            return dict(response.headers), response.read()

    def _check_process(self) -> None:
        if self._process is None:
            raise RuntimeError("baresip endpoint is not started")
        if self._process.returncode is not None:
            raise RuntimeError(
                f"baresip endpoint exited with {self._process.returncode}"
            )

    async def answer(
        self,
        offer: dict[str, str],
        *,
        media: bool,
        audio_only: bool = False,
    ) -> dict[str, str]:
        session_id, answer = await self.answer_session(
            offer, media=media, audio_only=audio_only
        )
        self._session_id = session_id
        return answer

    async def answer_session(
        self,
        offer: dict[str, str],
        *,
        media: bool,
        audio_only: bool = False,
    ) -> tuple[str, dict[str, str]]:
        self._check_process()
        route = (
            "/connect/offerer/audiodata"
            if audio_only
            else "/connect/offerer/avdata"
            if media
            else "/connect/offerer/data"
        )
        headers, _ = await asyncio.to_thread(
            self._request, "POST", route
        )
        session_id = headers.get("Session-ID")
        if not session_id:
            raise RuntimeError("baresip signaling response lacks Session-ID")
        _, body = await asyncio.to_thread(
            self._request, "PUT", "/sdp", offer, session_id
        )
        self._check_process()
        answer = json.loads(body)
        if answer.get("type") != "answer" or not answer.get("sdp"):
            raise RuntimeError("baresip returned an invalid SDP answer")
        return session_id, answer

    async def offer(
        self, *, media: bool, audio_only: bool = False
    ) -> dict[str, str]:
        self._check_process()
        route = (
            "/connect/audiodata"
            if audio_only
            else "/connect/avdata"
            if media
            else "/connect/data"
        )
        headers, body = await asyncio.to_thread(
            self._request, "POST", route
        )
        self._session_id = headers.get("Session-ID")
        if not self._session_id:
            raise RuntimeError("baresip signaling response lacks Session-ID")
        offer = json.loads(body)
        if offer.get("type") != "offer" or not offer.get("sdp"):
            raise RuntimeError("baresip returned an invalid SDP offer")
        return offer

    async def set_answer(self, answer: dict[str, str]) -> None:
        if self._session_id is None:
            raise RuntimeError("baresip has no active signaling session")
        await asyncio.to_thread(
            self._request, "PUT", "/sdp", answer, self._session_id
        )
        self._check_process()

    async def create_datachannel(self, label: str) -> None:
        if self._session_id is None:
            raise RuntimeError("baresip has no active signaling session")
        await asyncio.to_thread(
            self._request,
            "POST",
            "/datachannel",
            {"label": label},
            self._session_id,
        )
        self._check_process()

    async def delete_session(self) -> None:
        if self._session_id is None:
            return
        session_id, self._session_id = self._session_id, None
        await self.delete_session_id(session_id)

    async def delete_session_id(self, session_id: str) -> None:
        await asyncio.to_thread(
            self._request, "DELETE", "/connect", None, session_id
        )

    async def close(self) -> None:
        try:
            await self.delete_session()
        except Exception:
            pass
        if self._process is not None and self._process.returncode is None:
            self._process.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), 5.0)
            except asyncio.TimeoutError:
                self._process.kill()
                await self._process.wait()
        if self._log_task is not None:
            await self._log_task
        self._log_task = None
        self._process = None
