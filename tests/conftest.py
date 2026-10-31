"""Shared fixtures: a clean media guard per test, fake downloads, generated media."""
import io
import os
import shutil
import subprocess
import urllib.error

import pytest

# The real binaries, resolved before any guard wraps them.
REAL_FFMPEG = shutil.which("ffmpeg")
REAL_FFPROBE = shutil.which("ffprobe")
try:
    import imageio_ffmpeg

    REAL_IMAGEIO = imageio_ffmpeg.get_ffmpeg_exe()
except Exception:  # pragma: no cover
    REAL_IMAGEIO = REAL_FFMPEG

HAS_FFMPEG = REAL_FFMPEG is not None
needs_ffmpeg = pytest.mark.skipif(not HAS_FFMPEG, reason="ffmpeg not installed")

STORAGE = "https://vqzoyuvdarpfptuhhsws.supabase.co/storage/v1/object/public/test"
HLS_WITH_HTTP = b"#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:2\n#EXTINF:2.0,\nhttp://169.254.169.254/latest/meta-data/x.ts\n#EXT-X-ENDLIST\n"
FFCONCAT_PASSWD = b"ffconcat version 1.0\nfile '/etc/passwd'\n"


@pytest.fixture(autouse=True)
def clean_guard(tmp_path, monkeypatch):
    """Re-install the guard around the real binaries (other tests install fakes)."""
    import media_guard as mg

    monkeypatch.setenv("PATH", os.environ["PATH"])
    for k in ("FFMPEG_BINARY", "IMAGEIO_FFMPEG_EXE", "OPENCV_FFMPEG_CAPTURE_OPTIONS"):
        if k in os.environ:
            monkeypatch.setenv(k, os.environ[k])
    mg._state.clear()
    if HAS_FFMPEG:
        mg.install_ffmpeg_guard(real_ffmpeg=REAL_FFMPEG, real_ffprobe=REAL_FFPROBE,
                                real_imageio_ffmpeg=REAL_IMAGEIO, bin_dir=str(tmp_path / "guard-bin"))
    yield
    mg._state.clear()


class _Resp(io.BytesIO):
    def __init__(self, body):
        super().__init__(body)
        self.headers = {"Content-Length": str(len(body))}


class FakeWeb:
    """url -> bytes, or ("redirect", location). Records every URL opened."""

    def __init__(self):
        self.routes = {}
        self.opened = []
        self.resolve_to = "104.18.38.10"

    def open(self, req, timeout=None):
        url = req.full_url
        self.opened.append(url)
        if url not in self.routes:
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
        route = self.routes[url]
        if isinstance(route, tuple):
            raise urllib.error.HTTPError(url, 302, "Found", {"Location": route[1]}, None)
        return _Resp(route)

    def add(self, name, body):
        url = f"{STORAGE}/{name}"
        self.routes[url] = body
        return url


@pytest.fixture
def web(monkeypatch):
    import media_guard as mg

    fake = FakeWeb()
    monkeypatch.setattr(mg.urllib.request, "build_opener", lambda *a, **k: fake)
    monkeypatch.setattr(mg, "_default_resolve", lambda host: [fake.resolve_to])
    return fake


def ffmpeg(*args):
    subprocess.run([REAL_FFMPEG, "-v", "error", "-y", *args], check=True)


def make_mp4(path, seconds=2, audio=True, size="160x90"):
    args = ["-f", "lavfi", "-i", f"testsrc=size={size}:rate=10:duration={seconds}"]
    if audio:
        args += ["-f", "lavfi", "-i", f"sine=frequency=440:duration={seconds}", "-shortest", "-c:a", "aac"]
    ffmpeg(*args, "-c:v", "libx264", "-pix_fmt", "yuv420p", str(path))
    return path.read_bytes()


def make_audio(path, seconds=2):
    ffmpeg("-f", "lavfi", "-i", f"sine=frequency=440:duration={seconds}", str(path))
    return path.read_bytes()


def make_png(path, size="64x48"):
    ffmpeg("-f", "lavfi", "-i", f"testsrc=size={size}:duration=1", "-frames:v", "1", str(path))
    return path.read_bytes()


def probe(path, entries="format=duration"):
    r = subprocess.run([REAL_FFPROBE, "-v", "error", "-show_entries", entries, "-of", "default=nw=1", str(path)],
                       capture_output=True, text=True, check=True)
    return r.stdout
