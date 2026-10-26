"""media_guard: untrusted-media hardening shared by the film.fun cogs.

VENDORED: every cog repo carries its own copy (cogs are separate builds).
The canonical copy and its tests live in each repo as media_guard.py and
tests/test_media_guard.py; keep them identical across repos (bump GUARD_VERSION).

Threat: a caller-supplied URL or file makes ffmpeg/ffprobe/moviepy/OpenCV
fetch other URLs (SSRF: HLS/m3u8, DASH, RTSP/RTP/SDP …) or read local files
(concat/ffconcat lists, playlists with file: entries such as /proc/self/environ,
which holds REPLICATE_* secrets) and render them into the output.

Defence, in layers:
1. fetch(): the cog downloads every input itself. https only, default port,
   no credentials, allowlisted hosts (Forge storage + supplier CDNs) on every
   redirect hop, every resolved address public, size and time capped. data:,
   file:, http: and IP-literal URLs are refused.
2. detect_format(): the real type comes from magic bytes. Playlists, lists and
   anything text-like are refused before any decoder sees them.
3. input_args(): direct ffmpeg calls on an input use a forced demuxer (-f), a
   file-only protocol whitelist and a demuxer whitelist.
4. install_ffmpeg_guard(): every OTHER ffmpeg/ffprobe run (moviepy, imageio,
   bare "ffmpeg" in subprocess, OpenCV's bundled libavformat) gets the same
   protocol + demuxer whitelists on every input, and ffmpeg runs with an
   empty environment (no REPLICATE_* or other secrets).
"""
import ipaddress
import os
import shutil
import socket
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Iterable, Optional, Sequence, Tuple

GUARD_VERSION = "1"


class UnsafeInput(ValueError):
    """The input was refused (bad link, bad type, too large)."""


# ---------------------------------------------------------------------------
# Links
# ---------------------------------------------------------------------------

# Forge storage (prod) and Splice storage. Only their Storage API is served.
STORAGE_HOSTS = ("vqzoyuvdarpfptuhhsws.supabase.co", "nsriscxmwgauoxbqhpvn.supabase.co")
STORAGE_PATH_PREFIX = "/storage/v1/"
# Supplier output CDNs. A suffix matches the host or any subdomain.
SUPPLIER_HOST_SUFFIXES = ("replicate.delivery", "fal.media")
# Font sources the timeline / overlay text may name (fontUrl). Opt-in per call.
FONT_HOST_SUFFIXES = ("cdn.jsdelivr.net", "fonts.googleapis.com", "fonts.gstatic.com")

MAX_REDIRECTS = 3
DOWNLOAD_TIMEOUT_SECONDS = 600  # whole download, all hops
CONNECT_TIMEOUT_SECONDS = 30  # each socket operation

MB = 1024 * 1024
MAX_MEDIA_BYTES = 1024 * MB  # video / audio
MAX_IMAGE_BYTES = 100 * MB
MAX_SMALL_BYTES = 20 * MB  # fonts, LUTs, CSS


def _host_matches(host: str, suffixes: Iterable[str]) -> bool:
    return any(host == s or host.endswith("." + s) for s in suffixes)


def check_url(url: str, extra_host_suffixes: Sequence[str] = ()) -> str:
    """Return the url if it may be fetched, else raise UnsafeInput."""
    if not isinstance(url, str) or not url.strip():
        raise UnsafeInput("No link given")
    url = url.strip()
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        raise UnsafeInput("The link isn't valid") from None
    if parts.scheme.lower() != "https":
        raise UnsafeInput("Only https links are accepted")
    if parts.username or parts.password:
        raise UnsafeInput("Links with credentials are refused")
    if port not in (None, 443):
        raise UnsafeInput("Only the default https port is accepted")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise UnsafeInput("The link has no host")
    try:
        ipaddress.ip_address(host)
        raise UnsafeInput("Links to IP addresses are refused")
    except ValueError:
        pass
    if host in STORAGE_HOSTS:
        if not parts.path.startswith(STORAGE_PATH_PREFIX):
            raise UnsafeInput("Only storage links are accepted on this host")
        return url
    if _host_matches(host, SUPPLIER_HOST_SUFFIXES) or _host_matches(host, extra_host_suffixes):
        return url
    raise UnsafeInput(f"Links to {host} aren't allowed")


def is_allowed_url(url: str, extra_host_suffixes: Sequence[str] = ()) -> bool:
    try:
        check_url(url, extra_host_suffixes)
        return True
    except UnsafeInput:
        return False


def is_public_ip(addr: str) -> bool:
    ip = ipaddress.ip_address(addr.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return bool(ip.is_global) and not ip.is_multicast


def _default_resolve(host: str) -> Iterable[str]:
    return {ai[4][0] for ai in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)}


def check_resolves_public(url: str, resolve=None) -> None:
    host = (urllib.parse.urlsplit(url).hostname or "").rstrip(".")
    try:
        addrs = list((resolve or _default_resolve)(host))
    except OSError:
        raise UnsafeInput(f"Could not resolve {host}") from None
    if not addrs or not all(is_public_ip(a) for a in addrs):
        raise UnsafeInput(f"{host} does not resolve to a public address")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # followed by hand so every hop is re-checked


def download(
    url: str,
    dest: str,
    max_bytes: int = MAX_MEDIA_BYTES,
    extra_host_suffixes: Sequence[str] = (),
    resolve=None,
    opener=None,
) -> str:
    """Download url to dest. Returns the final URL (after checked redirects)."""
    opener = opener or urllib.request.build_opener(_NoRedirect())
    deadline = time.monotonic() + DOWNLOAD_TIMEOUT_SECONDS
    current = url.strip() if isinstance(url, str) else url
    for _ in range(MAX_REDIRECTS + 1):
        check_url(current, extra_host_suffixes)
        check_resolves_public(current, resolve)
        req = urllib.request.Request(current, headers={"User-Agent": "film-fun-cog/1"})
        try:
            resp = opener.open(req, timeout=CONNECT_TIMEOUT_SECONDS)
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307, 308) and e.headers.get("Location"):
                current = urllib.parse.urljoin(current, e.headers["Location"])
                continue
            raise UnsafeInput(f"Could not download the file (HTTP {e.code})") from None
        except (urllib.error.URLError, OSError) as e:
            raise UnsafeInput(f"Could not download the file ({type(e).__name__})") from None
        with resp:
            declared = resp.headers.get("Content-Length")
            if declared and declared.isdigit() and int(declared) > max_bytes:
                raise UnsafeInput(f"The file is larger than {max_bytes // MB} MB")
            total = 0
            with open(dest, "wb") as out:
                while True:
                    if time.monotonic() > deadline:
                        raise UnsafeInput("The download took too long")
                    chunk = resp.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise UnsafeInput(f"The file is larger than {max_bytes // MB} MB")
                    out.write(chunk)
        if total == 0:
            raise UnsafeInput("The file is empty")
        return current
    raise UnsafeInput("Too many redirects")


# ---------------------------------------------------------------------------
# Types (magic bytes)
# ---------------------------------------------------------------------------

VIDEO_FORMATS = frozenset({"mp4", "matroska", "avi", "mpegts", "flv", "gif"})
AUDIO_FORMATS = frozenset({"wav", "mp3", "aac", "flac", "ogg", "mp4", "matroska"})
IMAGE_FORMATS = frozenset({"png", "jpeg", "gif", "webp", "bmp", "tiff"})
FONT_FORMATS = frozenset({"ttf", "otf", "ttc", "woff", "woff2"})
AV_FORMATS = VIDEO_FORMATS | AUDIO_FORMATS
ANY_MEDIA = AV_FORMATS | IMAGE_FORMATS

# Detected type -> the demuxer forced with -f. Images use the content-based
# *_pipe demuxers (image2 would guess the codec from the file name).
DEMUXERS = {
    "mp4": "mov",  # mp4 / m4a / mov / 3gp; external data refs stay off (ffmpeg default)
    "matroska": "matroska",  # mkv / webm
    "avi": "avi",
    "mpegts": "mpegts",
    "flv": "flv",
    "wav": "wav",
    "mp3": "mp3",
    "aac": "aac",
    "flac": "flac",
    "ogg": "ogg",
    "gif": "gif",
    "png": "png_pipe",
    "jpeg": "jpeg_pipe",
    "webp": "webp_pipe",
    "bmp": "bmp_pipe",
    "tiff": "tiff_pipe",
}

# Demuxers ffmpeg may open at all. No hls, dash, concat, sdp/rtp/rtsp, playlists
# (m3u/pls/xspf …) or other text formats. lavfi and the raw PCM/video formats
# have no probe (only an explicit -f picks them): moviepy writes through
# "-f rawvideo -i -" and the cogs build silent tracks with "-f lavfi".
FORMAT_WHITELIST = ",".join(sorted(set(DEMUXERS.values()) | {
    "image2", "gif_pipe",
    "rawvideo", "s16le", "s32le", "f32le", "f64le", "u8", "s8", "lavfi",
}))
PROTOCOL_WHITELIST = "file,pipe,fd"  # "-" is pipe (ffmpeg <8) or fd (ffmpeg 8)

_MP4_BOXES = (b"ftyp", b"moov", b"mdat", b"free", b"wide", b"skip", b"pnot")
_HEIF_BRANDS = (b"heic", b"heix", b"hevc", b"hevx", b"mif1", b"msf1", b"avif", b"avis")


def _id3_end(b: bytes) -> int:
    if len(b) >= 10 and b[:3] == b"ID3":
        size = ((b[6] & 0x7F) << 21) | ((b[7] & 0x7F) << 14) | ((b[8] & 0x7F) << 7) | (b[9] & 0x7F)
        return 10 + size + (10 if b[5] & 0x10 else 0)
    return 0


def _sync_kind(b: bytes, at: int) -> Optional[str]:
    """MPEG audio (mp3) or ADTS (aac) frame sync at `at`."""
    if at + 2 > len(b) or b[at] != 0xFF or (b[at + 1] & 0xE0) != 0xE0:
        return None
    if (b[at + 1] & 0xF6) == 0xF0:  # 12-bit sync, layer bits 00
        return "aac"
    if ((b[at + 1] >> 1) & 3) != 0 and ((b[at + 1] >> 3) & 3) != 1:
        return "mp3"
    return None


def detect_format(head: bytes) -> Optional[str]:
    """The real type from the first bytes (read 64 KB), or None to refuse."""
    b = head or b""
    if len(b) < 12:
        return None
    if b[:4] == b"RIFF":
        return {b"WAVE": "wav", b"AVI ": "avi", b"WEBP": "webp"}.get(b[8:12])
    if b[4:8] == b"ftyp":
        return "heif" if b[8:12] in _HEIF_BRANDS else "mp4"
    if b[4:8] in _MP4_BOXES:
        return "mp4"
    if b[:4] == b"\x1aE\xdf\xa3":
        return "matroska"
    if b[:4] == b"fLaC":
        return "flac"
    if b[:4] == b"OggS":
        return "ogg"
    if b[:3] == b"FLV":
        return "flv"
    if b[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if b[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if b[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if b[:2] == b"BM" and len(b) >= 26 and b[6:10] == b"\x00\x00\x00\x00":
        return "bmp"
    if b[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff"
    if b[:4] in (b"\x00\x01\x00\x00", b"true"):
        return "ttf"
    if b[:4] == b"OTTO":
        return "otf"
    if b[:4] == b"ttcf":
        return "ttc"
    if b[:4] == b"wOFF":
        return "woff"
    if b[:4] == b"wOF2":
        return "woff2"
    if b[0] == 0x47 and len(b) > 376 and b[188] == 0x47 and b[376] == 0x47:
        return "mpegts"
    if b[:3] == b"ID3":
        end = _id3_end(b)
        if end >= len(b):
            return "mp3"
        return _sync_kind(b, end) or ("mp3" if b[end:end + 2] == b"\x00\x00" else None)
    return _sync_kind(b, 0)


def sniff(path: str, allowed: Iterable[str] = ANY_MEDIA, what: str = "file") -> str:
    """The detected type of a local file, or UnsafeInput if it isn't allowed."""
    with open(path, "rb") as f:
        head = f.read(64 * 1024)
    fmt = detect_format(head)
    if fmt is None or fmt not in set(allowed):
        raise UnsafeInput(f"Unsupported {what}: not a recognised media file of the expected type")
    return fmt


_SAFE_NAME_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")


def safe_basename(url: str, fallback: str = "input") -> str:
    """The URL's file name, reduced to [A-Za-z0-9._-] (no %, no leading - or .)."""
    try:
        name = urllib.parse.unquote(os.path.basename(urllib.parse.urlsplit(url).path))
    except ValueError:
        name = ""
    name = "".join(c if c in _SAFE_NAME_CHARS else "_" for c in name).lstrip(".-")[-120:]
    return name or fallback


def fetch(
    url: str,
    workdir: str,
    allowed: Iterable[str] = AV_FORMATS,
    max_bytes: int = MAX_MEDIA_BYTES,
    extra_host_suffixes: Sequence[str] = (),
    name: Optional[str] = None,
    what: str = "file",
    resolve=None,
    opener=None,
) -> Tuple[str, str]:
    """Download + type-check one input. Returns (local_path, detected_format).

    The file keeps the URL's (sanitised) file name, as cog's own Path download
    did, inside a fresh directory so names never collide.
    """
    os.makedirs(workdir, exist_ok=True)
    folder = tempfile.mkdtemp(prefix="in-", dir=workdir)
    dest = os.path.join(folder, name or safe_basename(url))
    try:
        download(url, dest, max_bytes=max_bytes, extra_host_suffixes=extra_host_suffixes, resolve=resolve, opener=opener)
        fmt = sniff(dest, allowed, what)
    except Exception:
        shutil.rmtree(folder, ignore_errors=True)
        raise
    return dest, fmt


# ---------------------------------------------------------------------------
# Direct ffmpeg calls
# ---------------------------------------------------------------------------


def input_args(path: str, fmt: Optional[str] = None) -> list:
    """`[...whitelists, -f <demuxer>, -i, path]` for one local, sniffed input."""
    if "://" in str(path) or str(path).startswith("-"):
        raise UnsafeInput("ffmpeg inputs must be local paths")
    args = ["-protocol_whitelist", PROTOCOL_WHITELIST, "-format_whitelist", FORMAT_WHITELIST]
    if fmt is not None:
        if fmt not in DEMUXERS:
            raise UnsafeInput("Unsupported input type")
        args += ["-f", DEMUXERS[fmt]]
    return args + ["-i", str(path)]


SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
_PASSTHROUGH_ENV = ("TMPDIR", "LANG", "LC_ALL", "FONTCONFIG_FILE", "FONTCONFIG_PATH")


def subprocess_env(extra: Optional[dict] = None) -> dict:
    """A minimal environment for media tools: no secrets (REPLICATE_*, tokens)."""
    env = {"PATH": SAFE_PATH}
    for k in _PASSTHROUGH_ENV:
        if os.environ.get(k):
            env[k] = os.environ[k]
    env.update(extra or {})
    return env


# ---------------------------------------------------------------------------
# Every other ffmpeg/ffprobe run (moviepy, imageio, bare "ffmpeg", OpenCV)
# ---------------------------------------------------------------------------

_FFMPEG_WRAPPER = r"""#!/bin/bash
# media_guard ffmpeg wrapper: whitelists on every input, empty environment.
args=()
pw=0
fw=0
for a in "$@"; do
  if [ "$a" = "-i" ]; then
    [ "$pw" = 0 ] && args+=("-protocol_whitelist" "__PW__")
    [ "$fw" = 0 ] && args+=("-format_whitelist" "__FW__")
    pw=0
    fw=0
  fi
  [ "$a" = "-protocol_whitelist" ] && pw=1
  [ "$a" = "-format_whitelist" ] && fw=1
  args+=("$a")
done
exec /usr/bin/env -i __ENV__ "__REAL__" "${args[@]}"
"""

_FFPROBE_WRAPPER = r"""#!/bin/bash
# media_guard ffprobe wrapper: whitelists on the input, empty environment.
pre=()
case " $* " in *" -protocol_whitelist "*) ;; *) pre+=("-protocol_whitelist" "__PW__") ;; esac
case " $* " in *" -format_whitelist "*) ;; *) pre+=("-format_whitelist" "__FW__") ;; esac
exec /usr/bin/env -i __ENV__ "__REAL__" "${pre[@]}" "$@"
"""

_state = {}


def _env_assignments() -> str:
    parts = [f'PATH="{SAFE_PATH}"']
    for k in _PASSTHROUGH_ENV:
        parts.append(f'${{{k}:+{k}="${k}"}}')
    return " ".join(parts)


def _write_wrapper(path: str, template: str, real: str) -> None:
    for bad in ('"', "$", "`", "\\", "\n"):
        if bad in real:
            raise RuntimeError("unexpected character in the ffmpeg path")
    body = (template.replace("__PW__", PROTOCOL_WHITELIST).replace("__FW__", FORMAT_WHITELIST)
            .replace("__ENV__", _env_assignments()).replace("__REAL__", real))
    with open(path, "w") as f:
        f.write(body)
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)


def _imageio_ffmpeg_exe() -> Optional[str]:
    try:
        import imageio_ffmpeg  # noqa: WPS433
    except Exception:
        return None
    saved = os.environ.pop("IMAGEIO_FFMPEG_EXE", None)
    try:
        return imageio_ffmpeg.get_ffmpeg_exe()
    except Exception:
        return None
    finally:
        if saved is not None:
            os.environ["IMAGEIO_FFMPEG_EXE"] = saved


def install_ffmpeg_guard(
    real_ffmpeg: Optional[str] = None,
    real_ffprobe: Optional[str] = None,
    real_imageio_ffmpeg: Optional[str] = None,
    bin_dir: Optional[str] = None,
) -> dict:
    """Route every ffmpeg/ffprobe through the whitelisting wrappers. Idempotent.

    Call it at the top of predict.py BEFORE importing moviepy. Each wrapper
    runs the same binary the caller used before (system ffmpeg for bare
    "ffmpeg", imageio-ffmpeg's for moviepy), so output is unchanged.
    """
    if _state.get("installed") and not (real_ffmpeg or real_ffprobe or bin_dir):
        return dict(_state)
    path_dirs = [d for d in os.environ.get("PATH", "").split(os.pathsep) if d and d != _state.get("bin_dir")]
    clean_path = os.pathsep.join(path_dirs)
    real_ffmpeg = real_ffmpeg or shutil.which("ffmpeg", path=clean_path)
    real_ffprobe = real_ffprobe or shutil.which("ffprobe", path=clean_path)
    real_imageio = real_imageio_ffmpeg or _imageio_ffmpeg_exe() or real_ffmpeg
    bin_dir = bin_dir or tempfile.mkdtemp(prefix="media-guard-bin-")
    os.makedirs(bin_dir, exist_ok=True)
    info = {"installed": True, "bin_dir": bin_dir}
    if real_ffmpeg:
        _write_wrapper(os.path.join(bin_dir, "ffmpeg"), _FFMPEG_WRAPPER, os.path.realpath(real_ffmpeg))
        info["ffmpeg"] = os.path.join(bin_dir, "ffmpeg")
    if real_ffprobe:
        _write_wrapper(os.path.join(bin_dir, "ffprobe"), _FFPROBE_WRAPPER, os.path.realpath(real_ffprobe))
        info["ffprobe"] = os.path.join(bin_dir, "ffprobe")
    if real_imageio:
        sub = os.path.join(bin_dir, "imageio")
        os.makedirs(sub, exist_ok=True)
        _write_wrapper(os.path.join(sub, "ffmpeg"), _FFMPEG_WRAPPER, os.path.realpath(real_imageio))
        info["imageio_ffmpeg"] = os.path.join(sub, "ffmpeg")
        os.environ["IMAGEIO_FFMPEG_EXE"] = info["imageio_ffmpeg"]
        os.environ["FFMPEG_BINARY"] = info["imageio_ffmpeg"]
        cfg = sys.modules.get("moviepy.config")
        if cfg is not None:  # moviepy imported first: point it at the wrapper too
            cfg.FFMPEG_BINARY = info["imageio_ffmpeg"]
    os.environ["PATH"] = os.pathsep.join([bin_dir] + path_dirs)
    # OpenCV's bundled libavformat: options for every VideoCapture open.
    os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"] = (
        f"protocol_whitelist;{PROTOCOL_WHITELIST}|format_whitelist;{FORMAT_WHITELIST}"
    )
    _state.clear()
    _state.update(info)
    return dict(info)


# ---------------------------------------------------------------------------
# Small text inputs (.cube LUTs)
# ---------------------------------------------------------------------------

_CUBE_KEYWORDS = ("TITLE", "LUT_1D_SIZE", "LUT_3D_SIZE", "DOMAIN_MIN", "DOMAIN_MAX", "LUT_1D_INPUT_RANGE", "LUT_3D_INPUT_RANGE")


def check_cube_lut(path: str) -> None:
    """A .cube LUT is plain ASCII: keywords, comments and rows of numbers only."""
    with open(path, "rb") as f:
        data = f.read(MAX_SMALL_BYTES + 1)
    if len(data) > MAX_SMALL_BYTES:
        raise UnsafeInput("The LUT file is too large")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise UnsafeInput("The LUT isn't a .cube file") from None
    has_size = False
    rows = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        word = line.split(None, 1)[0]
        if word in _CUBE_KEYWORDS:
            has_size = has_size or word in ("LUT_1D_SIZE", "LUT_3D_SIZE")
            continue
        try:
            nums = [float(x) for x in line.split()]
        except ValueError:
            raise UnsafeInput("The LUT isn't a .cube file") from None
        if len(nums) != 3:
            raise UnsafeInput("The LUT isn't a .cube file")
        rows += 1
    if not has_size or rows == 0:
        raise UnsafeInput("The LUT isn't a .cube file")
