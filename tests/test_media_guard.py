"""Tests for the vendored media_guard (identical in every cog repo).

ffmpeg-backed tests skip when ffmpeg isn't installed.
"""
import io
import os
import shutil
import subprocess
import urllib.error

import pytest

import media_guard as mg

HAS_FFMPEG = shutil.which("ffmpeg") is not None
needs_ffmpeg = pytest.mark.skipif(not mg.real_binary("ffmpeg"), reason="ffmpeg not installed")

# SHA-256 of the canonical media_guard.py: every vendored copy must match.
MEDIA_GUARD_SHA256 = "551bedde476ed9c38ed175584d063156f16a86f0e30b5b62c1fdf432a0002956"
STORAGE = "https://vqzoyuvdarpfptuhhsws.supabase.co/storage/v1/object/public"
PUBLIC_RESOLVE = lambda host: ["104.18.38.10"]  # noqa: E731

HLS_WITH_HTTP = b"#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:2\n#EXTINF:2.0,\nhttp://169.254.169.254/latest/meta-data/x.ts\n#EXT-X-ENDLIST\n"
FFCONCAT_PASSWD = b"ffconcat version 1.0\nfile '/etc/passwd'\n"


def test_vendored_copy_is_the_canonical_one():
    import hashlib
    with open(mg.__file__, "rb") as f:
        assert hashlib.sha256(f.read()).hexdigest() == MEDIA_GUARD_SHA256, (
            "media_guard.py differs from the canonical copy: re-vendor it, never edit it in place")
    assert mg.GUARD_VERSION == "3"


# --- links -----------------------------------------------------------------

@pytest.mark.parametrize("url,ok", [
    (f"{STORAGE}/media_library/a.mp4", True),
    ("https://vqzoyuvdarpfptuhhsws.supabase.co/storage/v1/object/sign/x/a.mp4?token=t", True),
    ("https://nsriscxmwgauoxbqhpvn.supabase.co/storage/v1/object/public/a.png", True),
    ("https://replicate.delivery/pbxt/abc/out.mp4", True),
    ("https://v3b.fal.media/files/x.mp3", True),
    ("https://vqzoyuvdarpfptuhhsws.supabase.co/rest/v1/tools", False),
    ("http://vqzoyuvdarpfptuhhsws.supabase.co/storage/v1/object/public/a.mp4", False),
    ("data:video/mp4;base64,AAAA", False),
    ("data:application/vnd.apple.mpegurl;base64,I0VYVE0zVQ==", False),
    ("file:///etc/passwd", False),
    ("ftp://replicate.delivery/a.mp4", False),
    ("https://169.254.169.254/latest/meta-data/", False),
    ("https://10.0.0.5/storage/v1/a.mp4", False),
    ("https://[::1]/a.mp4", False),
    ("https://127.0.0.1/a.mp4", False),
    ("https://localhost/a.mp4", False),
    ("https://metadata.google.internal/computeMetadata/v1/", False),
    ("https://evil.example/a.mp4", False),
    ("https://replicate.delivery.evil.example/a.mp4", False),
    ("https://user:pw@replicate.delivery/a.mp4", False),
    ("https://replicate.delivery:8443/a.mp4", False),
    ("", False),
])
def test_url_allowlist(url, ok):
    assert mg.is_allowed_url(url) is ok


def test_font_hosts_are_opt_in():
    url = "https://fonts.gstatic.com/s/inter/v1/a.ttf"
    assert not mg.is_allowed_url(url)
    assert mg.is_allowed_url(url, mg.FONT_HOST_SUFFIXES)


def test_private_ip_resolution_is_refused():
    url = f"{STORAGE}/a.mp4"
    for addr in ("10.1.2.3", "169.254.169.254", "127.0.0.1", "::1", "fd00::1", "::ffff:10.0.0.1", "100.64.0.1",
                 "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "64:ff9b::a00:1", "64:ff9b:1::a00:1", "64:ff9b:1::808:808",
                 "::7f00:1", "::808:808", "2002:7f00:1::", "2002:a00:1::", "2002:808:808::1",
                 "2001:0:4136:e378:8000:63bf:3fff:fdd2", "::", "::1"):
        with pytest.raises(mg.UnsafeInput):
            mg.check_resolves_public(url, resolve=lambda h, a=addr: [a])
    mg.check_resolves_public(url, resolve=PUBLIC_RESOLVE)
    assert mg.is_public_ip("64:ff9b::808:808")  # well-known NAT64 of 8.8.8.8
    assert not mg.is_public_ip("::ffff:10.0.0.1") and mg.is_public_ip("::ffff:8.8.8.8")
    # a public NAT64 answer passes only for a host that is allowlisted anyway
    mg.check_resolves_public(url, resolve=lambda h: ["64:ff9b::808:808"])
    assert not mg.is_allowed_url("https://nat64-public.example/a.mp4")
    assert mg.is_public_ip("2606:4700::6810:260a")


# --- download --------------------------------------------------------------

class _Resp(io.BytesIO):
    def __init__(self, body, headers=None):
        super().__init__(body)
        self.headers = headers or {}


class FakeOpener:
    """url -> bytes body, or ("redirect", location)."""

    def __init__(self, routes):
        self.routes = routes
        self.opened = []

    def open(self, req, timeout=None):
        url = req.full_url
        self.opened.append(url)
        route = self.routes[url]
        if isinstance(route, tuple) and route[0] == "redirect":
            raise urllib.error.HTTPError(url, 302, "Found", {"Location": route[1]}, None)
        return _Resp(route, {"Content-Length": str(len(route))})


def test_redirect_to_a_private_or_foreign_host_is_refused(tmp_path):
    src = f"{STORAGE}/a.mp4"
    for target in ("https://169.254.169.254/latest/meta-data/", "http://replicate.delivery/a.mp4", "https://evil.example/a.mp4"):
        opener = FakeOpener({src: ("redirect", target)})
        with pytest.raises(mg.UnsafeInput):
            mg.download(src, str(tmp_path / "x"), resolve=PUBLIC_RESOLVE, opener=opener)
        assert opener.opened == [src]


def test_size_cap(tmp_path):
    src = f"{STORAGE}/a.mp4"
    opener = FakeOpener({src: b"\x00" * 2048})
    with pytest.raises(mg.UnsafeInput):
        mg.download(src, str(tmp_path / "x"), max_bytes=1024, resolve=PUBLIC_RESOLVE, opener=opener)


@pytest.mark.parametrize("body", [
    HLS_WITH_HTTP,
    FFCONCAT_PASSWD,
    b"file '/etc/passwd'\nfile 'http://169.254.169.254/'\n",
    b"<?xml version='1.0'?><MPD xmlns='urn:mpeg:dash:schema:mpd:2011'></MPD>",
    b"[playlist]\nFile1=http://169.254.169.254/\n",
    b"v=0\no=- 0 0 IN IP4 127.0.0.1\nm=video 5004 RTP/AVP 96\n",
    b"<html><body>not media</body></html>",
    b"\x00" * 64,
])
def test_fetch_refuses_playlists_lists_and_text(tmp_path, body):
    src = f"{STORAGE}/clip.mp4"  # the name lies; the bytes decide
    opener = FakeOpener({src: body})
    with pytest.raises(mg.UnsafeInput):
        mg.fetch(src, str(tmp_path), allowed=mg.ANY_MEDIA, resolve=PUBLIC_RESOLVE, opener=opener)


def test_fetch_keeps_a_safe_name_and_type(tmp_path):
    src = f"{STORAGE}/media/My%20Clip%25d-01.mp4"
    body = b"\x00\x00\x00\x20ftypisom" + b"\x00" * 64
    path, fmt = mg.fetch(src, str(tmp_path), resolve=PUBLIC_RESOLVE, opener=FakeOpener({src: body}))
    assert fmt == "mp4"
    assert os.path.basename(path) == "My_Clip_d-01.mp4"
    assert open(path, "rb").read() == body
    with pytest.raises(mg.UnsafeInput):  # an image where a video is expected
        mg.fetch(src, str(tmp_path), allowed=mg.VIDEO_FORMATS, resolve=PUBLIC_RESOLVE,
                 opener=FakeOpener({src: b"\x89PNG\r\n\x1a\n" + b"\x00" * 64}))


def test_safe_basename():
    assert mg.safe_basename("https://h/x/-rf.mp4") == "rf.mp4"
    assert mg.safe_basename("https://h/x/..%2F..%2Fetc%2Fpasswd") == "_.._etc_passwd"
    assert mg.safe_basename("https://h/") == "input"


# --- types -----------------------------------------------------------------

def test_detects_real_types_by_magic():
    z = b"\x00" * 400
    assert mg.detect_format(b"\x00\x00\x00\x20ftypisom" + z) == "mp4"
    assert mg.detect_format(b"\x00\x00\x00\x20ftypM4A " + z) == "mp4"
    assert mg.detect_format(b"\x00\x00\x00\x20ftypqt  " + z) == "mp4"
    assert mg.detect_format(b"\x00\x00\x00\x08wide" + z) == "mp4"
    assert mg.detect_format(b"\x00\x00\x00\x20ftypheic" + z) == "heif"
    assert mg.detect_format(b"\x1aE\xdf\xa3" + z) == "matroska"
    assert mg.detect_format(b"RIFF\x00\x00\x00\x00WAVEfmt " + z) == "wav"
    assert mg.detect_format(b"RIFF\x00\x00\x00\x00AVI LIST" + z) == "avi"
    assert mg.detect_format(b"RIFF\x00\x00\x00\x00WEBPVP8 " + z) == "webp"
    assert mg.detect_format(b"ID3\x04\x00\x00\x00\x00\x00\x00\xff\xfb\x90\x00" + z) == "mp3"
    assert mg.detect_format(b"\xff\xfb\x90\x00" + z) == "mp3"
    assert mg.detect_format(b"\xff\xf1\x50\x80" + z) == "aac"
    assert mg.detect_format(b"fLaC" + z) == "flac"
    assert mg.detect_format(b"OggS" + z) == "ogg"
    assert mg.detect_format(b"FLV\x01" + z) == "flv"
    assert mg.detect_format(b"\x89PNG\r\n\x1a\n" + z) == "png"
    assert mg.detect_format(b"\xff\xd8\xff\xe0" + z) == "jpeg"
    assert mg.detect_format(b"GIF89a" + z) == "gif"
    assert mg.detect_format(b"II*\x00" + z) == "tiff"
    assert mg.detect_format(b"\x00\x01\x00\x00\x00\x10" + z) == "ttf"
    assert mg.detect_format(b"OTTO" + z) == "otf"
    assert mg.detect_format(b"wOF2" + z) == "woff2"
    ts = bytearray(600)
    ts[0] = ts[188] = ts[376] = 0x47
    assert mg.detect_format(bytes(ts)) == "mpegts"


@pytest.mark.parametrize("head", [HLS_WITH_HTTP, FFCONCAT_PASSWD, b"#EXTM3U\n" + b"x" * 64, b"\xef\xbb\xbf#EXTM3U\n" + b"x" * 64])
def test_playlists_are_not_media(head):
    assert mg.detect_format(head) is None


def test_input_args_force_demuxer_and_whitelists():
    a = mg.input_args("/tmp/in.mp4", "mp4")
    assert a[-2:] == ["-i", "/tmp/in.mp4"]
    assert a[a.index("-f") + 1] == "mov"
    assert a[a.index("-protocol_whitelist") + 1] == mg.PROTOCOL_WHITELIST
    wl = a[a.index("-format_whitelist") + 1].split(",")
    for bad in ("hls", "concat", "dash", "sdp", "rtsp", "rtp", "applehttp", "mpjpeg", "ffmetadata", "tty"):
        assert bad not in wl
    for bad in ("http://x/a.mp4", "-y"):
        with pytest.raises(mg.UnsafeInput):
            mg.input_args(bad, "mp4")
    with pytest.raises(mg.UnsafeInput):
        mg.input_args("/tmp/x", "hls")


def test_subprocess_env_has_no_secrets(monkeypatch):
    monkeypatch.setenv("REPLICATE_API_TOKEN", "r8_secret")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "s")
    env = mg.subprocess_env()
    assert "REPLICATE_API_TOKEN" not in env and "AWS_SECRET_ACCESS_KEY" not in env
    assert env["PATH"] == mg.SAFE_PATH


def test_cube_lut_check(tmp_path):
    good = tmp_path / "a.cube"
    good.write_text('TITLE "x"\nLUT_3D_SIZE 2\n# c\n' + "0 0 0\n1 0 0\n0 1 0\n1 1 0\n0 0 1\n1 0 1\n0 1 1\n1 1 1\n")
    mg.check_cube_lut(str(good))
    for body in (HLS_WITH_HTTP, FFCONCAT_PASSWD, b"LUT_3D_SIZE 2\nfile:///etc/passwd\n", b"\x89PNG\r\n"):
        bad = tmp_path / "b.cube"
        bad.write_bytes(body)
        with pytest.raises(mg.UnsafeInput):
            mg.check_cube_lut(str(bad))


# --- wrappers --------------------------------------------------------------

@pytest.fixture
def restore_guard(monkeypatch):
    """Tests install wrappers around fake binaries; undo that afterwards."""
    for k in ("PATH", "FFMPEG_BINARY", "IMAGEIO_FFMPEG_EXE", "OPENCV_FFMPEG_CAPTURE_OPTIONS"):
        if k in os.environ:
            monkeypatch.setenv(k, os.environ[k])
        else:
            monkeypatch.delenv(k, raising=False)
    saved = dict(mg._state)
    yield
    mg._state.clear()
    mg._state.update(saved)


def _fake_tool(tmp_path, name):
    log = tmp_path / f"{name}.log"
    tool = tmp_path / f"real-{name}"
    tool.write_text(f'#!/bin/bash\n{{ printf "%s\\n" "$@"; echo ENV; env; }} > "{log}"\n')
    tool.chmod(0o755)
    return str(tool), log


@pytest.fixture
def fake(tmp_path, monkeypatch, restore_guard):
    ff, fflog = _fake_tool(tmp_path, "ffmpeg")
    fp, fplog = _fake_tool(tmp_path, "ffprobe")
    monkeypatch.setenv("REPLICATE_API_TOKEN", "r8_secret")
    mg._state.clear()
    info = mg.install_ffmpeg_guard(real_ffmpeg=ff, real_ffprobe=fp, real_imageio_ffmpeg=ff, bin_dir=str(tmp_path / "bin"))

    def run(tool, *args):
        log = fflog if tool == "ffmpeg" else fplog
        if log.exists():
            log.unlink()
        r = subprocess.run([tool, *args], capture_output=True, text=True)
        if r.returncode != 0:
            return r, None, None
        a, env = log.read_text().split("ENV\n")
        return r, a.splitlines(), env

    return info, run


FORCED = ["-protocol_whitelist", mg.PROTOCOL_WHITELIST, "-format_whitelist", mg.FORMAT_WHITELIST]


def test_wrappers_force_whitelists_on_every_input_and_strip_env(fake):
    info, run = fake
    assert shutil.which("ffmpeg") == info["ffmpeg"]
    assert os.environ["FFMPEG_BINARY"] == info["imageio_ffmpeg"] == os.environ["IMAGEIO_FFMPEG_EXE"]
    assert "format_whitelist;" in os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"]
    r, args, env = run("ffmpeg", "-y", "-i", "a.mp4", "-f", "lavfi", "-i", "anullsrc", *mg.input_args("/w/b.mp4", "mp4"), "out.mp4")
    assert r.returncode == 0, r.stderr
    assert args.count("-i") == 3 and args.count("-protocol_whitelist") == 3 and args.count("-format_whitelist") == 3
    first = args.index("-i")
    assert args[first - 4:first] == FORCED
    assert "REPLICATE_API_TOKEN" not in env and "r8_secret" not in env
    r, pargs, penv = run("ffprobe", "-v", "error", "a.mp4")
    assert pargs[:4] == FORCED and "r8_secret" not in penv


@pytest.mark.parametrize("tool", ["ffmpeg", "ffprobe"])
def test_whitelist_tokens_inside_a_filename_do_not_suppress_the_forced_flags(fake, tool):
    _, run = fake
    name = "x -protocol_whitelist file,http -format_whitelist hls .mp4"
    r, args, _ = run(tool, "-i", name, "o.mp4") if tool == "ffmpeg" else run(tool, name)
    assert r.returncode == 0, r.stderr
    assert args.count("-protocol_whitelist") == 1 and args[args.index("-protocol_whitelist") + 1] == mg.PROTOCOL_WHITELIST
    assert args[args.index("-format_whitelist") + 1] == mg.FORMAT_WHITELIST
    assert name in args


@pytest.mark.parametrize("tool", ["ffmpeg", "ffprobe"])
@pytest.mark.parametrize("extra", [
    ["-protocol_whitelist", "file,http,tcp"], ["-format_whitelist", "hls,mov"], ["-format_whitelist", "concat"],
    ["-pattern_type", "glob"], ["-enable_drefs", "1"],
])
def test_caller_cannot_loosen_the_whitelists(fake, tool, extra):
    _, run = fake
    r, _, _ = run(tool, *extra, "-i", "a.mp4", "o.mp4")
    assert r.returncode == 2 and "media_guard" in r.stderr


def _media(path):
    path.write_bytes(b"\x00\x00\x00\x20ftypM4A " + b"\x00" * 64)


def test_concat_only_for_our_own_list(fake, tmp_path):
    _, run = fake
    work = tmp_path / "work"
    work.mkdir()
    _media(work / "part-0000.m4a")
    _media(work / "part-0001.m4a")
    (work / "list.txt").write_text("file 'part-0000.m4a'\nfile 'part-0001.m4a'\n")
    r, _, _ = run("ffmpeg", "-f", "concat", "-safe", "0", "-i", str(work / "list.txt"), "o.m4a")
    assert r.returncode == 2  # dir not registered: user-style concat is refused
    mg.allow_concat_dir(str(work))
    r, args, _ = run("ffmpeg", "-f", "concat", "-safe", "0", "-i", str(work / "list.txt"), "o.m4a")
    assert r.returncode == 0, r.stderr
    i = args.index("-i")
    assert args[i - 6:i] == ["-protocol_whitelist", "file", "-format_whitelist", mg.FORMAT_WHITELIST + ",concat", "-safe", "1"]
    assert "0" not in args[:i - 6]  # the caller's -safe 0 was dropped
    (work / "notes.txt").write_text("hello")
    for body in ("file '/etc/passwd'\n", "file '../x.m4a'\n", "file 'http://169.254.169.254/'\n",
                 "file 'notes.txt'\n", "file 'missing.m4a'\n", "ffconcat version 1.0\n", "option x 1\nfile 'part-0000.m4a'\n"):
        (work / "evil.txt").write_text(body)
        r, _, _ = run("ffmpeg", "-f", "concat", "-i", str(work / "evil.txt"), "o.m4a")
        assert r.returncode == 2, body
    os.symlink("/etc/passwd", work / "link.m4a")
    (work / "evil.txt").write_text("file 'link.m4a'\n")
    assert run("ffmpeg", "-f", "concat", "-i", str(work / "evil.txt"), "o.m4a")[0].returncode == 2
    mg.clear_concat_dirs()
    assert run("ffmpeg", "-f", "concat", "-i", str(work / "list.txt"), "o.m4a")[0].returncode == 2
    assert run("ffprobe", "-f", "concat", str(work / "list.txt"))[0].returncode == 2


def test_image2pipe_only_from_stdin(fake, tmp_path):
    _, run = fake
    assert run("ffmpeg", "-f", "image2pipe", "-i", "-", "o.mp4")[0].returncode == 0
    assert run("ffmpeg", "-f", "image2pipe", "-i", str(tmp_path / "x.png"), "o.mp4")[0].returncode == 2


# --- real ffmpeg (the attacks themselves) ------------------------------------

@pytest.fixture
def guarded(tmp_path, restore_guard):
    real = {k: mg.real_binary(k) for k in ("ffmpeg", "ffprobe")}  # never a guard installed earlier
    mg._state.clear()
    return mg.install_ffmpeg_guard(real_ffmpeg=real["ffmpeg"], real_ffprobe=real["ffprobe"],
                                   real_imageio_ffmpeg=real["ffmpeg"], bin_dir=str(tmp_path / "bin"))


def _tiny_mp4(path):
    subprocess.run([shutil.which("ffmpeg"), "-v", "error", "-y", "-f", "lavfi", "-i", "testsrc=size=64x48:rate=10:duration=1",
                    "-f", "lavfi", "-i", "sine=frequency=440:duration=1", "-shortest", "-c:v", "libx264", "-pix_fmt", "yuv420p",
                    "-c:a", "aac", str(path)], check=True)


@needs_ffmpeg
def test_guarded_ffmpeg_refuses_hls_and_concat(tmp_path, guarded):
    (tmp_path / "evil.m3u8").write_bytes(HLS_WITH_HTTP)
    local = tmp_path / "evil2.m3u8"
    local.write_bytes(b"#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXTINF:2.0,\nfile:///etc/passwd\n#EXT-X-ENDLIST\n")
    (tmp_path / "list.ffconcat").write_bytes(FFCONCAT_PASSWD)
    for name in ("evil.m3u8", "evil2.m3u8", "list.ffconcat"):
        out = tmp_path / f"{name}.mp4"
        r = subprocess.run(["ffmpeg", "-v", "error", "-y", "-i", str(tmp_path / name), str(out)], capture_output=True, text=True)
        assert r.returncode != 0
        assert not out.exists() or out.stat().st_size == 0
    r = subprocess.run(["ffprobe", "-v", "error", str(tmp_path / "evil.m3u8")], capture_output=True, text=True)
    assert r.returncode != 0


@needs_ffmpeg
def test_guarded_ffmpeg_processes_normal_media(tmp_path, guarded):
    src = tmp_path / "in.mp4"
    _tiny_mp4(src)
    assert mg.sniff(str(src), mg.VIDEO_FORMATS) == "mp4"
    out = tmp_path / "out.mp4"
    r = subprocess.run(["ffmpeg", "-v", "error", "-y", *mg.input_args(str(src), "mp4"), "-t", "0.5", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    r = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", str(out)], capture_output=True, text=True)
    assert r.returncode == 0 and 0.3 < float(r.stdout) < 0.8
    # moviepy-style writer input through a pipe still works
    r = subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", "4x4", "-r", "1", "-i", "-",
                        str(tmp_path / "raw.mp4")], input=b"\x00" * 48, capture_output=True)
    assert r.returncode == 0, r.stderr


@needs_ffmpeg
def test_guarded_ffmpeg_runs_our_concat_list(tmp_path, guarded):
    work = tmp_path / "work"
    work.mkdir()
    for n in ("a.mp4", "b.mp4"):
        _tiny_mp4(work / n)
    (work / "list.txt").write_text("file 'a.mp4'\nfile 'b.mp4'\n")
    mg.allow_concat_dir(str(work))
    out = tmp_path / "joined.mp4"
    r = subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "concat", "-safe", "0", "-i", str(work / "list.txt"), "-c", "copy", str(out)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    r = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", str(out)], capture_output=True, text=True)
    assert 1.8 < float(r.stdout) < 2.3


def test_a_second_install_wraps_the_real_binary_not_the_first_wrapper(tmp_path, restore_guard):
    if not mg.real_binary("ffmpeg"):
        pytest.skip("ffmpeg not installed")
    mg._state.clear()
    first = mg.install_ffmpeg_guard(bin_dir=str(tmp_path / "b1"))
    mg._state.clear()
    second = mg.install_ffmpeg_guard(bin_dir=str(tmp_path / "b2"))
    for key in ("ffmpeg", "imageio_ffmpeg"):
        body = open(second[key]).read()
        assert str(tmp_path / "b1") not in body and mg.is_guard_wrapper(second[key])
    assert mg.real_binary("ffmpeg") and not mg.is_guard_wrapper(mg.real_binary("ffmpeg"))
    with pytest.raises(RuntimeError):
        mg._write_wrapper(str(tmp_path / "x"), "ffmpeg", first["ffmpeg"], second["concat_dirs"])
