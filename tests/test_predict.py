"""Predict-level security + behaviour tests (fixtures generated with ffmpeg)."""
import pytest

from conftest import FFCONCAT_PASSWD, HLS_WITH_HTTP, STORAGE, make_mp4, needs_ffmpeg

pytestmark = needs_ffmpeg
pytest.importorskip("cog")
cv2 = pytest.importorskip("cv2")

import predict  # noqa: E402


@pytest.fixture
def predictor(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # the output goes to ./tmp/
    p = predict.Predictor()
    p.setup()
    return p


def run(p, url, return_first_frame=False):
    return p.predict(video=url, return_first_frame=return_first_frame)


def test_hls_playlist_with_http_entry_is_refused(web, predictor):
    url = web.add("clip.m3u8", HLS_WITH_HTTP)
    with pytest.raises(ValueError, match="refused"):
        run(predictor, url)
    assert web.opened == [url]


def test_ffconcat_listing_etc_passwd_is_refused(web, predictor):
    url = web.add("clip.mp4", FFCONCAT_PASSWD)
    with pytest.raises(ValueError, match="refused"):
        run(predictor, url)


@pytest.mark.parametrize("url", ["data:video/mp4;base64,AAAAIGZ0eXBpc29t", "file:///etc/passwd", "http://127.0.0.1/a.mp4"])
def test_data_file_and_http_urls_are_refused(web, predictor, url):
    with pytest.raises(ValueError, match="refused"):
        run(predictor, url)
    assert web.opened == []


def test_private_ip_urls_and_redirects_are_refused(web, predictor, tmp_path):
    for url in ("https://169.254.169.254/latest/meta-data/", "https://10.0.0.7/storage/v1/a.mp4"):
        with pytest.raises(ValueError, match="refused"):
            run(predictor, url)
    src = f"{STORAGE}/redirect.mp4"
    web.routes[src] = ("redirect", "https://169.254.169.254/latest/meta-data/")
    with pytest.raises(ValueError, match="refused"):
        run(predictor, src)
    assert web.opened == [src]
    url = web.add("ok.mp4", make_mp4(tmp_path / "ok.mp4"))
    web.resolve_to = "10.0.0.7"
    with pytest.raises(ValueError, match="refused"):
        run(predictor, url)


@pytest.mark.parametrize("first", [True, False])
def test_normal_mp4_frame_is_extracted(web, predictor, tmp_path, first):
    url = web.add("in.mp4", make_mp4(tmp_path / "in.mp4", seconds=2, size="160x90"))
    out = run(predictor, url, first)
    img = cv2.imread(str(out))
    assert img is not None and img.shape[:2] == (90, 160)


def test_opencv_capture_gets_the_whitelists(tmp_path):
    """Belt and braces: even a playlist on disk can't be opened by OpenCV."""
    import os

    assert "format_whitelist;" in os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"]
    make_mp4(tmp_path / "seg.mp4")
    pl = tmp_path / "local.m3u8"
    pl.write_bytes(b"#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXTINF:2.0,\n" + str(tmp_path / "seg.mp4").encode() + b"\n#EXT-X-ENDLIST\n")
    assert not cv2.VideoCapture(str(pl)).isOpened()
    assert cv2.VideoCapture(str(tmp_path / "seg.mp4")).isOpened()
