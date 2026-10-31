"""Fetch + frame grab, without the cog runtime (so tests can run it).

The input is untrusted: media_guard downloads it (https, allowlisted hosts,
size cap) and checks its real type by magic bytes; OpenCV's FFmpeg backend
opens it with file-only protocol + demuxer whitelists
(OPENCV_FFMPEG_CAPTURE_OPTIONS, set by install_ffmpeg_guard).
"""
import media_guard

media_guard.install_ffmpeg_guard()  # before cv2 is imported

import logging  # noqa: E402
import os  # noqa: E402

import cv2  # noqa: E402

from helpers import select_frame_index  # noqa: E402

logger = logging.getLogger(__name__)

VIDEO_ALLOWED = media_guard.VIDEO_FORMATS


def fetch_video(video, workdir):
    try:
        path, fmt = media_guard.fetch(str(video) if video else "", workdir, allowed=VIDEO_ALLOWED, what="video")
    except media_guard.UnsafeInput as e:
        raise ValueError(f"video refused: {e}") from None
    logger.info("Fetched video (%s)", fmt)
    return path


def extract_frame(video_path, return_first_frame):
    """The original frame grab, unchanged. Returns the output path."""
    output_dir = "tmp"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "output_frame.jpg")

    cap = cv2.VideoCapture(str(video_path))
    if not cap.isOpened():
        raise ValueError("Failed to open video file")
    frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    if frame_count == 0:
        raise ValueError("Video file contains no frames")

    target_index = select_frame_index(frame_count, return_first_frame)
    cap.set(cv2.CAP_PROP_POS_FRAMES, target_index)
    ret, frame = cap.read()
    if not ret:
        label = "first" if return_first_frame else "last"
        raise ValueError(f"Failed to read {label} frame")

    cv2.imwrite(output_path, frame)
    cap.release()
    return output_path
