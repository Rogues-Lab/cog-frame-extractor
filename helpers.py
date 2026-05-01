"""Pure helpers for cog-frame-extractor — testable without cv2."""
from __future__ import annotations


def select_frame_index(frame_count: int, return_first_frame: bool) -> int:
    """
    Pick which 0-indexed frame to return for a given video length.

    Returns:
      - 0 when return_first_frame is True
      - frame_count - 1 when False (last frame)

    Raises ValueError on a zero-length video — callers should bail out
    before opening the video at all in that case.
    """
    if frame_count <= 0:
        raise ValueError(f"Video has no frames (frame_count={frame_count})")
    return 0 if return_first_frame else frame_count - 1
