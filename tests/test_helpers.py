"""Unit tests for the pure helpers in cog-frame-extractor."""
import pytest

from helpers import select_frame_index


class TestSelectFrameIndex:
    def test_first_frame_is_zero(self):
        assert select_frame_index(100, return_first_frame=True) == 0

    def test_last_frame_is_count_minus_one(self):
        assert select_frame_index(100, return_first_frame=False) == 99

    def test_single_frame_video_returns_zero_either_way(self):
        # First and last collapse to the same frame.
        assert select_frame_index(1, return_first_frame=True) == 0
        assert select_frame_index(1, return_first_frame=False) == 0

    def test_zero_frames_raises(self):
        with pytest.raises(ValueError, match="no frames"):
            select_frame_index(0, return_first_frame=True)

    def test_negative_frame_count_raises(self):
        # Defensive — cv2 occasionally returns negative on broken streams.
        with pytest.raises(ValueError):
            select_frame_index(-1, return_first_frame=True)
