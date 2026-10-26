# Prediction interface for Cog ⚙️
# https://cog.run/python
import media_guard

media_guard.install_ffmpeg_guard()  # before cv2 is imported (see media_guard.py)

import tempfile  # noqa: E402

from cog import BasePredictor, Input, Path  # noqa: E402

from pipeline import extract_frame, fetch_video  # noqa: E402


class Predictor(BasePredictor):
    def setup(self):
        """Load the model into memory to make running multiple predictions efficient"""
        # No model to load for this predictor
        pass

    def predict(
        self,
        video: str = Input(description="Input video file (https link on Forge storage or a supplier CDN)"),
        return_first_frame: bool = Input(
            description="Toggle to return the first frame instead of the last frame",
            default=False,
        ),
    ) -> Path:
        """Run a single prediction on the model"""
        with tempfile.TemporaryDirectory(prefix="cog-input-") as workdir:
            video_path = fetch_video(video, workdir)
            output_path = extract_frame(video_path, return_first_frame)
        return Path(output_path)
