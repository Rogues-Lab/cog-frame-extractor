# Prediction interface for Cog ⚙️
# https://cog.run/python

import os
import cv2
import numpy as np
from cog import BasePredictor, Input, Path


class Predictor(BasePredictor):
    def setup(self):
        """Load the model into memory to make running multiple predictions efficient"""
        # No model to load for this predictor
        pass

    def predict(
        self,
        video: Path = Input(description="Input video file"),
        return_first_frame: bool = Input(
            description="Toggle to return the first frame instead of the last frame",
            default=False,
        ),
    ) -> Path:
        """Run a single prediction on the model"""
        # Create output directory if it doesn't exist
        output_dir = "tmp"
        os.makedirs(output_dir, exist_ok=True)
        
        # Define output path
        output_path = os.path.join(output_dir, "output_frame.jpg")
        
        # Open the video file
        cap = cv2.VideoCapture(str(video))
        
        if not cap.isOpened():
            raise ValueError(f"Failed to open video file: {video}")
            
        # Get frame count
        frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        
        if frame_count == 0:
            raise ValueError(f"Video file contains no frames: {video}")
            
        if return_first_frame:
            # Set to first frame
            cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
            ret, frame = cap.read()
            if not ret:
                raise ValueError("Failed to read first frame")
        else:
            # Set to last frame
            cap.set(cv2.CAP_PROP_POS_FRAMES, frame_count - 1)
            ret, frame = cap.read()
            if not ret:
                raise ValueError("Failed to read last frame")
                
        # Save the frame as an image
        cv2.imwrite(output_path, frame)
        
        # Release the video capture object
        cap.release()
        
        return Path(output_path)