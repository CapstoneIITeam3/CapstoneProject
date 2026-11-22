"""High-Precision Video Recording Utility for Selenium E2E Tests.

Captures browser viewports during headless or headful Selenium test execution,
synchronizes frames to real wall-clock time (eliminating artificial fast-forward speedup),
and encodes them into smooth MP4 videos with diagnostic HUD overlays and end-state hold.
"""
import os
import time
import threading
import numpy as np
import cv2


class SeleniumVideoRecorder:
    """Records Selenium WebDriver browser sessions to an MP4 video with real-time pacing."""

    def __init__(
        self,
        driver,
        output_path: str,
        fps: int = 10,
        speed: float = 1.0,
        end_hold_sec: float = 1.2,
        overlay: bool = True,
        test_name: str = "",
    ):
        self.driver = driver
        self.output_path = output_path
        self.fps = max(5, fps)
        self.speed = max(0.1, float(speed))
        self.end_hold_sec = max(0.0, float(end_hold_sec))
        self.overlay = overlay
        self.test_name = test_name

        self._stop_event = threading.Event()
        self._thread = None
        self._snapshots = []  # List of tuples: (relative_timestamp, png_bytes)
        self._start_time = None
        self._test_status = None

    def set_status(self, passed: bool):
        """Set the final test status for display on the end-state banner."""
        self._test_status = "PASSED" if passed else "FAILED"

    def start(self):
        """Start the background screenshot capture thread."""
        os.makedirs(os.path.dirname(os.path.abspath(self.output_path)), exist_ok=True)
        self._start_time = time.time()
        self._snapshots.clear()
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._capture_worker,
            daemon=True,
            name=f"VideoRec-{self.test_name}",
        )
        self._thread.start()

    def _capture_worker(self):
        """Background worker that samples screenshots and tags them with elapsed timestamps."""
        # Poll aggressively so we catch fast DOM state transitions (up to ~15-20 times/sec if driver allows)
        target_interval = 0.05

        while not self._stop_event.is_set():
            t_sample = time.time()
            try:
                png_bytes = self.driver.get_screenshot_as_png()
                if png_bytes:
                    rel_time = t_sample - self._start_time
                    self._snapshots.append((rel_time, png_bytes))
            except Exception:
                # Browser navigating, alert open, or session closing
                pass

            elapsed = time.time() - t_sample
            sleep_time = max(0.01, target_interval - elapsed)
            time.sleep(sleep_time)

    def stop(self, timeout: float = 3.0):
        """Stop capture and render synchronized, real-time paced MP4 video container."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)

        # Capture one final frame after test assertion completes
        try:
            final_png = self.driver.get_screenshot_as_png()
            if final_png:
                rel_time = time.time() - self._start_time
                self._snapshots.append((rel_time, final_png))
        except Exception:
            pass

        if not self._snapshots:
            return None

        return self._render_video()

    def _render_video(self):
        """Assemble captured snapshots into a real-time paced video file."""
        # Decode all unique snapshots into OpenCV BGR images
        decoded_frames = []
        for rel_t, raw in self._snapshots:
            img = cv2.imdecode(np.frombuffer(raw, np.uint8), cv2.IMREAD_COLOR)
            if img is not None:
                decoded_frames.append((rel_t, img))

        if not decoded_frames:
            return None

        # Standardize target dimensions based on initial viewport
        first_img = decoded_frames[0][1]
        h_target, w_target, _ = first_img.shape
        dimensions = (w_target, h_target)

        # Calculate time boundaries
        t_first = decoded_frames[0][0]
        t_last = decoded_frames[-1][0]
        wall_clock_duration = max(0.5, t_last - t_first)

        # Scale duration by requested playback speed
        # speed = 1.0 -> exact real-time; speed = 0.5 -> half-speed demo
        active_video_duration = wall_clock_duration / self.speed
        total_video_duration = active_video_duration + self.end_hold_sec
        total_frames = max(1, int(total_video_duration * self.fps))

        fourcc = cv2.VideoWriter_fourcc(*"mp4v")
        writer = cv2.VideoWriter(self.output_path, fourcc, self.fps, dimensions)

        num_snapshots = len(decoded_frames)
        current_snap_idx = 0

        for frame_idx in range(total_frames):
            # Video time progress (0.0 to total_video_duration)
            v_time = frame_idx / self.fps

            if v_time <= active_video_duration:
                # Map video time back to wall-clock time
                target_wall_t = t_first + (v_time * self.speed)
                while (
                    current_snap_idx + 1 < num_snapshots
                    and decoded_frames[current_snap_idx + 1][0] <= target_wall_t
                ):
                    current_snap_idx += 1
                source_rel_t, base_img = decoded_frames[current_snap_idx]
                is_end_hold = False
            else:
                # In end-hold dwell phase: hold final snapshot
                source_rel_t, base_img = decoded_frames[-1]
                is_end_hold = True

            frame = base_img.copy()
            if (frame.shape[1], frame.shape[0]) != dimensions:
                frame = cv2.resize(frame, dimensions)

            if self.overlay:
                self._add_overlay(frame, v_time, self.speed, is_end_hold)

            writer.write(frame)

        writer.release()
        return self.output_path if os.path.exists(self.output_path) else None

    def _add_overlay(self, img, video_time: float, speed: float, is_end_hold: bool):
        """Render diagnostic HUD overlay on frame."""
        h, w, _ = img.shape
        banner_h = 38
        overlay_banner = img[0:banner_h, 0:w].copy()
        cv2.rectangle(img, (0, 0), (w, banner_h), (18, 18, 24), -1)
        cv2.addWeighted(img[0:banner_h, 0:w], 0.88, overlay_banner, 0.12, 0, img[0:banner_h, 0:w])

        # Test name & speed badge
        title_text = f"ThreatWatch E2E :: {self.test_name}" if self.test_name else "ThreatWatch E2E Test"
        font = cv2.FONT_HERSHEY_SIMPLEX

        # Status indicator
        if is_end_hold and self._test_status:
            status_color = (60, 210, 100) if self._test_status == "PASSED" else (60, 60, 240)
            cv2.circle(img, (16, 19), 6, status_color, -1)
            cv2.putText(img, f"{title_text} [{self._test_status}]", (30, 25), font, 0.52, (255, 255, 255), 1, cv2.LINE_AA)
        else:
            cv2.circle(img, (16, 19), 6, (80, 200, 120), -1)
            cv2.putText(img, title_text, (30, 25), font, 0.52, (240, 240, 245), 1, cv2.LINE_AA)

        # Right-aligned stats
        speed_label = "Real-Time (1.0x)" if abs(speed - 1.0) < 0.05 else f"Demo ({speed:.2f}x)"
        stats_text = f"T+{video_time:04.1f}s | {speed_label}"
        cv2.putText(img, stats_text, (w - 230, 25), font, 0.46, (180, 180, 205), 1, cv2.LINE_AA)

    def discard(self):
        """Delete video file if retention criteria not met."""
        self.stop()
        if os.path.exists(self.output_path):
            try:
                os.remove(self.output_path)
            except OSError:
                pass
