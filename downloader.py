#!/usr/bin/env python3
"""
enhanced_downloader_pinterest.py
Enhanced Tkinter resumable downloader with Pinterest video URL extraction.

Usage:
    python enhanced_downloader_pinterest.py

Dependencies:
    pip install requests
"""

import os
import time
import json
import math
import re
import html
import threading
from collections import deque
from pathlib import Path
from urllib.parse import urlsplit
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import requests

# ---------- Config ----------
CHUNK_SIZE = 1024 * 64            # 64 KB chunks
MAX_RETRIES = 5
RETRY_BACKOFF_FACTOR = 1.5        # exponential backoff multiplier
SPEED_SAMPLES = 6                 # smoothing window (seconds)
META_SUFFIX = ".meta.json"
PART_SUFFIX = ".part"
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
# ----------------------------


def looks_like_pinterest(url: str) -> bool:
    try:
        netloc = urlsplit(url).netloc.lower()
        return any(x in netloc for x in ("pinterest.com", "pinimg.com", "pin.it"))
    except Exception:
        return False


def extract_pinterest_video_url(session: requests.Session, url: str, timeout=10) -> str | None:
    """
    Try several heuristics to find a direct mp4 URL for a Pinterest page.
    Returns direct mp4 URL or None if not found.
    """
    # If the URL already looks like a direct mp4 (v.pinimg.com...), just return it
    if re.search(r"\.mp4($|\?)", url):
        return url

    headers = {"User-Agent": USER_AGENT}
    try:
        resp = session.get(url, headers=headers, timeout=timeout)
        resp.raise_for_status()
        text = resp.text
    except Exception:
        # Try again with trailing slash removed/added if initial fails
        try:
            alt_url = url.rstrip("/") + "/"
            resp = session.get(alt_url, headers=headers, timeout=timeout)
            resp.raise_for_status()
            text = resp.text
        except Exception:
            return None

    text_unescaped = html.unescape(text)

    # 1) Try meta tags: og:video, og:video:secure_url, twitter:player:stream
    meta_patterns = [
        r'<meta[^>]+property=["\']og:video["\'][^>]+content=["\']([^"\']+)["\']',
        r'<meta[^>]+property=["\']og:video:url["\'][^>]+content=["\']([^"\']+)["\']',
        r'<meta[^>]+property=["\']og:video:secure_url["\'][^>]+content=["\']([^"\']+)["\']',
        r'<meta[^>]+name=["\']twitter:player:stream["\'][^>]+content=["\']([^"\']+)["\']',
    ]
    for pat in meta_patterns:
        m = re.search(pat, text_unescaped, flags=re.IGNORECASE)
        if m:
            cand = m.group(1)
            cand = cand.replace("\\u0026", "&")
            if re.search(r"\.mp4($|\?)", cand):
                return cand

    # 2) JSON blobs: contentUrl / playable_url / progressive arrays
    json_patterns = [
        r'"contentUrl"\s*:\s*"([^"]+\.mp4[^"]*)"',
        r'"playable_url"\s*:\s*"([^"]+\.mp4[^"]*)"',
        r'"progressive"\s*:\s*\[([^\]]+)\]',  # contains objects with url fields
        r'"videos"\s*:\s*\{[^}]*"url"\s*:\s*"([^"]+\.mp4[^"]*)"',  # fallback
    ]
    for pat in json_patterns:
        m = re.search(pat, text_unescaped, flags=re.IGNORECASE | re.DOTALL)
        if m:
            if pat.endswith("progressive\"\\s*:\\s*\\["):
                # extract url fields inside the array
                arr_text = m.group(1)
                m2 = re.search(r'"url"\s*:\s*"([^"]+\.mp4[^"]*)"', arr_text, flags=re.IGNORECASE)
                if m2:
                    cand = m2.group(1).replace("\\u0026", "&")
                    return cand
            else:
                cand = m.group(1).replace("\\u0026", "&")
                # unescape any sequences
                cand = cand.replace("\\/", "/")
                if re.search(r"https?://", cand) and re.search(r"\.mp4($|\?)", cand):
                    return cand

    # 3) Generic search for v.pinimg.com or i.pinimg.com .mp4 links
    m = re.search(r'https://v\.pinimg\.com/videos/[^\s"\'<>]+?\.mp4[^"\']*', text_unescaped)
    if m:
        return m.group(0).replace("\\u0026", "&")

    m = re.search(r'https://i\.pinimg\.com/originals/[^\s"\'<>]+?\.mp4[^"\']*', text_unescaped)
    if m:
        return m.group(0).replace("\\u0026", "&")

    # 4) Sometimes Pinterest uses cdn URLs inside escaped JSON
    m = re.search(r'(https?://[^"]+\.pinimg\.com/[^"]+\.mp4[^"]*)', text_unescaped)
    if m:
        cand = m.group(1).replace("\\u0026", "&").replace("\\/", "/")
        if re.search(r"\.mp4($|\?)", cand):
            return cand

    # 5) As a last resort, follow embed endpoints (some pins have /video/ or /pin/<id>/embed)
    # Try appending /video or /embed appended patterns and re-check
    try_variants = []
    p = urlsplit(url)
    base = f"{p.scheme}://{p.netloc}{p.path}"
    if not base.endswith("/"):
        try_variants.append(base + "/embed/")
        try_variants.append(base + "/video/")
        try_variants.append(base + "?r=record")
    else:
        try_variants.append(base + "embed/")
        try_variants.append(base + "video/")

    for vurl in try_variants:
        try:
            r2 = session.get(vurl, headers=headers, timeout=8)
            if r2.ok:
                txt2 = html.unescape(r2.text)
                m = re.search(r'https://v\.pinimg\.com/videos/[^\s"\'<>]+?\.mp4[^"\']*', txt2)
                if m:
                    return m.group(0).replace("\\u0026", "&")
        except Exception:
            continue

    # failed
    return None


class EnhancedDownloader:
    def __init__(self, master):
        self.master = master
        master.title("Resumable Downloader (Pinterest aware)")

        # UI layout (ttk where appropriate)
        frm = ttk.Frame(master, padding=12)
        frm.grid(sticky="nsew")
        master.columnconfigure(0, weight=1)
        master.rowconfigure(0, weight=1)

        ttk.Label(frm, text="Download URL:").grid(row=0, column=0, sticky="w")
        self.url_var = tk.StringVar()
        self.url_entry = ttk.Entry(frm, textvariable=self.url_var, width=60)
        self.url_entry.grid(row=1, column=0, columnspan=4, sticky="ew", pady=6)

        ttk.Label(frm, text="Save as (optional):").grid(row=2, column=0, sticky="w")
        self.path_var = tk.StringVar()
        self.path_label = ttk.Label(frm, textvariable=self.path_var, width=50)
        self.path_label.grid(row=3, column=0, columnspan=2, sticky="w")
        ttk.Button(frm, text="Browse...", command=self.choose_path).grid(row=3, column=2, sticky="e")

        # Buttons
        self.download_btn = ttk.Button(frm, text="Download", command=self.start_download)
        self.download_btn.grid(row=4, column=0, pady=(10, 4))
        self.pause_btn = ttk.Button(frm, text="Pause", command=self.pause, state="disabled")
        self.pause_btn.grid(row=4, column=1, padx=6)
        self.resume_btn = ttk.Button(frm, text="Resume", command=self.resume, state="disabled")
        self.resume_btn.grid(row=4, column=2, padx=6)
        self.cancel_btn = ttk.Button(frm, text="Cancel", command=self.cancel, state="disabled")
        self.cancel_btn.grid(row=4, column=3, padx=6)

        # Progress and status
        self.progress = ttk.Progressbar(frm, length=580, mode="determinate")
        self.progress.grid(row=5, column=0, columnspan=4, pady=(10, 4))
        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(frm, textvariable=self.status_var).grid(row=6, column=0, columnspan=4, sticky="w")

        # internals
        self._worker_thread = None
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": USER_AGENT})
        self._pause_event = threading.Event()   # when set -> paused
        self._stop_event = threading.Event()    # when set -> cancel/stop
        self._lock = threading.Lock()

        # runtime metadata
        self._url = None
        self._out_path = None
        self._part_path = None
        self._meta_path = None
        self._total_size = 0
        self._downloaded = 0
        self._speed_samples = deque(maxlen=SPEED_SAMPLES)
        self._last_update = 0

        # graceful close
        master.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------------- UI helpers ----------------
    def choose_path(self):
        suggested = self.url_guess_filename(self.url_var.get().strip()) or "download"
        file = filedialog.asksaveasfilename(title="Save as", initialfile=suggested)
        if file:
            self.path_var.set(file)

    def set_status(self, text):
        # queue to main thread
        self.master.after(0, lambda: self.status_var.set(text))

    def set_progress(self, percent):
        # percent: 0..100
        self.master.after(0, lambda: self.progress.configure(value=percent))

    def enable_buttons_for_running(self):
        self.master.after(0, lambda: (
            self.download_btn.config(state="disabled"),
            self.pause_btn.config(state="normal"),
            self.resume_btn.config(state="disabled"),
            self.cancel_btn.config(state="normal"),
        ))

    def enable_buttons_for_paused(self):
        self.master.after(0, lambda: (
            self.download_btn.config(state="normal"),
            self.pause_btn.config(state="disabled"),
            self.resume_btn.config(state="normal"),
            self.cancel_btn.config(state="normal"),
        ))

    def enable_buttons_for_idle(self):
        self.master.after(0, lambda: (
            self.download_btn.config(state="normal"),
            self.pause_btn.config(state="disabled"),
            self.resume_btn.config(state="disabled"),
            self.cancel_btn.config(state="disabled"),
        ))

    # --------------- Download control ---------------
    def start_download(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a download URL.")
            return

        self.set_status("Resolving URL...")
        self.master.update_idletasks()

        # If this looks like a Pinterest page (or shortener), attempt to extract direct mp4 first
        extracted = None
        try:
            if looks_like_pinterest(url):
                self.set_status("Detected Pinterest link — resolving direct video URL...")
                extracted = extract_pinterest_video_url(self._session, url)
                if extracted:
                    self.set_status(f"Resolved direct video URL: {extracted}")
                else:
                    # show a non-blocking warning but continue attempting original URL
                    self.set_status("Could not automatically extract direct video URL; will try original URL.")
            else:
                # also handle case where user pasted a Pinterest "sharing" short URL
                # we still attempt to extract if redirected to pinterest domain
                try:
                    r = self._session.head(url, allow_redirects=True, timeout=6)
                    if looks_like_pinterest(r.url):
                        self.set_status("Resolved redirect to Pinterest — extracting video URL...")
                        extracted = extract_pinterest_video_url(self._session, r.url)
                        if extracted:
                            self.set_status(f"Resolved direct video URL: {extracted}")
                except Exception:
                    pass
        except Exception as e:
            # extraction failed unexpectedly, but we won't block; fall back to original
            self.set_status(f"Pinterest extraction error: {e}")

        final_url = extracted or url
        self._url = final_url

        chosen = self.path_var.get().strip()
        if chosen:
            out = Path(chosen)
        else:
            guessed = self.url_guess_filename(final_url) or "download"
            out = Path.cwd() / guessed

        # ensure parent exists
        out.parent.mkdir(parents=True, exist_ok=True)

        self._out_path = out
        self._part_path = out.with_suffix(out.suffix + PART_SUFFIX)
        self._meta_path = out.with_suffix(out.suffix + META_SUFFIX)

        # reset flags & state
        self._pause_event.clear()
        self._stop_event.clear()
        self._speed_samples.clear()
        self._last_update = time.time()
        self._downloaded = 0
        self._total_size = 0

        # spawn worker
        self._worker_thread = threading.Thread(target=self._download_worker, daemon=True)
        self._worker_thread.start()
        self.enable_buttons_for_running()
        self.set_status("Starting download...")

    def pause(self):
        if self._worker_thread and self._worker_thread.is_alive():
            self._pause_event.set()
            self.set_status("Paused")
            self.enable_buttons_for_paused()

    def resume(self):
        if not self._worker_thread or not self._worker_thread.is_alive():
            # restart worker to resume
            self._pause_event.clear()
            self._stop_event.clear()
            self._worker_thread = threading.Thread(target=self._download_worker, daemon=True)
            self._worker_thread.start()
        else:
            # just clear pause
            self._pause_event.clear()
        self.set_status("Resuming...")
        self.enable_buttons_for_running()

    def cancel(self):
        if messagebox.askyesno("Cancel download", "Are you sure you want to cancel the current download?"):
            self._stop_event.set()
            self._pause_event.clear()
            self.set_status("Cancelling...")

    # --------------- Worker & logic ---------------
    def _download_worker(self):
        """
        Implements robust resumable download with retries and progress updates.
        """
        url = self._url
        out = Path(self._out_path)
        part = Path(self._part_path)
        meta = Path(self._meta_path)

        # Validate URL and server support with HEAD
        headers = {}
        try:
            head = self._session.head(url, allow_redirects=True, timeout=10)
            head.raise_for_status()
        except Exception as e:
            self.set_status(f"HEAD request failed: {e}")
            self.enable_buttons_for_idle()
            return

        # Check total size
        total = head.headers.get("Content-Length")
        accept_ranges = head.headers.get("Accept-Ranges", "").lower() == "bytes"
        try:
            total_size = int(total) if total is not None else 0
        except Exception:
            total_size = 0

        self._total_size = total_size

        # If .part exists, get its size
        existing = part.stat().st_size if part.exists() else 0
        self._downloaded = existing

        # Save meta info about this download (so user can resume across restarts)
        meta_data = {"url": url, "out": str(out), "total_size": total_size, "part": str(part)}
        try:
            meta.write_text(json.dumps(meta_data))
        except Exception:
            pass

        # If server does not support ranges but we have partial, we must restart
        if existing > 0 and not accept_ranges:
            self.set_status("Server does not support resume. Restarting from scratch.")
            try:
                part.unlink()
                existing = 0
                self._downloaded = 0
            except Exception:
                self.set_status("Cannot remove partial file; aborting.")
                self.enable_buttons_for_idle()
                return

        # If server supports ranges, prepare Range header
        if existing > 0 and accept_ranges:
            headers["Range"] = f"bytes={existing}-"

        # streaming GET with retries
        retries = 0
        backoff = 1.0
        while retries <= MAX_RETRIES and not self._stop_event.is_set():
            try:
                with self._session.get(url, headers=headers, stream=True, timeout=15) as resp:
                    # Accept both 200 (new) and 206 (partial)
                    if resp.status_code not in (200, 206):
                        raise RuntimeError(f"Unexpected HTTP status: {resp.status_code}")

                    # If total unknown, try to deduce from headers now
                    cl = resp.headers.get("Content-Length")
                    if cl is not None:
                        try:
                            content_len = int(cl)
                        except Exception:
                            content_len = 0
                    else:
                        content_len = 0

                    # Compute final total size if possible:
                    if headers.get("Range"):
                        if content_len and existing:
                            self._total_size = existing + content_len
                        elif self._total_size == 0:
                            self._total_size = existing + content_len
                    else:
                        if content_len:
                            self._total_size = content_len

                    mode = "ab" if existing and accept_ranges else "wb"

                    start_time = time.time()
                    last_report = start_time
                    with open(part, mode) as f:
                        for chunk in resp.iter_content(chunk_size=CHUNK_SIZE):
                            # handle stop/cancel
                            if self._stop_event.is_set():
                                self.set_status("Cancelled")
                                self.enable_buttons_for_idle()
                                return

                            # handle pause
                            while self._pause_event.is_set():
                                time.sleep(0.2)
                                if self._stop_event.is_set():
                                    self.set_status("Cancelled")
                                    self.enable_buttons_for_idle()
                                    return

                            if not chunk:
                                continue
                            f.write(chunk)
                            f.flush()
                            os.fsync(f.fileno())

                            # update counters
                            n = len(chunk)
                            self._downloaded += n
                            now = time.time()
                            # record sample (bytes, timestamp) and compute smoothed speed
                            self._speed_samples.append((n, now))
                            cutoff = now - SPEED_SAMPLES
                            while self._speed_samples and self._speed_samples[0][1] < cutoff:
                                self._speed_samples.popleft()

                            total_bytes = sum(x[0] for x in self._speed_samples)
                            time_span = max(1e-6, (self._speed_samples[-1][1] - self._speed_samples[0][1]) if len(self._speed_samples) > 1 else 1.0)
                            speed_bps = total_bytes / time_span

                            percent = 0.0
                            if self._total_size and self._total_size > 0:
                                percent = (self._downloaded / self._total_size) * 100.0
                                if percent > 100.0:
                                    percent = 100.0

                            eta = None
                            if speed_bps > 0 and self._total_size and self._total_size > self._downloaded:
                                eta = (self._total_size - self._downloaded) / speed_bps

                            if now - last_report >= 0.25:
                                last_report = now
                                self._ui_update(percent, speed_bps, eta)

                    # finished streaming loop
                    if self._total_size and part.exists() and part.stat().st_size >= self._total_size:
                        try:
                            part.replace(out)
                        except Exception:
                            try:
                                part.rename(out)
                            except Exception as e:
                                self.set_status(f"Finished but could not rename file: {e}")
                                self.enable_buttons_for_idle()
                                return
                        try:
                            if meta.exists():
                                meta.unlink()
                        except Exception:
                            pass

                        self._ui_update(100.0, 0.0, 0.0)
                        self.set_status(f"Completed: {out.name}")
                        self.enable_buttons_for_idle()
                        return
                    else:
                        # no content-length known -> assume complete
                        if not resp.headers.get("Content-Length"):
                            try:
                                part.replace(out)
                            except Exception:
                                try:
                                    part.rename(out)
                                except Exception:
                                    self.set_status("Download completed but rename failed")
                                    self.enable_buttons_for_idle()
                                    return
                            self.set_status(f"Completed (size unknown): {out.name}")
                            self.enable_buttons_for_idle()
                            return

                break

            except Exception as e:
                retries += 1
                if retries > MAX_RETRIES:
                    self.set_status(f"Download failed after {MAX_RETRIES} retries: {e}")
                    self.enable_buttons_for_idle()
                    return
                else:
                    self.set_status(f"Error: {e} — retrying ({retries}/{MAX_RETRIES}) in {backoff:.1f}s")
                    time.sleep(backoff)
                    backoff *= RETRY_BACKOFF_FACTOR
                    if part.exists():
                        existing = part.stat().st_size
                        self._downloaded = existing
                        if accept_ranges:
                            headers["Range"] = f"bytes={existing}-"
                    continue

        if self._stop_event.is_set():
            self.set_status("Cancelled")
            self.enable_buttons_for_idle()
        else:
            if out.exists():
                self.set_status(f"Finished: {out.name}")
            else:
                self.set_status("Stopped")
            self.enable_buttons_for_idle()

    def _ui_update(self, percent, speed_bps, eta):
        speed_str = self._human_size(speed_bps) + "/s"
        eta_str = self._human_time(eta) if eta else "--:--:--"
        downloaded_str = self._human_size(self._downloaded)
        total_str = self._human_size(self._total_size) if self._total_size else "Unknown"
        status_text = f"{percent:.2f}% — {downloaded_str} / {total_str} — {speed_str} — ETA {eta_str}"
        self.set_status(status_text)
        self.set_progress(percent)

    # --------------- Utilities ---------------
    @staticmethod
    def url_guess_filename(url):
        try:
            from urllib.parse import urlsplit, unquote
            u = urlsplit(url)
            name = os.path.basename(unquote(u.path)) or None
            # ensure ends with .mp4 if pinterest resolved and filename contains mp4 token
            if name and not name.strip():
                return None
            return name
        except Exception:
            return None

    @staticmethod
    def _human_size(n):
        try:
            n = float(n)
        except Exception:
            return "0 B"
        if math.isnan(n) or n < 0:
            return "0 B"
        units = ["B", "KB", "MB", "GB", "TB"]
        i = 0
        while n >= 1024.0 and i < len(units) - 1:
            n /= 1024.0
            i += 1
        return f"{n:0.2f} {units[i]}"

    @staticmethod
    def _human_time(seconds):
        try:
            s = int(max(0, seconds))
        except Exception:
            return "--:--:--"
        h = s // 3600
        m = (s % 3600) // 60
        sec = s % 60
        return f"{h:02d}:{m:02d}:{sec:02d}"

    def _on_close(self):
        if self._worker_thread and self._worker_thread.is_alive():
            if messagebox.askyesno("Exit", "A download is in progress. Exit and cancel download?"):
                self._stop_event.set()
                self._pause_event.clear()
                time.sleep(0.2)
                self.master.destroy()
        else:
            self.master.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("720x260")
    app = EnhancedDownloader(root)
    root.mainloop()

