#!/usr/bin/env python3
"""
Modern Downloader with yt-dlp support - Enhanced Version
Supports: YouTube, Facebook, Instagram, Pinterest, Twitter, TikTok, and 1000+ other sites
"""

import os
import json
import time
import threading
import logging
from pathlib import Path
from urllib.parse import urlparse
import tkinter as tk
from tkinter import ttk
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from ttkbootstrap.dialogs import Messagebox
import yt_dlp
from PIL import Image, ImageTk, ImageSequence
import requests
from io import BytesIO

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
def center_window(window, width=900, height=600):
    """Center the window on the screen."""
    window.update_idletasks()  # Ensure correct screen size info
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = (screen_width // 2) - (width // 2)
    y = (screen_height // 2) - (height // 2)
    window.geometry(f"{width}x{height}+{x}+{y}")

class ModernDownloader:
    def __init__(self, master):
        self.master = master
        master.title("Universal Video Downloader")
        #master.geometry("900x600")
        center_window(master, 1000, 695)
        # Configure grid
        master.columnconfigure(0, weight=1)
        master.rowconfigure(1, weight=1)
        
        # Title
        title_frame = tb.Frame(master)
        title_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        title_frame.columnconfigure(0, weight=1)
        
        tb.Label(title_frame, text="Universal Video Downloader", 
                font=("Helvetica", 16, "bold"), bootstyle="success").grid(row=0, column=0)
        
        # Main content frame
        main_frame = tb.Frame(master)
        main_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        # URL input
        url_frame = tb.Frame(main_frame)
        url_frame.grid(row=0, column=0, sticky="ew", pady=5)
        url_frame.columnconfigure(1, weight=1)
        
        tb.Label(url_frame, text="Video URL:", font=("Helvetica", 15, "bold")).grid(row=0, column=0, sticky="w", padx=5)
        self.url_var = tb.StringVar()
        self.url_entry = tb.Entry(url_frame, textvariable=self.url_var, width=70)
        self.url_entry.grid(row=0, column=1, sticky="ew", padx=5)
        
        # Fetch info button
        self.fetch_btn = tb.Button(url_frame, text="Fetch Info", command=self.fetch_video_info, 
                                  bootstyle="primary")
        self.fetch_btn.grid(row=0, column=2, padx=5)
        
        # Video info frame
        self.info_frame = tb.Frame(main_frame)
        self.info_frame.grid(row=1, column=0, sticky="nsew", pady=5)
        self.info_frame.columnconfigure(0, weight=1)
        self.info_frame.rowconfigure(0, weight=2)
        self.info_frame.rowconfigure(0, weight=2)
        
        # Thumbnail
        self.thumbnail_label = tb.Label(self.info_frame, text="Thumbnail will be displayed here", anchor="center")
        self.thumbnail_label.grid(row=0, column=0, sticky="nsew", pady=10)
        
        # Video info text
        info_container = tb.Frame(self.info_frame)
        info_container.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        info_container.columnconfigure(0, weight=1)
        info_container.rowconfigure(0, weight=1)
        
        self.info_text = tb.Text(info_container, height=8, width=60)
        self.info_text.grid(row=0, column=0, sticky="nsew")
        
        # Scrollbar for info text
        scrollbar = tb.Scrollbar(self.info_frame, orient="vertical", command=self.info_text.yview)
        scrollbar.grid(row=1, column=1, sticky="ns")
        self.info_text.configure(yscrollcommand=scrollbar.set)
        
        # Loading overlay for just the info frame
        self.overlay_frame = tb.Frame(self.info_frame)
        self.overlay_frame.grid(row=0, column=0, rowspan=2, sticky="nsew")
        self.overlay_frame.columnconfigure(0, weight=1)
        self.overlay_frame.rowconfigure(0, weight=1)
        self.overlay_frame.grid_remove()  # Hide initially
        
        # Centered spinner label
        self.central_spinner = tb.Label(self.overlay_frame, text="", anchor="center")
        self.central_spinner.grid(row=0, column=0, sticky="")
        
        # Download options frame
        options_frame = tb.Frame(main_frame)
        options_frame.grid(row=2, column=0, sticky="ew", pady=5)
        options_frame.columnconfigure(1, weight=1)
        
        tb.Label(options_frame, text="Filename:").grid(row=0, column=0, sticky="w", padx=5)
        self.filename_var = tb.StringVar(value="video")
        self.filename_entry = tb.Entry(options_frame, textvariable=self.filename_var)
        self.filename_entry.grid(row=0, column=1, sticky="ew", padx=5)
        
        tb.Label(options_frame, text="Format:").grid(row=1, column=0, sticky="w", padx=5)
        self.format_var = tb.StringVar(value="best")
        format_combo = tb.Combobox(options_frame, textvariable=self.format_var, 
                                  values=["best", "worst", "bestvideo", "bestaudio", "mp4", "webm"])
        format_combo.grid(row=1, column=1, sticky="w", padx=5)
        
        # Progress area
        progress_frame = tb.Frame(main_frame)
        progress_frame.grid(row=3, column=0, sticky="ew", pady=5)
        progress_frame.columnconfigure(0, weight=1)
        
        self.progress = tb.Progressbar(progress_frame, bootstyle="success-striped", maximum=100)
        self.progress.grid(row=0, column=0, sticky="ew", padx=5)
        
        self.status_var = tb.StringVar(value="Ready")
        status_label = tb.Label(progress_frame, textvariable=self.status_var)
        status_label.grid(row=1, column=0, sticky="w", padx=5)
        
        # Buttons frame
        buttons_frame = tb.Frame(main_frame)
        buttons_frame.grid(row=4, column=0, sticky="ew", pady=10)
        
        self.download_btn = tb.Button(buttons_frame, text="Download", command=self.start_download, 
                                     bootstyle="success", state="disabled")
        self.download_btn.pack(side="left", padx=5)
        
        self.pause_btn = tb.Button(buttons_frame, text="Pause", command=self.pause_download, 
                                  bootstyle="warning", state="disabled")
        self.pause_btn.pack(side="left", padx=5)
        
        self.resume_btn = tb.Button(buttons_frame, text="Resume", command=self.resume_download, 
                                   bootstyle="info", state="disabled")
        self.resume_btn.pack(side="left", padx=5)
        
        self.cancel_btn = tb.Button(buttons_frame, text="Cancel", command=self.cancel_download, 
                                   bootstyle="danger", state="disabled")
        self.cancel_btn.pack(side="left", padx=5)
        
        # Initialize variables
        self.video_info = None
        self.download_thread = None
        self.pause_event = threading.Event()
        self.stop_event = threading.Event()
        self.downloading = False
        self.ydl = None  # yt-dlp instance
        
        # Load spinner GIF
        self.spinner_frames = []
        self.spinner_index = 0
        self.spinner_animation_id = None
        self.load_spinner_gif()
        
        # Centered footer with red hearts
        footer_frame = tb.Frame(master)
        footer_frame.grid(row=2, column=0, sticky="ew", pady=10)
        footer_frame.columnconfigure(0, weight=1)
        
        # Create the footer text with two red hearts
        tb.Label(footer_frame, 
                text="Supports: Pinterest, Youtube, Facebook, Instagram, Twitter, TikTok, and 1000+ other sites  -   Made with ❤️ by Walid Lamraoui.", 
                font=("Helvetica", 9), bootstyle="light").grid(row=0, column=0, sticky="ew")
        
        # Center the footer content
        footer_frame.columnconfigure(0, weight=1)
        
        # Bind Enter key to fetch info
        self.master.bind('<Return>', lambda event: self.fetch_video_info())
    
    def load_spinner_gif(self):
        """Load the spinner GIF from the same directory as the script"""
        try:
            # Try to load the spinner.gif from the same directory
            script_dir = os.path.dirname(os.path.abspath(__file__))
            gif_path = os.path.join(script_dir, "spinner.gif")
            
            if os.path.exists(gif_path):
                gif = Image.open(gif_path)
                for frame in ImageSequence.Iterator(gif):
                    frame = frame.copy()
                    # Resize to a reasonable size
                    frame.thumbnail((50, 50), Image.Resampling.LANCZOS)
                    self.spinner_frames.append(ImageTk.PhotoImage(frame))
            else:
                # Fallback to text spinner if GIF not found
                logger.warning("spinner.gif not found in script directory. Using text spinner.")
                self.spinner_frames = None
        except Exception as e:
            logger.error(f"Error loading spinner GIF: {e}")
            self.spinner_frames = None
    
    def show_loading_overlay(self):
        """Show the loading overlay over just the info frame"""
        self.overlay_frame.grid()
        self.overlay_frame.lift()  # Bring to front
        
        if self.spinner_frames:
            self.central_spinner.configure(image=self.spinner_frames[0])
        else:
            self.central_spinner.configure(text="🔄 Loading...")
        
        # Start animation
        self.animate_spinner()
    
    def hide_loading_overlay(self):
        """Hide the loading overlay"""
        self.overlay_frame.grid_remove()
        self.stop_animation()
    
    def animate_spinner(self):
        """Animate the spinner GIF"""
        if self.spinner_frames:
            self.spinner_index = (self.spinner_index + 1) % len(self.spinner_frames)
            self.central_spinner.configure(image=self.spinner_frames[self.spinner_index])
            self.spinner_animation_id = self.master.after(50, self.animate_spinner)
        else:
            # Fallback to text animation
            current_text = self.central_spinner.cget("text")
            if current_text == "🔄 Loading...":
                self.central_spinner.configure(text="🔄 Loading..")
            elif current_text == "🔄 Loading..":
                self.central_spinner.configure(text="🔄 Loading.")
            else:
                self.central_spinner.configure(text="🔄 Loading...")
            self.spinner_animation_id = self.master.after(300, self.animate_spinner)
    
    def stop_animation(self):
        """Stop the spinner animation"""
        if self.spinner_animation_id:
            self.master.after_cancel(self.spinner_animation_id)
            self.spinner_animation_id = None
    
    def fetch_video_info(self):
        url = self.url_var.get().strip()
        if not url:
            Messagebox.show_error("Please enter a URL", "Error", parent=self.master
            
            )
            return
            
        self.fetch_btn.config(state="disabled")
        self.status_var.set("Fetching video info...")
        
        # Show loading overlay over just the info frame
        self.show_loading_overlay()
        
        # Clear previous thumbnail and info
        self.thumbnail_label.config(image="", text="")
        self.info_text.delete(1.0, tk.END)
        
        # Run in thread to avoid blocking UI
        thread = threading.Thread(target=self._fetch_info_thread, args=(url,), daemon=True)
        thread.start()
        
    def _fetch_info_thread(self, url):
        try:
            ydl_opts = {
                'quiet': True,
                'no_warnings': True,
                'skip_download': True,
                'socket_timeout': 9999,  # Increased timeout for slow connections
                'extract_flat': False,
            }
            
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(url, download=False)
                self.video_info = info
                
                # Update UI in main thread
                self.master.after(0, self._update_video_info, info)
                
        except Exception as e:
            error_msg = f"Error fetching video info: {str(e)}"
            logger.error(error_msg)
            self.master.after(0, Messagebox.show_error, error_msg, "Error", parent=self.master)
            self.master.after(0, lambda: self.fetch_btn.config(state="normal"))
            self.master.after(0, lambda: self.status_var.set("Ready"))
            self.master.after(0, self.hide_loading_overlay)
    
    def _update_video_info(self, info):
        # Hide loading overlay
        self.hide_loading_overlay()
        
        # Update thumbnail
        try:
            thumbnail_url = info.get('thumbnail', '')
            if thumbnail_url:
                # Use a thread to fetch thumbnail to avoid blocking UI
                threading.Thread(target=self._load_thumbnail, args=(thumbnail_url,), daemon=True).start()
            else:
                self.thumbnail_label.config(text="Thumbnail not available")
        except Exception as e:
            self.thumbnail_label.config(text="Thumbnail not available")
            logger.error(f"Error loading thumbnail: {e}")
        
        # Update info text
        info_text = f"Title: {info.get('title', 'N/A')}\n"
        info_text += f"Duration: {info.get('duration', 'N/A')} seconds\n"
        info_text += f"Uploader: {info.get('uploader', 'N/A')}\n"
        info_text += f"View count: {info.get('view_count', 'N/A')}\n"
        info_text += f"Formats available: {len(info.get('formats', []))}\n"
        
        # Set default filename to video title
        title = info.get('title', 'video')
        # Remove invalid characters for filename
        safe_title = "".join(c for c in title if c.isalnum() or c in (' ', '-', '_')).rstrip()
        self.filename_var.set(safe_title[:50])  # Limit length
        
        self.info_text.delete(1.0, tk.END)
        self.info_text.insert(1.0, info_text)
        
        # Enable download button
        self.download_btn.config(state="normal")
        self.fetch_btn.config(state="normal")
        self.status_var.set("Ready to download")
    
    def _load_thumbnail(self, thumbnail_url):
        try:
            response = requests.get(thumbnail_url, timeout=10)
            img_data = response.content
            img = Image.open(BytesIO(img_data))
            # Make thumbnail larger (increased size)
            img.thumbnail((480, 270), Image.Resampling.LANCZOS)
            photo = ImageTk.PhotoImage(img)
            self.master.after(0, lambda: self.thumbnail_label.config(image=photo, text=""))
            self.master.after(0, lambda: setattr(self.thumbnail_label, "image", photo))  # Keep reference
        except Exception as e:
            self.master.after(0, lambda: self.thumbnail_label.config(text="Thumbnail not available"))
            logger.error(f"Error loading thumbnail: {e}")
    
    def start_download(self):
        if not self.video_info:
            Messagebox.show_error("Please fetch video info first", "Error", parent=self.master)
            return
            
        self.downloading = True
        self.stop_event.clear()
        self.pause_event.clear()
        
        self.download_btn.config(state="disabled")
        self.pause_btn.config(state="normal")
        self.cancel_btn.config(state="normal")
        self.fetch_btn.config(state="disabled")
        
        # Get download path
        download_path = os.path.join(os.path.expanduser("~"), "Downloads")
        filename = self.filename_var.get().strip() or "video"
        format_type = self.format_var.get()
        
        # Start download thread
        self.download_thread = threading.Thread(
            target=self._download_thread, 
            args=(self.video_info['webpage_url'], download_path, filename, format_type),
            daemon=True
        )
        self.download_thread.start()
    
    def _get_ydl_options(self, download_path, filename, format_type):
        # Optimized for all connection types with auto-detection
        return {
            'outtmpl': os.path.join(download_path, f'{filename}.%(ext)s'),
            'format': format_type,
            'noprogress': False,
            'continuedl': True,  # Enable resume
            'quiet': True,
            'no_warnings': False,
            'progress_hooks': [self._progress_hook],
            'socket_timeout': 9999,
            'retries': 9999,  # Increased retries for slow connections
            'buffersize': 1024 * 128,  # Balanced buffer size
            'http_chunk_size': 1024 * 512,  # Balanced chunk size
            'fragment_retries': 25,  # Retries for fragments
        }
    
    def _download_thread(self, url, download_path, filename, format_type):
        ydl_opts = self._get_ydl_options(download_path, filename, format_type)
        
        try:
            self.ydl = yt_dlp.YoutubeDL(ydl_opts)
            # Check if we need to resume
            temp_files = [f for f in os.listdir(download_path) if f.startswith(f'{filename}.') and f.endswith('.part')]
            
            if temp_files and not self.stop_event.is_set():
                self.master.after(0, lambda: self.status_var.set("Resuming download..."))
            
            self.ydl.download([url])
            
            if not self.stop_event.is_set():
                self.master.after(0, self._download_completed)
            
        except Exception as e:
            if not self.stop_event.is_set():
                error_msg = f"Download error: {str(e)}"
                logger.error(error_msg)
                self.master.after(0, Messagebox.show_error, error_msg, "Error", parent=self.master)
                self.master.after(0, self._reset_ui)
    
    def _progress_hook(self, d):
        if self.stop_event.is_set():
            # Clean up and exit if download was cancelled
            try:
                if self.ydl:
                    self.ydl.ydl_opts['noprogress'] = True
            except:
                pass
            raise yt_dlp.DownloadError("Download cancelled by user")
            
        if d['status'] == 'downloading':
            # Pause if requested
            while self.pause_event.is_set() and not self.stop_event.is_set():
                time.sleep(0.5)
                
            if self.stop_event.is_set():
                raise yt_dlp.DownloadError("Download cancelled by user")
                
            # Update progress
            if d.get('total_bytes'):
                percent = d.get('downloaded_bytes', 0) / d.get('total_bytes', 1) * 100
            elif d.get('total_bytes_estimate'):
                percent = d.get('downloaded_bytes', 0) / d.get('total_bytes_estimate', 1) * 100
            else:
                percent = 0
                
            speed = d.get('speed', 0)
            eta = d.get('eta', 0)
            
            self.master.after(0, self._update_progress, percent, speed, eta)
    
    def _update_progress(self, percent, speed, eta):
        self.progress['value'] = percent
        speed_str = f"{speed / 1024 / 1024:.3f} MB/s" if speed else "N/A"
        eta_str = time.strftime("%H:%M:%S", time.gmtime(eta)) if eta else "N/A"
        self.status_var.set(f"Downloading: {percent:.1f}% | Speed: {speed_str} | ETA: {eta_str}")
    
    def _download_completed(self):
        self.status_var.set("Download completed!")
        Messagebox.show_info("Download completed successfully!", "Success", parent=self.master)
        self._reset_ui()
    
    def pause_download(self):
        self.pause_event.set()
        self.pause_btn.config(state="disabled")
        self.resume_btn.config(state="normal")
        self.status_var.set("Download paused")
    
    def resume_download(self):
        self.pause_event.clear()
        self.pause_btn.config(state="normal")
        self.resume_btn.config(state="disabled")
        self.status_var.set("Resuming download...")
    
    def cancel_download(self):
        self.stop_event.set()
        self.pause_event.clear()
        self.status_var.set("Cancelling download...")
        
        # Try to force yt-dlp to stop
        try:
            if self.ydl:
                # This will force yt-dlp to stop on the next progress hook check
                self.ydl.ydl_opts['noprogress'] = True
        except:
            pass
            
        # Wait a moment for the download thread to terminate
        self.master.after(100, self._download_cancelled)
    
    def _download_cancelled(self):
        self.status_var.set("Download cancelled")
        Messagebox.show_info("Download was cancelled", "Cancelled", parent=self.master)
        self._reset_ui()
    
    def _reset_ui(self):
        self.downloading = False
        self.download_btn.config(state="normal" if self.video_info else "disabled")
        self.pause_btn.config(state="disabled")
        self.resume_btn.config(state="disabled")
        self.cancel_btn.config(state="disabled")
        self.fetch_btn.config(state="normal")
        self.progress['value'] = 0
        self.ydl = None

if __name__ == "__main__":
    root = tb.Window(themename="darkly") 
    app = ModernDownloader(root)
    root.mainloop()
