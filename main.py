import os
import sys
import time
import json
import queue
import logging
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

# Add the current directory to path to import scraper
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from scraper import SplusScraper, SplusAuth
except ImportError:
    messagebox.showerror("Import Error", "Could not import SplusScraper. Make sure scraper.py is in the same directory.")
    sys.exit(1)

class GUIHandler(logging.Handler):
    def __init__(self, gui_app):
        super().__init__()
        self.gui_app = gui_app
        
    def emit(self, record):
        log_entry = self.format(record)
        self.gui_app.log_message(log_entry)

class SplusScraperGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Splus Scraper")
        self.root.geometry("750x800")
        self.root.resizable(True, True)
        
        self.scraper = None
        self.auth = SplusAuth(debug=True)
        self.is_running = False
        self.login_window = None
        self.processed_chats = 0  
        
        # Setup logging queue
        self.log_queue = queue.Queue()
        self.setup_logging()
        self.setup_ui()
        
    def setup_logging(self):
        """Setup logging to redirect to GUI"""
        # Remove existing handlers
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
            
        # Create GUI handler
        gui_handler = GUIHandler(self)
        gui_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        gui_handler.setFormatter(formatter)
        
        # Add handler to root logger
        logging.root.addHandler(gui_handler)
        logging.root.setLevel(logging.INFO)
        
    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="Splus Scraper", font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Authentication section
        auth_frame = ttk.LabelFrame(main_frame, text="Authentication", padding="5")
        auth_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        auth_frame.columnconfigure(1, weight=1)
        
        ttk.Label(auth_frame, text="Status:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.auth_status_var = tk.StringVar(value="Not authenticated")
        ttk.Label(auth_frame, textvariable=self.auth_status_var).grid(row=0, column=1, sticky=tk.W, pady=2)
        
        auth_button_frame = ttk.Frame(auth_frame)
        auth_button_frame.grid(row=1, column=0, columnspan=2, pady=5)
        
        self.login_button = ttk.Button(auth_button_frame, text="Manual Login", command=self.start_manual_login)
        self.login_button.pack(side=tk.LEFT, padx=5)
        
        self.check_auth_button = ttk.Button(auth_button_frame, text="Check Authentication", command=self.check_authentication)
        self.check_auth_button.pack(side=tk.LEFT, padx=5)
        
        # Scraping settings
        settings_frame = ttk.LabelFrame(main_frame, text="Scraping Settings", padding="5")
        settings_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        settings_frame.columnconfigure(1, weight=1)
        
        # Debug mode
        ttk.Label(settings_frame, text="Debug mode:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.debug_var = tk.BooleanVar(value=False)
        debug_check = ttk.Checkbutton(settings_frame, variable=self.debug_var)
        debug_check.grid(row=0, column=1, sticky=tk.W, pady=5)
        
        # Max messages input
        ttk.Label(settings_frame, text="Max messages per chat (0 for unlimited):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.max_messages_var = tk.StringVar(value="0")
        max_messages_entry = ttk.Entry(settings_frame, textvariable=self.max_messages_var, width=10)
        max_messages_entry.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        # Tab selection
        ttk.Label(settings_frame, text="Chat type:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.tab_var = tk.StringVar(value="1")
        tab_frame = ttk.Frame(settings_frame)
        tab_frame.grid(row=2, column=1, sticky=tk.W, pady=5)
        
        ttk.Radiobutton(tab_frame, text="All", variable=self.tab_var, value="1").pack(side=tk.LEFT)
        ttk.Radiobutton(tab_frame, text="Private", variable=self.tab_var, value="2").pack(side=tk.LEFT)
        ttk.Radiobutton(tab_frame, text="Groups", variable=self.tab_var, value="3").pack(side=tk.LEFT)
        ttk.Radiobutton(tab_frame, text="Channels", variable=self.tab_var, value="4").pack(side=tk.LEFT)
        
        # Download options
        ttk.Label(settings_frame, text="Download options:").grid(row=3, column=0, sticky=tk.W, pady=5)
        options_frame = ttk.Frame(settings_frame)
        options_frame.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=5)
        
        self.sticker_var = tk.BooleanVar(value=True)
        self.file_var = tk.BooleanVar(value=True)
        self.video_var = tk.BooleanVar(value=True)
        self.image_var = tk.BooleanVar(value=True)
        self.audio_var = tk.BooleanVar(value=True)
        self.album_var = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(options_frame, text="Stickers", variable=self.sticker_var).grid(row=0, column=0, sticky=tk.W)
        ttk.Checkbutton(options_frame, text="Files", variable=self.file_var).grid(row=0, column=1, sticky=tk.W)
        ttk.Checkbutton(options_frame, text="Videos", variable=self.video_var).grid(row=1, column=0, sticky=tk.W)
        ttk.Checkbutton(options_frame, text="Images", variable=self.image_var).grid(row=1, column=1, sticky=tk.W)
        ttk.Checkbutton(options_frame, text="Audio", variable=self.audio_var).grid(row=2, column=0, sticky=tk.W)
        ttk.Checkbutton(options_frame, text="Albums", variable=self.album_var).grid(row=2, column=1, sticky=tk.W)
        
        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=2, pady=10)
        
        self.start_button = ttk.Button(button_frame, text="Start Scraping", command=self.start_scraping, state=tk.DISABLED)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="Stop", command=self.stop_scraping, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        # Status and progress
        status_frame = ttk.Frame(main_frame)
        status_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(status_frame, text="Status:").pack(side=tk.LEFT)
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(status_frame, textvariable=self.status_var).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(status_frame, text="Progress:").pack(side=tk.LEFT, padx=(20, 0))
        self.progress_var = tk.StringVar(value="0 chats processed")
        ttk.Label(status_frame, textvariable=self.progress_var).pack(side=tk.LEFT, padx=5)
        
        # Log output
        ttk.Label(main_frame, text="Log:").grid(row=6, column=0, sticky=tk.NW, pady=5)
        self.log_text = scrolledtext.ScrolledText(main_frame, width=85, height=20, state=tk.DISABLED)
        self.log_text.grid(row=7, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Configure row/column weights for proper resizing
        main_frame.rowconfigure(7, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Check initial authentication status
        self.root.after(100, self.check_authentication)
        
    def log_message(self, message):
        """Add a message to the log text area"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
        
    def check_authentication(self):
        """Check if user is already authenticated"""
        try:
            tokens = self.auth.get_tokens()
            if tokens and tokens.get('dc2_auth_key'):
                self.auth_status_var.set("Authenticated ✓")
                self.start_button.config(state=tk.NORMAL)
                logging.info("Authentication: Valid tokens found in database")
                return True
            else:
                self.auth_status_var.set("Not authenticated")
                self.start_button.config(state=tk.DISABLED)
                logging.info("Authentication: No valid tokens found")
                return False
        except Exception as e:
            self.auth_status_var.set("Error checking authentication")
            logging.error(f"Authentication error: {str(e)}")
            return False
    
    def start_manual_login(self):
        """Start manual login process"""
        self.login_button.config(state=tk.DISABLED)
        self.auth_status_var.set("Starting manual login...")
        
        # Create login confirmation window
        self.create_login_window()
        
        # Start login process in background
        thread = threading.Thread(target=self._perform_manual_login, daemon=True)
        thread.start()
    
    def create_login_window(self):
        """Create login confirmation window"""
        if self.login_window and self.login_window.winfo_exists():
            self.login_window.destroy()
        
        self.login_window = tk.Toplevel(self.root)
        self.login_window.title("Manual Login")
        self.login_window.geometry("500x300")
        self.login_window.resizable(False, False)
        self.login_window.transient(self.root)
        self.login_window.grab_set()
        
        # Center the window
        self.login_window.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - self.login_window.winfo_width()) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - self.login_window.winfo_height()) // 2
        self.login_window.geometry(f"+{x}+{y}")
        
        # Instructions
        instructions = tk.Label(self.login_window, text="Manual Login Instructions", font=("Arial", 14, "bold"))
        instructions.pack(pady=10)
        
        instruction_text = """
1. A browser window will open automatically
2. Login to your Splus.ir account
3. Wait until you see the main Splus.ir page
4. Click the 'Confirm Login' button below

Note: Do not close the browser window until you confirm login!
        """
        
        text_widget = tk.Text(self.login_window, height=8, width=50, wrap=tk.WORD)
        text_widget.insert(tk.END, instruction_text)
        text_widget.config(state=tk.DISABLED)
        text_widget.pack(pady=10, padx=20)
        
        # Confirm button
        confirm_frame = ttk.Frame(self.login_window)
        confirm_frame.pack(pady=10)
        
        self.confirm_button = ttk.Button(confirm_frame, text="Confirm Login", 
                                       command=self.confirm_login, state=tk.DISABLED)
        self.confirm_button.pack(side=tk.LEFT, padx=5)
        
        cancel_button = ttk.Button(confirm_frame, text="Cancel", command=self.cancel_login)
        cancel_button.pack(side=tk.LEFT, padx=5)
        
        # Countdown
        self.countdown_var = tk.StringVar(value="Waiting for browser...")
        countdown_label = ttk.Label(self.login_window, textvariable=self.countdown_var)
        countdown_label.pack(pady=5)
    
    def _perform_manual_login(self):
        """Perform the manual login process in background"""
        try:
            logging.info("Starting manual login process...")
            
            # Initialize driver and open browser
            self.auth.init_driver()
            self.auth.driver.get("https://web.splus.ir/")
            
            # Enable confirm button after a short delay
            self.root.after(3000, lambda: self.confirm_button.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.countdown_var.set("Browser opened! Login and then click Confirm Login"))
            
            logging.info("Browser window opened. Please login to Splus.ir")
            
        except Exception as e:
            logging.error(f"Error opening browser: {str(e)}")
            self.root.after(0, lambda: self.auth_status_var.set("Browser error"))
            self.root.after(0, lambda: self.login_button.config(state=tk.NORMAL))
            if self.login_window:
                self.root.after(0, self.login_window.destroy)
    
    def confirm_login(self):
        """Confirm that login is complete and extract tokens"""
        try:
            self.confirm_button.config(state=tk.DISABLED)
            self.countdown_var.set("Extracting tokens...")
            
            # Extract tokens from localStorage
            tokens = {}
            tokens['dc2_auth_key'] = self.auth.driver.execute_script("return localStorage.getItem('dc2_auth_key')")
            tokens['dc2_auth_key_bc'] = self.auth.driver.execute_script("return localStorage.getItem('dc2_auth_key_bc')")
            tokens['dc2_hash'] = self.auth.driver.execute_script("return localStorage.getItem('dc2_hash')")
            tokens['server_salt'] = self.auth.driver.execute_script("return localStorage.getItem('server_salt')")

            
            user_auth = json.loads(self.auth.driver.execute_script("return localStorage.getItem('user_auth')") or "{}")
            tokens.update({
                'user_id': user_auth.get('id'),
                'dc_id': user_auth.get('dcID')
            })
            
            if tokens and tokens.get('dc2_auth_key'):
                self.auth.save_tokens(tokens)
                self.auth.close_driver()
                
                self.root.after(0, lambda: self.auth_status_var.set("Login successful! ✓"))
                self.root.after(0, lambda: self.start_button.config(state=tk.NORMAL))
                logging.info("Manual login successful! Tokens saved.")
                
                if self.login_window:
                    self.root.after(0, self.login_window.destroy)
                
                messagebox.showinfo("Success", "Login successful! You can now start scraping.")
            else:
                logging.error("Login failed: No valid tokens found")
                messagebox.showerror("Error", "No valid tokens found. Please make sure you logged in correctly.")
                
        except Exception as e:
            logging.error(f"Error confirming login: {str(e)}")
            messagebox.showerror("Error", f"Login confirmation failed: {str(e)}")
        finally:
            self.root.after(0, lambda: self.login_button.config(state=tk.NORMAL))
    
    def cancel_login(self):
        """Cancel the login process"""
        try:
            self.auth.close_driver()
        except Exception as e:
            # Closing an already-dead driver is expected during cancellation.
            logging.debug("Driver close during cancel did not complete: %s", e)
        
        if self.login_window:
            self.login_window.destroy()
        
        self.auth_status_var.set("Login cancelled")
        self.login_button.config(state=tk.NORMAL)
        logging.info("Manual login cancelled")
    
    def start_scraping(self):
        """Start the scraping process in a separate thread"""
        # Check authentication first
        if not self.check_authentication():
            messagebox.showwarning("Authentication Required", 
                                 "You need to authenticate first. Please use the Manual Login button.")
            return
            
        try:
            max_messages = int(self.max_messages_var.get())
            if max_messages < 0:
                max_messages = 0
        except ValueError:
            messagebox.showerror("Input Error", "Please enter a valid number for max messages")
            return
            
        # Get download settings
        download_settings = {
            'sticker': self.sticker_var.get(),
            'file': self.file_var.get(),
            'video': self.video_var.get(),
            'image': self.image_var.get(),
            'audio': self.audio_var.get(),
            'album': self.album_var.get(),
        }
        
        tab = self.tab_var.get()
        debug_mode = self.debug_var.get()
        
        # Reset progress counter
        self.processed_chats = 0
        self.update_progress()
        
        # Update UI
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_var.set("Initializing...")
        self.is_running = True
        
        # Start scraping in a separate thread
        thread = threading.Thread(
            target=self.run_scraper,
            args=(max_messages, tab, download_settings, debug_mode),
            daemon=True
        )
        thread.start()
        
    def update_progress(self):
        """Update the progress display"""
        self.progress_var.set(f"{self.processed_chats} chats processed")
        
    def increment_progress(self):
        """Increment the progress counter"""
        self.processed_chats += 1
        self.update_progress()
        
    def stop_scraping(self):
        """Stop the scraping process"""
        self.is_running = False
        self.status_var.set("Stopping...")
        if self.scraper:
            try:
                self.scraper.close_driver()
            except Exception as e:
                logging.debug("Driver close during stop did not complete: %s", e)
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_var.set("Stopped")
        
    def run_scraper(self, max_messages, tab, download_settings, debug_mode):
        """Run the scraper (in a separate thread)"""
        try:
            logging.info("Initializing scraper...")
            # interactive=False: the GUI has its own login window and runs in a
            # background thread, so the engine must never block on input().
            self.scraper = SplusScraper(
                max_messages_per_chat=max_messages, debug=debug_mode, interactive=False
            )
            
            logging.info("Initializing driver...")
            self.scraper.init_driver()
            
            self.status_var.set("Scraping...")
            
            # Start scraping - با استفاده از متد اصلاح شده
            chat_count = self.scrape_chats_with_progress(tab, download_settings)
            
            if self.is_running:
                self.status_var.set("Completed")
                logging.info(f"Successfully processed {chat_count} chats")
                messagebox.showinfo("Completed", f"Successfully processed {chat_count} chats")
            else:
                logging.info("Scraping stopped by user")
                
        except Exception as e:
            error_msg = f"Error during scraping: {str(e)}"
            logging.error(error_msg)
            self.status_var.set("Error")
            if self.is_running:  # Only show error if not stopped by user
                messagebox.showerror("Error", error_msg)
        finally:
            # Clean up
            if self.scraper:
                try:
                    self.scraper.close_driver()
                except Exception as e:
                    logging.debug("Driver close during cleanup did not complete: %s", e)
            
            # Update UI
            self.is_running = False
            self.root.after(0, self.on_scraping_finished)
    
    def scrape_chats_with_progress(self, tab, download_settings):
        """Scrape chats with progress tracking"""
        if not self.scraper.driver:
            raise RuntimeError("Driver not initialized")
            
        scroll_attempts = 0
        max_scroll_attempts = 5
        scroll_increment = 500
        consecutive_failures = 0
        max_consecutive_failures = 3
        processed_count = 0

        while (scroll_attempts < max_scroll_attempts and 
            consecutive_failures < max_consecutive_failures and
            self.is_running):
            
            try:
                chat_items = self.scraper._get_fresh_chat_elements(tab)
                if not chat_items:
                    scroll_attempts += 1
                    consecutive_failures += 1
                    continue

                new_chats_found = False
                for chat in chat_items:
                    if not self.is_running:
                        break
                        
                    try:
                        chat_data = self.scraper._extract_chat_data(chat)
                        if not chat_data:
                            continue

                        if chat_data['id'] not in self.scraper.processed_chat_ids:
                            new_chats_found = True

                            # Only mark the chat as processed once it was actually
                            # opened and its messages saved. Marking it beforehand
                            # silently dropped chats whose open failed, and a retry
                            # could never pick them up again.
                            if self.scraper._enter_and_exit_chat(chat, download_settings):
                                self.scraper._update_chats_list(chat_data)
                                self.scraper.processed_chat_ids.add(chat_data['id'])
                                # افزایش شمارنده و به‌روزرسانی پیشرفت
                                processed_count += 1
                                self.root.after(0, self.increment_progress)
                                logging.info(f"Processed chat {processed_count}: {chat_data['title']}")

                            break
                            
                    except Exception as e:
                        logging.error(f"Error processing chat: {str(e)}")
                        continue

                if not new_chats_found:
                    consecutive_failures += 1
                    continue

                if len(self.scraper.chats) >= 100:
                    break

                if not self.scraper._scroll_chat_list(scroll_increment):
                    consecutive_failures += 1

            except Exception as e:
                logging.error(f"Main loop error: {str(e)}")
                scroll_attempts += 1
                consecutive_failures += 1
                time.sleep(3)
                if consecutive_failures % 2 == 0:
                    self.scraper.driver.refresh()
                    time.sleep(5)

        self.scraper.save_chats_to_file()
        return processed_count
    
    def on_scraping_finished(self):
        """Callback when scraping finishes (runs in main thread)"""
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        if self.status_var.get() != "Stopped":
            self.status_var.set("Ready")

def main():
    """Main function to run the GUI"""
    root = tk.Tk()
    app = SplusScraperGUI(root)
    root.protocol("WM_DELETE_WINDOW", lambda: (app.stop_scraping(), root.destroy()))
    root.mainloop()

if __name__ == "__main__":
    main()