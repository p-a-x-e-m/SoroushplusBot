import os
import re
import sys
import time
import json
import base64
import hashlib
import sqlite3
import logging
from datetime import datetime, timedelta
from typing import TypedDict, Optional, Literal, Dict, Any, List, Set, Union

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import (NoSuchElementException, 
                                      StaleElementReferenceException)
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.support import expected_conditions as EC

from webdriver_manager.chrome import ChromeDriverManager

# تنظیمات لاگینگ
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ====================== CONSTANTS ======================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
JSON_DIR = os.path.join(BASE_DIR, 'output')
MEDIA_DIR = os.path.join(BASE_DIR, 'output')
os.makedirs(JSON_DIR, exist_ok=True)
os.makedirs(MEDIA_DIR, exist_ok=True)

# ====================== OUTPUT SAFETY ======================
# Chat and message IDs come from the page DOM, so they are untrusted input that
# ends up in filesystem paths. Whitelist what we accept instead of blacklisting.
SAFE_ID_RE = re.compile(r'\A[A-Za-z0-9_-]{1,128}\Z')


def safe_path_component(value: Any, fallback_prefix: str = "id") -> str:
    """Coerce a DOM-derived identifier into a single, safe path component.

    Anything outside [A-Za-z0-9_-] is rejected outright; if no usable value
    remains we derive a stable hash instead. This prevents a crafted chat title
    or id (e.g. '../../..') from escaping the output directory (CWE-22).
    """
    text = str(value or "").strip()
    if SAFE_ID_RE.match(text):
        return text
    digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]
    return f"{fallback_prefix}_{digest}"


def safe_download_filename(raw_name: str, fallback: str) -> str:
    """Build a filename that cannot leave the chat's media directory.

    Chrome derives the downloaded file's name from the server's Content-
    Disposition header, so the name is attacker-controlled. Strip any directory
    component, then whitelist characters.
    """
    name = os.path.basename(str(raw_name).replace("\\", "/"))
    name = re.sub(r'[^A-Za-z0-9._-]', '_', name).lstrip('.')
    return name or fallback


# ====================== SECRET STORAGE ======================
SECRET_FILE_MODE = 0o600


def restrict_file_to_owner(path: str) -> None:
    """Best-effort chmod 0600 — no-op on Windows, where chmod only maps the
    read-only bit and real ACLs govern access."""
    try:
        os.chmod(path, SECRET_FILE_MODE)
    except OSError:
        pass


def warn_if_group_or_world_readable(path: str) -> None:
    """Warn when a secret file is readable by anyone other than its owner."""
    if os.name == "nt":
        return
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return
    if mode & 0o077:
        logging.getLogger(__name__).warning(
            "Credential store %s is group/world readable (mode %o); run "
            "'chmod 600 %s'.", path, mode & 0o777, path
        )


# ====================== JS LITERAL ESCAPING ======================
# Order matters: escape backslashes first, then the quote we wrap with.
_JS_ESCAPES = (
    ("\\", "\\\\"),
    ("\n", "\\n"),
    ("\r", "\\r"),
    (" ", "\\u2028"),   # JS line separator: breaks a bare string literal
    (" ", "\\u2029"),   # JS paragraph separator
)


def js_string_literal(value: Any) -> str:
    """Render *value* as a single-quoted JavaScript string literal.

    Account identifiers are injected into a script that runs in the page, so
    they must be escaped rather than interpolated directly (CWE-94).
    """
    text = "" if value is None else str(value)
    for char, escaped in _JS_ESCAPES:
        text = text.replace(char, escaped)
    text = text.replace("'", "\\'")
    text = text.replace("</", "<\\/")  # never terminate the enclosing <script>
    return f"'{text}'"

# ====================== TYPE DEFINITIONS ======================
class MessageData(TypedDict):
    message_id: Optional[str]
    sender_type: Optional[Literal['own', 'other']]
    content_type: Literal['sticker', 'emoji', 'call', 'file', 'video', 'image', 'audio', 'text', 'unknown', 'album']
    timestamp: Optional[str]
    date: Optional[str]  
    media_path: Optional[str]
    text_content: Optional[str]
    file_name: Optional[str]
    file_size: Optional[str]
    duration: Optional[str]
    title: Optional[str]
    artist: Optional[str]
    call_status: Optional[str]
    audio_type: Optional[Literal['voice', 'file']]

class ChatData(TypedDict):
    id: str
    title: str
    last_message: str
    timestamp: str
    avatar_path: Optional[str]

class Tokens(TypedDict):
    dc2_auth_key: str
    dc2_auth_key_bc: Optional[str]
    dc2_hash: Optional[str]
    server_salt: Optional[str]
    user_id: str
    dc_id: int
    expires_at: str

# ====================== AUTHENTICATION ======================
class SplusAuth:
    """Handles authentication with Splus.ir"""
    
    # Absolute path so the credential store always lands next to the project,
    # never in whatever directory the process happened to be started from.
    DB_PATH = os.path.join(BASE_DIR, 'splus.db')

    def __init__(self, debug, interactive: bool = True):
        self.debug = debug
        # Interactive login blocks on input(); the GUI runs on a daemon thread
        # with no console attached, where that would hang the process forever.
        self.interactive = interactive
        self.driver: Optional[webdriver.Chrome] = None
        self.logger = logging.getLogger(__name__ + '.Auth')
        self.init_db()

    def init_db(self) -> None:
        """Initialize database for token storage"""
        with sqlite3.connect(self.DB_PATH) as conn:
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS tokens
                        (id INTEGER PRIMARY KEY,
                         dc2_auth_key TEXT,
                         dc2_auth_key_bc TEXT,
                         dc2_hash TEXT,
                         server_salt TEXT,
                         user_id TEXT,
                         dc_id INTEGER,
                         expires_at TEXT)''')
        # The file holds live session credentials: owner-only on POSIX.
        restrict_file_to_owner(self.DB_PATH)
        warn_if_group_or_world_readable(self.DB_PATH)

    def save_tokens(self, tokens: Tokens) -> None:
        """Save tokens to database"""
        expires_at = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
        with sqlite3.connect(self.DB_PATH) as conn:
            c = conn.cursor()
            c.execute("DELETE FROM tokens")
            c.execute("INSERT INTO tokens VALUES (1, ?, ?, ?, ?, ?, ?, ?)",
                    (tokens['dc2_auth_key'],
                     tokens.get('dc2_auth_key_bc'),
                     tokens.get('dc2_hash'),
                     tokens.get('server_salt'),
                     tokens['user_id'],
                     tokens['dc_id'],
                     expires_at))
        restrict_file_to_owner(self.DB_PATH)

    def get_tokens(self) -> Optional[Tokens]:
        """Retrieve tokens from database, ignoring expired ones.

        Expiry was stored but never enforced, so an expired session was replayed
        on every run and only failed deep inside the scraping loop.
        """
        with sqlite3.connect(self.DB_PATH) as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM tokens WHERE id=1")
            row = c.fetchone()

        if not row:
            return None

        tokens = {
            'dc2_auth_key': row[1],
            'dc2_auth_key_bc': row[2],
            'dc2_hash': row[3],
            'server_salt': row[4],
            'user_id': row[5],
            'dc_id': row[6],
            'expires_at': row[7]
        }

        if not tokens['dc2_auth_key']:
            return None

        expires_at = tokens.get('expires_at')
        if expires_at:
            try:
                if datetime.now() >= datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S"):
                    self.logger.info(
                        "Stored credentials expired on %s; manual login required.",
                        expires_at,
                    )
                    return None
            except ValueError:
                # Unparseable timestamp: treat as expired rather than trusting it.
                self.logger.warning("Unreadable credential expiry; re-login required.")
                return None

        return tokens

    def init_driver(self) -> webdriver.Chrome:
        """Initialize the WebDriver"""
        if self.driver is not None:
            return self.driver
            
        options = webdriver.ChromeOptions()

        if not self.debug:
            options.add_argument("--headless=new")

        options.add_argument("--log-level=3")
        options.add_argument("--disable-notifications")
        options.add_argument("--disable-infobars")
        options.add_argument("--mute-audio")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_experimental_option("prefs", {
            "download.default_directory": os.path.abspath("media"),
            "download.prompt_for_download": False,
            "download.directory_upgrade": True,
            "safebrowsing.enabled": True
        })

        self.driver = webdriver.Chrome(
            service=Service(ChromeDriverManager().install(), log_path=os.devnull),
            options=options
        )
        return self.driver

    def close_driver(self) -> None:
        """Close the WebDriver"""
        if self.driver is not None:
            self.driver.quit()
            self.driver = None

    def manual_login(self) -> Tokens:
        """Manual login and token extraction.

        Opened for the user to sign in, then polled until the session appears in
        localStorage. Polling replaces a blocking ``input()`` prompt so this can
        also run on the GUI's background thread (and so an empty Enter no longer
        produces a token-less "success").
        """
        self.init_driver()
        self.driver.get("https://web.splus.ir/")
        self.logger.info("Please log in to Splus.ir in the opened browser window...")

        timeout = 300
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                if self.driver.execute_script("return localStorage.getItem('dc2_auth_key')"):
                    break
            except Exception as e:
                # Page still navigating; keep waiting.
                self.logger.debug("Waiting for page to become ready: %s", e)
            time.sleep(2)
        else:
            raise RuntimeError(
                "Timed out waiting for login. Please sign in to Splus.ir and try again."
            )

        tokens: Dict[str, Any] = {
            'dc2_auth_key': self.driver.execute_script("return localStorage.getItem('dc2_auth_key')"),
            'dc2_auth_key_bc': self.driver.execute_script("return localStorage.getItem('dc2_auth_key_bc')"),
            'dc2_hash': self.driver.execute_script("return localStorage.getItem('dc2_hash')"),
            'server_salt': self.driver.execute_script("return localStorage.getItem('server_salt')"),
        }

        user_auth = json.loads(self.driver.execute_script("return localStorage.getItem('user_auth')") or "{}")
        tokens.update({
            'user_id': user_auth.get('id'),
            'dc_id': user_auth.get('dcID')
        })

        return tokens  

    def set_localstorage(self) -> bool:
        """Set tokens from database to localStorage"""
        tokens = self.get_tokens()
        if not tokens:
            return False

        self.init_driver()
        self.driver.get("https://web.splus.ir")

        # Every value below is interpolated into a script executed in the page,
        # so each one must be escaped as a JS literal rather than dropped in raw.
        dc_id = tokens.get('dc_id')
        dc_id_literal = str(int(dc_id)) if isinstance(dc_id, int) or str(dc_id or "").isdigit() else "null"
        script = (
            "localStorage.setItem('dc2_auth_key', %s);"
            "localStorage.setItem('dc2_auth_key_bc', %s);"
            "localStorage.setItem('dc2_hash', %s);"
            "localStorage.setItem('server_salt', %s);"
            "localStorage.setItem('user_auth', JSON.stringify({id: %s, dcID: %s}));"
            % (
                js_string_literal(tokens['dc2_auth_key']),
                js_string_literal(tokens.get('dc2_auth_key_bc')),
                js_string_literal(tokens.get('dc2_hash')),
                js_string_literal(tokens.get('server_salt')),
                js_string_literal(tokens.get('user_id')),
                dc_id_literal,
            )
        )
        self.driver.execute_script(script)
        time.sleep(2)
        self.driver.refresh()
        return True

    def auth(self) -> bool:
        """Main authentication method"""
        if self.get_tokens():
            if self.set_localstorage():
                return True

        if not self.interactive:
            # Non-interactive callers (the GUI) run their own login window and
            # save the tokens themselves; blocking here would hang the thread.
            raise RuntimeError(
                "No valid stored credentials. Use 'Manual Login' to authenticate."
            )

        self.logger.info("Manual login required")
        tokens = self.manual_login()
        self.save_tokens(tokens)
        return True

# ====================== SCRAPER ======================
class SplusScraper:
    def __init__(self, debug, max_messages_per_chat=0, interactive: bool = True):
        self.driver = None
        self.auth = SplusAuth(debug=debug, interactive=interactive)
        self.current_chat_id: Optional[str] = None
        self.current_chat_messages: List[MessageData] = []
        self.chats: List[ChatData] = []
        self.processed_message_ids: Set[str] = set()
        self.processed_chat_ids: Set[str] = set()
        self.download_settings = {
            'sticker': True,
            'file': True,
            'video': True,
            'image': True,
            'audio': True,
            'album': True,
        }
        self.max_messages_per_chat = max_messages_per_chat
        self.logger = logging.getLogger(__name__ + '.Scraper')
        self.load_existing_data()

    def load_existing_data(self):
        """Load existing chats and processed message IDs"""
        # Load existing chats
        chats_file = os.path.join(JSON_DIR, 'chat_data.json')
        if os.path.exists(chats_file):
            with open(chats_file, 'r', encoding='utf-8') as f:
                self.chats = json.load(f)["chats"]
                self.processed_chat_ids = {chat['id'] for chat in self.chats}

        if os.path.exists(chats_file):
            with open(chats_file, "r", encoding="utf-8") as f:
                all_chats = json.load(f)["chat_data"]
                for chat in all_chats.values():
                    for message in chat:
                        self.processed_message_ids.update(message["message_id"]) 

    def init_driver(self):
        """Initialize the WebDriver"""
        if not self.auth.auth():
            raise RuntimeError("Authentication failed")
        self.driver = self.auth.driver

    def close_driver(self):
        """Close the WebDriver"""
        self.auth.close_driver()

    def save_chats_to_file(self):
        """Save chats list to JSON file, maintaining existing data"""
        chats_file = os.path.join(JSON_DIR, 'chat_data.json')
        
        # Create a dictionary of chats by ID for easy updates
        existing_chats = {chat['id']: chat for chat in self.chats}
        
        # If file exists, load and merge with existing data
        if os.path.exists(chats_file):
            with open(chats_file, 'r', encoding='utf-8') as f:
                try:
                    saved_chats = json.load(f)["chats"]
                    for chat in saved_chats:
                        if chat['id'] not in existing_chats:
                            existing_chats[chat['id']] = chat
                except KeyError:
                    pass

        # Convert back to list and save
        merged_chats = list(existing_chats.values())
        previous_data = {"chats":merged_chats}

        # Load previous data and put the chat info in correct section
        if os.path.exists(chats_file):
            with open(chats_file, "r", encoding="utf-8") as f:
                previous_data = json.load(f)
                previous_data["chats"] = merged_chats

        with open(chats_file, 'w', encoding='utf-8') as f:
            json.dump(previous_data, f, ensure_ascii=False, indent=2)

    def save_current_chat_messages(self):
        """Save messages for current chat, merging with existing data and clearing buffer after write"""
        if not self.current_chat_id or not self.current_chat_messages:
            return

        chat_file = os.path.join(JSON_DIR, "chat_data.json")
        all_chats = {}

        # Load previous data if exists
        if os.path.exists(chat_file):
            with open(chat_file, 'r', encoding='utf-8') as f:
                all_chats = json.load(f)["chat_data"]

        # Get existing messages for this chat
        existing_messages = all_chats.get(self.current_chat_id, [])

        # Create a dict for fast lookup and update
        existing_messages_dict = {msg['message_id']: msg for msg in existing_messages if msg.get('message_id')}

        # Add/overwrite with new messages
        for msg in self.current_chat_messages:
            if msg.get('message_id'):
                existing_messages_dict[msg['message_id']] = msg

        # Save back to disk
        all_chats[self.current_chat_id] = list(existing_messages_dict.values())
        previous_data = {"chat_data":all_chats}

        # Load previous data
        if os.path.exists(chat_file):
            with open(chat_file, "r", encoding="utf-8") as f:
                previous_data = json.load(f)
                previous_data["chat_data"] = all_chats

        with open(chat_file, 'w', encoding='utf-8') as f:
            json.dump(previous_data, f, ensure_ascii=False, indent=2)

        # Clear buffer after saving
        self.current_chat_messages.clear()

    def is_advertisement(self, chat_element):
        """Check if the chat is an advertisement"""
        try:
            ad_icon = chat_element.find_element(By.CSS_SELECTOR, '.AdvertisementIcon')
            return ad_icon is not None
        except NoSuchElementException:
            return False

    def _download_avatar(self, chat_element, chat_id: str) -> Optional[str]:
        """Download chat avatar if available"""
        try:
            # Create chat-specific avatar directory
            # chat_id is DOM-derived; re-sanitise so this stays safe even when the
            # caller passes a raw value (CWE-22).
            chat_id = safe_path_component(chat_id, 'chat')
            avatar_dir = os.path.join(MEDIA_DIR, chat_id, '')
            os.makedirs(avatar_dir, exist_ok=True)
            
            avatar_element = chat_element.find_element(By.CSS_SELECTOR, '.Avatar img')
            avatar_url = avatar_element.get_attribute('src')
            
            if not avatar_url or not avatar_url.startswith('blob:'):
                return None
                
            # Generate unique filename
            avatar_filename = f"{chat_id}_avatar.png"
            avatar_path = os.path.join(avatar_dir, avatar_filename)
            
            # Download using JavaScript workaround
            script = """
                var url = arguments[0];
                var callback = arguments[1];
                
                fetch(url)
                    .then(res => res.blob())
                    .then(blob => {
                        var reader = new FileReader();
                        reader.onload = function() {
                            callback(reader.result);
                        };
                        reader.readAsDataURL(blob);
                    });
            """
            
            # Execute JavaScript and get base64 data
            base64_data = self.driver.execute_async_script(script, avatar_url)
            
            # Save to file
            if base64_data.startswith('data:image'):
                with open(avatar_path, 'wb') as f:
                    f.write(base64.b64decode(base64_data.split(',')[1]))
                return avatar_path
                
        except Exception as e:
            self.logger.error(f"Error downloading avatar: {str(e)}")
        return None

    def _extract_chat_data(self, chat_element) -> Optional[ChatData]:
        """Extract title and last message from chat element"""
        try:
            if self.is_advertisement(chat_element):
                return None

            # Try multiple ways to get chat ID
            chat_id = (
                self._get_chat_id_from_avatar(chat_element) or
                self._get_chat_id_from_href(chat_element) or
                self._generate_fallback_chat_id(chat_element)
            )

            if not chat_id:
                return None

            title = self._get_chat_title(chat_element)
            last_message = self._get_last_message(chat_element)
            
            # Download avatar if available
            avatar_path = self._download_avatar(chat_element, chat_id)

            return {
                'id': chat_id,
                'title': title,
                'last_message': last_message,
                'timestamp': datetime.now().isoformat(),
                'avatar_path': avatar_path  # Added
            }
        
        except Exception as e:
            self.logger.error(f"Error extracting chat data: {str(e)}")
            return None

    def _get_chat_id_from_avatar(self, chat_element) -> Optional[str]:
        """Extract chat ID from avatar element"""
        try:
            avatar_div = chat_element.find_element(By.CSS_SELECTOR, '.Avatar')
            raw = avatar_div.get_attribute('id').replace('peer-story', '')
            return safe_path_component(raw, 'chat') if raw else None
        except Exception:
            return None

    def _get_chat_id_from_href(self, chat_element) -> Optional[str]:
        """Extract chat ID from href attribute"""
        try:
            chat_link = chat_element.find_element(By.TAG_NAME, 'a')
            raw = chat_link.get_attribute('href').split('#')[-1]
            return safe_path_component(raw, 'chat') if raw else None
        except Exception:
            return None

    def _generate_fallback_chat_id(self, chat_element) -> str:
        """Generate fallback chat ID using a stable hash of the chat text.

        Uses sha256 rather than hash() so the id stays the same across runs;
        hash() is randomised per process for str, which made the fallback id
        unstable and produced duplicate output folders.
        """
        text = chat_element.text or ""
        digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
        return digest[:10]

    def _get_chat_title(self, chat_element) -> str:
        """Extract chat title"""
        try:
            return chat_element.find_element(By.CSS_SELECTOR, '.title h3').text.strip()
        except NoSuchElementException:
            return "No title"

    def _get_last_message(self, chat_element) -> str:
        """Extract last message"""
        try:
            return chat_element.find_element(By.CSS_SELECTOR, '.last-message').text.strip()
        except NoSuchElementException:
            return "No message"

    def _is_chat_open(self, expected_id=None) -> bool:
        """Check if we're in a chat view"""
        try:
            self.driver.find_element(By.CLASS_NAME, 'messages-container')
            return True
        except NoSuchElementException:
            return False

    def _check_and_scroll_to_bottom(self):
        """Check if chat has unread messages and scroll to bottom if needed"""
        try:
            # Look for the "Go to bottom" button (indicates unread messages)
            bottom_button = self.driver.find_element(
                By.XPATH, 
                "//button[@aria-label='رفتن به پایین صفحه' or @title='رفتن به پایین صفحه']"
            )
            
            # If the button is found and visible, click it to scroll to bottom
            if bottom_button.is_displayed():
                bottom_button.click()
                self.logger.info("Scrolled to bottom of chat (unread messages detected)")
                time.sleep(2)
                return True
                
        except NoSuchElementException:
            # No "Go to bottom" button means we're already at the bottom
            self.logger.info("No unread messages detected - already at bottom")
            return False
        except Exception as e:
            self.logger.error(f"Error checking/scrolling to bottom: {str(e)}")
            return False

    # Add this method to your SplusScraper class and call it after entering a chat
    def _enter_and_exit_chat(self, chat_element, download_settings) -> bool:
        """Enter chat by simulating click and return to main page"""
        try:
            if self.is_advertisement(chat_element):
                return False

            chat_data = self._extract_chat_data(chat_element)
            if not chat_data:
                return False

            self.current_chat_id = chat_data['id']
            self.current_chat_messages = []
            self.logger.info(f"Processing chat: {self.current_chat_id}")

            original_url = self.driver.current_url

            # Try different ways to click the chat
            try:
                clickable = chat_element.find_element(By.CSS_SELECTOR, '.chat-item-clickable, .ListItem-button')
                clickable.click()
            except Exception:
                chat_element.click()

            time.sleep(6)

            if not self._is_chat_open(self.current_chat_id):
                self.driver.get(original_url)
                return False

            # NEW: Check if we need to scroll to bottom for unread messages
            self._check_and_scroll_to_bottom()

            # Checks for possible pop ups
            try:
                button = self.driver.find_element(
                    "xpath",
                    "//div[@class='dialog-buttons mt-2']//button[@class='Button default primary text']"
                )
                button.click()
            except NoSuchElementException:
                pass

            # Process messages in this chat
            self.scroll_from_highest_to_lowest(download_settings)
            
            # Save messages for this chat immediately
            self.save_current_chat_messages()
            
            # Update chats list with this chat's info
            self._update_chats_list(chat_data)
            
            self.logger.info(f"Chat {self.current_chat_id} completed!")
            self.driver.get(original_url)
            time.sleep(3)
            
            if self._is_chat_open():
                self.driver.get("https://web.splus.ir/")
                time.sleep(3)
                return False
                
            return True

        except Exception as e:
            self.logger.error(f"Error entering/exiting chat: {str(e)}")
            self.driver.get("https://web.splus.ir/")
            time.sleep(3)
            return False

    def _update_chats_list(self, chat_data: ChatData):
        """Update the chats list with new chat data"""
        # Remove existing entry if present
        self.chats = [chat for chat in self.chats if chat['id'] != chat_data['id']]
        # Add new entry
        self.chats.append(chat_data)
        # Save the updated list
        self.save_chats_to_file()

    def _get_fresh_chat_elements(self, tab) -> List[Any]:
        """Get fresh references to chat elements"""
        TAB_NAME = {
            "1": "همه",
            "2": "شخصی",
            "3": "گروه‌ها",
            "4": "کانال‌ها"
        }
        
        try:
            if tab != "1":    
                tab_element = WebDriverWait(self.driver, 10).until(
                    EC.element_to_be_clickable((By.XPATH, 
                        f"//div[@class='Tab Tab--interactive']/span[contains(text(), '{TAB_NAME[tab]}')]")))
                tab_element.click()
                time.sleep(3)

            chat_list_container = WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.XPATH, 
                    "//*[contains(@class, 'chat-list') and contains(@class, 'Transition_slide-active')]"))
            )

            return WebDriverWait(chat_list_container, 10).until(
                EC.presence_of_all_elements_located((By.CLASS_NAME, "Chat")))
        
        except Exception as e:
            self.logger.error(f"Error getting chat elements: {str(e)}")
            return []

    def _extract_album_data(self, message_element, download) -> Optional[MessageData]:
        """Extract data from album messages"""
        try:
            result: MessageData = {
                'message_id': message_element.get_attribute('data-message-id'),
                'sender_type': 'other',
                'content_type': 'album',
                'timestamp': None,
                'media_path': None,
                'text_content': None,
            }

            try:
                content_wrapper = message_element.find_element(By.CLASS_NAME, 'message-content-wrapper')
                if content_wrapper.find_element(By.CLASS_NAME, 'MessageOutgoingStatus'):
                    result['sender_type'] = 'own'
            except NoSuchElementException:
                pass

            try:
                result['timestamp'] = content_wrapper.find_element(By.CLASS_NAME, 'message-time').text
            except NoSuchElementException:
                pass

            if download:
                result['media_path'] = self._download_with_selenium(message_element)

            try:
                content_inner = content_wrapper.find_element(By.CLASS_NAME, 'content-inner')
                self._extract_text_content(content_inner, result)
            except NoSuchElementException:
                pass

            return result

        except Exception as e:
            self.logger.error(f"Error extracting album data: {str(e)}")
            return None

    def _download_with_selenium(self, message_element) -> Optional[Union[str, List[str]]]:
        """Download media file from message"""
        try:
            if not self.current_chat_id:
                raise ValueError("No current chat ID set for media download")
                
            chat_media_dir = os.path.join(
                MEDIA_DIR, safe_path_component(self.current_chat_id, 'chat')
            )
            os.makedirs(chat_media_dir, exist_ok=True)

            message_id = self._get_message_id(message_element)
            if not message_id:
                return None

            self._configure_download_behavior(chat_media_dir)
            self._initiate_download(message_element)

            return self._wait_for_download_complete(message_id, chat_media_dir)

        except Exception as e:
            self.logger.error(f"Download error: {str(e)}")
            return None

    def _get_message_id(self, message_element) -> str:
        """Extract or generate a path-safe message ID"""
        message_id = message_element.get_attribute('data-message-id') or ""
        if not message_id:
            element_id = message_element.get_attribute('id') or ""
            if element_id.startswith('album-media-message'):
                message_id = element_id.split('-')[-1]
            else:
                message_id = str(int(time.time() * 1000))
        # Used as a filename component, so enforce the safe-id whitelist.
        return safe_path_component(message_id, 'msg')

    def _configure_download_behavior(self, download_path: str) -> None:
        """Configure download behavior for Chrome"""
        self.driver.execute_cdp_cmd('Page.setDownloadBehavior', {
            'behavior': 'allow',
            'downloadPath': download_path
        })

    def _initiate_download(self, message_element) -> None:
        """Right-click and select download option"""
        ActionChains(self.driver).context_click(message_element).perform()
        time.sleep(1)

        download_menu_item = WebDriverWait(self.driver, 10).until(
            EC.presence_of_element_located((By.XPATH, 
                "//div[@class='MenuItem compact' and .//i[contains(@class, 'icon-download')]]"))
        )
        download_menu_item.click()

    def _wait_for_download_complete(self, message_id: str, download_path: str) -> Optional[Union[str, List[str]]]:
        """Wait for download to complete and rename files"""
        existing_files = set(os.listdir(download_path))
        start_time = time.time()
        timeout = 60
        downloaded_files = []
        last_file_count = 0
        stable_checks = 0

        while time.time() - start_time < timeout:
            current_files = set(os.listdir(download_path))
            new_files = current_files - existing_files
            
            complete_files = [
                f for f in new_files 
                if not any(f.endswith(ext) for ext in ['.crdownload', '.part', '.tmp'])
                and f not in downloaded_files
            ]
            
            if len(complete_files) == last_file_count:
                stable_checks += 1
                if stable_checks >= 3:
                    break
            else:
                last_file_count = len(complete_files)
                stable_checks = 0

            for idx, downloaded_file in enumerate(complete_files):
                original_path = os.path.join(download_path, downloaded_file)

                # Chrome names the file from the server's Content-Disposition
                # header, so treat it as untrusted: keep the extension only when
                # it is safe, and always rebuild the name from a sanitised stem.
                safe_name = safe_download_filename(
                    downloaded_file, f"download_{int(time.time() * 1000)}_{idx}"
                )
                file_ext = os.path.splitext(safe_name)[1]
                if not re.fullmatch(r'\.[A-Za-z0-9]{1,8}', file_ext or ''):
                    file_ext = ''
                stem = os.path.splitext(safe_name)[0] or safe_path_component(message_id, 'msg')
                new_filename = f"{stem}_{safe_path_component(message_id, 'msg')}{file_ext}"
                new_path = os.path.join(download_path, new_filename)

                # Containment check: never rename outside the chat's directory.
                if os.path.dirname(os.path.realpath(new_path)) != os.path.realpath(download_path):
                    self.logger.error("Refusing to write outside the download directory.")
                    continue

                try:
                    os.rename(original_path, new_path)
                    downloaded_files.append(new_filename)
                except OSError as e:
                    self.logger.error(f"File rename error: {e}")
                    continue

            time.sleep(2)

        self._cleanup_partial_downloads(download_path)
        
        if not downloaded_files:
            return None
            
        if len(downloaded_files) > 1:
            return [os.path.join(download_path, f) for f in downloaded_files]
        return os.path.join(download_path, downloaded_files[0])

    def _cleanup_partial_downloads(self, download_path: str) -> None:
        """Remove partial download files"""
        for f in os.listdir(download_path):
            if any(f.endswith(ext) for ext in ['.crdownload', '.part', '.tmp']):
                try:
                    os.remove(os.path.join(download_path, f))
                except OSError as e:
                    # File may already be gone or still locked by Chrome.
                    self.logger.debug("Could not remove partial download %s: %s", f, e)

    def _detect_content_type(self, element) -> str:
        """Helper to detect content type"""
        try:
            if element.find_element(By.CLASS_NAME, 'Album'):
                return 'album'
        except NoSuchElementException:
            # No album marker: it is a single-media message.
            pass
        return "single"

    def _extract_text_content(self, content_inner, result: MessageData) -> None:
        """Helper method to extract and clean text content"""
        try:
            text_element = content_inner.find_element(By.CLASS_NAME, 'text-content')
            raw_text = text_element.text.strip()

            if result['timestamp'] and raw_text.endswith(result['timestamp']):
                clean_text = raw_text[:-len(result['timestamp'])].strip()
            else:
                clean_text = raw_text

            result['text_content'] = '\n'.join(
                line.strip() for line in clean_text.split('\n') if line.strip()
            )
        except NoSuchElementException:
            pass

    def _extract_message_data(self, message_element, download_settings) -> Optional[MessageData]:
        """Extract all data from a message element"""
        try:
            # Check for album first
            try:
                message_element.find_element(By.CLASS_NAME, 'Album')
                msg_data = self._extract_album_data(message_element, download_settings["album"])
                if msg_data and self.current_chat_id:
                    self.current_chat_messages.append(msg_data)
                return msg_data
            except NoSuchElementException:
                pass

            content_wrapper = message_element.find_element(By.CLASS_NAME, 'message-content-wrapper')
            content_inner = content_wrapper.find_element(By.CLASS_NAME, 'content-inner')

            result: MessageData = {
                'message_id': message_element.get_attribute('data-message-id'),
                'sender_type': 'other',
                'content_type': 'unknown',
                'timestamp': None,
                'media_path': None,
                'text_content': None
            }

            # Extract common message metadata
            self._extract_message_metadata(content_wrapper, result)

            # Check different content types in order
            content_checkers = [
                self._check_for_sticker,
                self._check_for_emoji,
                self._check_for_call,
                self._check_for_file,
                self._check_for_video,
                self._check_for_image,
                self._check_for_audio,
                self._check_for_text
            ]

            for checker in content_checkers:
                if checker(content_inner, message_element, result, download_settings):
                    if self.current_chat_id:
                        self.current_chat_messages.append(result)
                    return result

            if self.current_chat_id:
                self.current_chat_messages.append(result)
            return result

        except Exception as e:
            self.logger.error(f"Error extracting message data: {str(e)}")
            return None

    def _extract_message_metadata(self, content_wrapper, result: MessageData) -> None:
        """Extract common message metadata"""
        try:
            # Extract time
            result['timestamp'] = content_wrapper.find_element(By.CLASS_NAME, 'message-time').text
            
            # Extract date from the sticky date element above the message
            date_group = content_wrapper.find_element(By.XPATH, "./ancestor::div[contains(@class, 'message-date-group')]")
            date_element = date_group.find_element(By.CLASS_NAME, 'sticky-date')
            result['date'] = date_element.text.strip()
            
        except NoSuchElementException:
            pass

        try:
            if content_wrapper.find_element(By.CLASS_NAME, 'MessageOutgoingStatus'):
                result['sender_type'] = 'own'
        except NoSuchElementException:
            pass

    def _check_for_sticker(self, content_inner, message_element, result: MessageData, download_settings) -> bool:
        """Check if message is a sticker"""
        try:
            content_inner.find_element(By.CLASS_NAME, 'Sticker')
            result['content_type'] = 'sticker'
            if download_settings["sticker"]:
                result['media_path'] = self._download_with_selenium(message_element)
            return True
        except NoSuchElementException:
            return False

    def _check_for_emoji(self, content_inner, message_element, result: MessageData, download_settings) -> bool:
        """Check if message is emoji-only"""
        try:
            if 'emoji-only' in message_element.find_element(By.CLASS_NAME, 'message-content').get_attribute('class'):
                result['content_type'] = 'emoji'
                return True
        except NoSuchElementException:
            pass
        return False

    def _check_for_call(self, content_inner, message_element, result: MessageData, download_settings) -> bool:
        """Check if message is a call"""
        try:
            call_element = content_inner.find_element(By.CLASS_NAME, 'vDeypQzM845_JE14qGId')
            result['sender_type'] = None
            result['content_type'] = 'call'
            result['call_status'] = call_element.find_element(By.CLASS_NAME, 'LWVSvxVjeEyHPBrCb2sD').text
            return True
        except NoSuchElementException:
            return False

    def _check_for_file(self, content_inner, message_element, result: MessageData, download_settings) -> bool:
        """Check if message is a file"""
        try:
            file_element = content_inner.find_element(By.CLASS_NAME, 'File')
            result['content_type'] = 'file'
            result.update({
                'file_name': file_element.find_element(By.CLASS_NAME, 'file-title').text,
                'file_size': file_element.find_element(By.CLASS_NAME, 'file-subtitle').text
            })
            if download_settings["file"]:
                result['media_path'] = self._download_with_selenium(message_element)
            self._extract_text_content(content_inner, result)
            return True
        except NoSuchElementException:
            return False

    def _check_for_video(self, content_inner, message_element, result: MessageData, download_settings) -> bool:
        """Check if message is a video"""
        try:
            media_inner = content_inner.find_element(By.CLASS_NAME, 'media-inner')
            classes = media_inner.get_attribute('class')

            if 'dark' in classes and 'interactive' in classes:
                media_inner.find_element(By.CLASS_NAME, 'message-media-duration')
                result['content_type'] = 'video'
                if download_settings["video"]:    
                    result['media_path'] = self._download_with_selenium(message_element)
                self._extract_text_content(content_inner, result)
                return True
        except NoSuchElementException:
            pass
        return False

    def _check_for_image(self, content_inner, message_element, result: MessageData, download_settings) -> bool:
        """Check if message is an image"""
        try:
            media_inner = content_inner.find_element(By.CLASS_NAME, 'media-inner')
            classes = media_inner.get_attribute('class')

            if 'interactive' in classes and 'dark' not in classes:
                result['content_type'] = 'image'
                if download_settings["image"]:
                    result['media_path'] = self._download_with_selenium(message_element)
                self._extract_text_content(content_inner, result)
                return True
        except NoSuchElementException:
            pass
        return False

    def _check_for_audio(self, content_inner, message_element, result: MessageData, download_settings) -> bool:
        """Check if message is audio or voice"""
        try:
            audio_element = content_inner.find_element(By.CLASS_NAME, 'Audio')
            result['content_type'] = 'audio'
            
            try:
                duration_element = audio_element.find_element(By.CLASS_NAME, 'voice-duration')
                result['audio_type'] = 'voice'
                result['duration'] = duration_element.text
            except NoSuchElementException:
                try:
                    duration_element = audio_element.find_element(By.CLASS_NAME, 'duration')
                    result['audio_type'] = 'file'
                    result.update({
                        'title': audio_element.find_element(By.CLASS_NAME, 'title').text,
                        'duration': duration_element.text,
                        'size': audio_element.find_element(By.CLASS_NAME, 'performer').text,
                        'artist': audio_element.find_elements(By.CLASS_NAME, 'performer')[1].text
                    })
                except NoSuchElementException:
                    pass
            
            if download_settings["audio"]:
                result['media_path'] = self._download_with_selenium(message_element)
            return True
        except NoSuchElementException:
            return False

    def _check_for_text(self, content_inner, message_element, result: MessageData, download_settings) -> bool:
        """Check if message is text"""
        try:
            text_element = content_inner.find_element(By.CLASS_NAME, 'text-content')
            result['content_type'] = 'text'
            self._extract_text_content(content_inner, result)
            return True
        except NoSuchElementException:
            return False

    def scroll_from_highest_to_lowest(self, download_settings=None) -> int:
        """Scroll from newest to oldest messages with dynamic loading and max message limit"""
        if not self.driver:
            raise RuntimeError("Driver not initialized")

        if download_settings is None:
            download_settings = self.download_settings

        chat_container = WebDriverWait(self.driver, 30).until(
            EC.presence_of_element_located((By.CLASS_NAME, "messages-container"))
        )

        self._initialize_scroll(chat_container)
        scroll_attempts = 0
        max_scroll_attempts = 10

        loaded_messages = 0
        while scroll_attempts < max_scroll_attempts:
            current_ids = self._get_current_message_ids()
            new_ids = [msg_id for msg_id in sorted(current_ids, key=int, reverse=True) if msg_id not in self.processed_message_ids]

            # Only process messages if we haven't reached the max
            if self.max_messages_per_chat > 0 and loaded_messages >= self.max_messages_per_chat:
                break

            # Limit new_ids to remaining allowed
            if self.max_messages_per_chat > 0:
                remaining = self.max_messages_per_chat - loaded_messages
                new_ids = new_ids[:remaining]

            new_messages_found = self._process_new_messages(new_ids, download_settings)
            loaded_messages += len(new_ids)

            if new_messages_found:
                scroll_attempts = 0
            else:
                scroll_attempts += 1

            if scroll_attempts < max_scroll_attempts and (self.max_messages_per_chat == 0 or loaded_messages < self.max_messages_per_chat):
                self._scroll_up(chat_container)

        return loaded_messages

    def _initialize_scroll(self, chat_container) -> None:
        """Initialize scroll position"""
        self.driver.execute_script("arguments[0].scrollTop = arguments[0].scrollHeight", chat_container)
        time.sleep(3)

    def _get_current_message_ids(self) -> List[str]:
        """Get all message IDs currently in view"""
        return self.driver.execute_script("""
            return Array.from(document.querySelectorAll('.Message[data-message-id]'))
                .map(el => el.getAttribute('data-message-id'));
        """)

    def _process_new_messages(self, message_ids, download_settings) -> bool:
        """Process new messages that haven't been seen before"""
        new_messages_found = False
        for msg_id in sorted(message_ids, key=int, reverse=True):
            if msg_id not in self.processed_message_ids:
                try:
                    message = WebDriverWait(self.driver, 5).until(
                        EC.presence_of_element_located((By.CSS_SELECTOR, f".Message[data-message-id='{msg_id}']")))

                    self.driver.execute_script(
                        "arguments[0].scrollIntoView({behavior: 'auto', block: 'center'});",
                        message
                    )
                    time.sleep(0.3)

                    msg_data = self._extract_message_data(message, download_settings)
                    if msg_data:
                        self.processed_message_ids.add(msg_id)
                        new_messages_found = True

                        # Save messages to disk immediately after each new message
                        self.save_current_chat_messages()

                except Exception as e:
                    self.logger.error(f"Error processing message {msg_id}: {str(e)}")
                    continue
        return new_messages_found

    def _scroll_up(self, chat_container) -> None:
        """Scroll up to load older messages"""
        try:
            self.driver.execute_script("arguments[0].scrollTop -= 500;", chat_container)
            time.sleep(2)
        except Exception as e:
            self.logger.error(f"Error scrolling up: {str(e)}")

    def scrape_chat_list(self, tab="1", download_settings=None):
        """Scrape chat list from top to bottom"""
        if not self.driver:
            raise RuntimeError("Driver not initialized")

        scroll_attempts = 0
        max_scroll_attempts = 5
        scroll_increment = 500
        consecutive_failures = 0
        max_consecutive_failures = 3

        while (scroll_attempts < max_scroll_attempts and 
            consecutive_failures < max_consecutive_failures):
            
            try:
                chat_items = self._get_chat_items_with_retry(tab)
                if not chat_items:
                    scroll_attempts += 1
                    consecutive_failures += 1
                    continue

                if not self._process_chat_items(chat_items, download_settings):
                    consecutive_failures += 1
                    continue

                if len(self.chats) >= 100:
                    break

                if not self._scroll_chat_list(scroll_increment):
                    consecutive_failures += 1

            except Exception as e:
                self.logger.error(f"Main loop error: {str(e)}")
                scroll_attempts += 1
                consecutive_failures += 1
                time.sleep(3)
                if consecutive_failures % 2 == 0:
                    self.driver.refresh()
                    time.sleep(5)

        return len(self.chats)

    def _get_chat_items_with_retry(self, tab) -> List[Any]:
        """Get chat items with retry logic"""
        try:
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.CLASS_NAME, "chat-list")))
            
            chat_items = self._get_fresh_chat_elements(tab)
            if not chat_items:
                self.driver.refresh()
                time.sleep(5)
                return []
            return chat_items
        except Exception as e:
            self.logger.error(f"Error getting chat elements: {str(e)}")
            self.driver.refresh()
            time.sleep(5)
            return []

    def _process_chat_items(self, chat_items, download_settings) -> bool:
        """Process each chat item in the list"""
        new_chats_found = False
        for chat in chat_items:
            try:
                chat_data = self._extract_chat_data(chat)
                if not chat_data:
                    continue

                if chat_data['id'] not in self.processed_chat_ids:
                    new_chats_found = True

                    # Mark the chat as processed only after it was successfully
                    # opened; _enter_and_exit_chat already persists the messages
                    # and updates the chat list on success.
                    if not self._enter_and_exit_chat(chat, download_settings):
                        break

                    self.processed_chat_ids.add(chat_data['id'])
                    break
                    
            except StaleElementReferenceException:
                break
            except Exception as e:
                self.logger.error(f"Error processing chat: {str(e)}")
                continue

        return new_chats_found

    def _scroll_chat_list(self, scroll_increment) -> bool:
        """Scroll the chat list to load more items"""
        try:
            chat_list_container = WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.CLASS_NAME, "chat-list")))
            
            current_scroll = self.driver.execute_script(
                "return arguments[0].scrollTop", 
                chat_list_container)
            
            container_height = self.driver.execute_script(
                "return arguments[0].scrollHeight", 
                chat_list_container)
            
            self.driver.execute_script(
                "arguments[0].scrollTop = arguments[1];", 
                chat_list_container,
                current_scroll + scroll_increment)
            
            time.sleep(3)
            
            new_scroll = self.driver.execute_script(
                "return arguments[0].scrollTop", 
                chat_list_container)
            
            if new_scroll <= current_scroll:
                self.driver.execute_script(
                    "window.scrollBy(0, arguments[0]);", 
                    scroll_increment)
                time.sleep(3)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Scroll error: {str(e)}")
            return False

# ====================== MAIN ======================
TAB_CHOICES = ("1", "2", "3", "4")
CONTENT_TYPES = ('sticker', 'file', 'video', 'image', 'audio', 'album')


def prompt_or_default(env_name: str, prompt: str, default: str, argv_value: Optional[str] = None) -> str:
    """Prefer an explicit argument, then an environment variable, then a prompt.

    Args:
        env_name: Environment variable holding a non-interactive override.
        prompt: Text shown when interactive input is still required.
        default: Value used when the prompt is skipped or left blank.
        argv_value: Value supplied directly by the caller.
    """
    if argv_value is not None:
        return argv_value.strip()
    env_value = os.environ.get(env_name)
    if env_value is not None:
        return env_value.strip()
    try:
        entered = input(prompt).strip()
    except EOFError:
        # No console attached (piped input, service): fall back to the default.
        return default
    return entered or default


def main(argv: Optional[List[str]] = None):
    argv = sys.argv[1:] if argv is None else argv

    # Parse "--flag value" pairs; unknown flags are rejected rather than ignored.
    args: Dict[str, str] = {}
    index = 0
    while index < len(argv):
        item = argv[index]
        if not item.startswith('--'):
            print(f"Unexpected argument: {item}")
            return 2
        key = item[2:].replace('-', '_')
        if index + 1 >= len(argv):
            print(f"Missing value for {item}")
            return 2
        args[key] = argv[index + 1]
        index += 2

    known = {'max_messages', 'tab'} | set(CONTENT_TYPES)
    unknown = set(args) - known
    if unknown:
        print(f"Unknown option(s): {', '.join(sorted(unknown))}")
        return 2

    max_messages_input = prompt_or_default(
        'SPLUS_MAX_MESSAGES',
        "Maximum number of messages to load per chat (0 for unlimited): ",
        "0",
        args.get('max_messages'),
    )
    try:
        max_messages_per_chat = max(0, int(max_messages_input))
    except ValueError:
        max_messages_per_chat = 0

    tab = prompt_or_default(
        'SPLUS_TAB', "(1) All\n(2) Private\n(3) Groups\n(4) Chanels\n", "1", args.get('tab')
    )
    if tab not in TAB_CHOICES:
        tab = "1"

    download_settings = {}
    for content_type in CONTENT_TYPES:
        answer = prompt_or_default(
            f"SPLUS_DOWNLOAD_{content_type.upper()}",
            f"{content_type.capitalize()}s? (y/n): ",
            "y",
            args.get(content_type),
        )
        download_settings[content_type] = answer.lower() == 'y'

    scraper = SplusScraper(max_messages_per_chat=max_messages_per_chat, debug=True)
    try:
        scraper.init_driver()
        chat_count = scraper.scrape_chat_list(tab, download_settings)
        print(f"Successfully processed {chat_count} chats")
        return 0
    except Exception as e:
        # Message only: a traceback could echo page content or credential material.
        print(f"Error during scraping: {str(e)}")
        return 1
    finally:
        scraper.close_driver()

if __name__ == "__main__":
    sys.exit(main())