from asyncio import MultiLoopChildWatcher
import os
import sys
import platform
import json
import threading
import re
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import bcrypt
import requests

# KivyMD Imports for building the UI
from kivy.lang import Builder
from kivy.metrics import dp
from kivy.properties import StringProperty, ObjectProperty
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.core.window import Window
from kivy.clock import Clock
from kivy.uix.widget import Widget

# KivyMD Widgets for UI components
from kivymd.app import MDApp
from kivymd.icon_definitions import md_icons
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.label import MDLabel
from kivymd.uix.textfield import MDTextField
from kivymd.uix.button import MDRaisedButton
from kivymd.uix.selectioncontrol import MDCheckbox
from kivymd.uix.list import MDList
from kivymd.uix.scrollview import MDScrollView
from kivymd.uix.filemanager import MDFileManager  # For file selection

# Permission handling for Android
from jnius import autoclass
from android import activity
from android.permissions import request_permissions, Permission
Activity = autoclass('org.kivy.android.PythonActivity')
Context = autoclass('android.content.Context')
PackageManager = autoclass('android.content.pm.PackageManager')
Permission = autoclass('android.Manifest$permission')

# NOTE: The actual display depends on whether your Korean font contains these glyphs.

EMOJI_CHECKBOX_UNCHECKED = '\u2B1C' # ⬜ (White Large Square - common for unchecked)
EMOJI_CHECKBOX_CHECKED = '\u2705'   # ✅ (White Heavy Check Mark - common for checked)
EMOJI_ARROW_LEFT = '\u2B05\uFE0F'   # ⬅️ (Leftwards Black Arrow, with emoji variation selector)
EMOJI_ARROW_RIGHT = '\u27A1\uFE0F'  # ➡️ (Black Rightwards Arrow, with emoji variation selector)
EMOJI_CHECK_MARK = '\u2714\uFE0F'   # ✔️ (Heavy Check Mark, with emoji variation selector)
EMOJI_FOLDER = '\U0001F4C1'         # 📁 (Folder)
EMOJI_FILE = '\U0001F4C4'           # 📄 (Page Facing Up - common for generic file)
EMOJI_PLUS = '\u2795'               # ➕ (Heavy Plus Sign)
EMOJI_MINUS = '\u2796'              # ➖ (Heavy Minus Sign)
EMOJI_STAR = '\u2B50'               # ⭐ (White Medium Star)
EMOJI_HEART = '\u2764\uFE0F'        # ❤️ (Heavy Black Heart, with emoji variation selector)


def request_permissions(permissions, callback=None):
    try:
        current_activity = Activity.mActivity
        permissions_to_request = []
        for perm in permissions:
            if current_activity.checkSelfPermission(perm) != PackageManager.PERMISSION_GRANTED:
                permissions_to_request.append(perm)
        if permissions_to_request:
            current_activity.requestPermissions(permissions_to_request, 0)
        elif callback:
            callback(True)
    except Exception as e:
        print("Error on permission request: ", e)
# Configuration
# Determine the base directory based on the execution environment
if getattr(sys, 'frozen', False):  # Running as a bundled app (e.g., Android APK)
    if platform.system() == 'Android':
        basedir = '/data/data/org.yoonjin67.incuspeed/files/app/'  # Android internal storage path
    else:  # Bundled on desktop (Windows, Linux, macOS)
        basedir = os.path.dirname(sys.executable)  # Directory of the executable
else:  # Running in development mode (from source)
    basedir = os.path.dirname(os.path.abspath(__file__))  # Directory of the script

SERVER_URL = "https://hobbies.yoonjin2.kr:32000"  # Server URL for API requests
cert_path = ""  # Certificate path, set dynamically based on platform

# Path to the global font file, assumed to be in the app's directory
GLOBAL_FONT_FILE = os.path.join(basedir, 'RobotoCJKSC-Regular.ttf')

# Utility class for AES encryption and decryption
class CryptoHelper:
    @staticmethod
    def pad(s):
        # Pad the input string to match AES block size
        return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

    @staticmethod
    def unpad(s):
        # Remove padding from the decrypted string
        return s[:-ord(s[len(s) - 1:])]

    @staticmethod
    def encrypt(text, key):
        # Encrypt text using AES-CBC with a random IV
        key = base64.b64decode(key)
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(CryptoHelper.pad(text).encode())
        return base64.b64encode(encrypted_text).decode(), base64.b64encode(iv).decode()

    @staticmethod
    def decrypt(encrypted_text, key, iv):
        # Decrypt text using AES-CBC with provided key and IV
        key = base64.b64decode(key)
        iv = base64.b64decode(iv)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return CryptoHelper.unpad(cipher.decrypt(base64.b64decode(encrypted_text)).decode())

# Main screen for user input and primary actions
class MainScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Create the main vertical layout
        layout = MDBoxLayout(orientation='vertical', padding=dp(8), spacing=dp(8), size_hint=(1, 1), adaptive_height=True)
        self.layout = layout

        # Create a centered vertical layout for UI elements
        central_layout = MDBoxLayout(
            orientation='vertical',
            size_hint=(None, None),
            width=min(dp(320), Window.width * 0.8),
            pos_hint={'center_x': 0.5},
            spacing=dp(16)
        )
        central_layout.bind(minimum_height=central_layout.setter('height'))

        # Add title label
        title_label = MDLabel(text="Linux Container Manager", halign='center', theme_text_color="Primary")
        central_layout.add_widget(title_label)

        # Add input fields for username, password, distro, and container tag
        self.username_input = MDTextField(hint_text="Username", size_hint_x=None, width=central_layout.width)
        self.password_input = MDTextField(hint_text="Password", password=True, size_hint_x=None, width=central_layout.width)
        self.container_tag = MDTextField(hint_text="Container Label (e.g., my-web-app)", size_hint_x=None, width=central_layout.width)
        self.distro = MDTextField(hint_text="Distro:Version (e.g., ubuntu:22.04)", size_hint_x=None, width=central_layout.width)

        central_layout.add_widget(self.username_input)
        central_layout.add_widget(self.password_input)
        central_layout.add_widget(self.distro)
        central_layout.add_widget(self.container_tag)

        # Create a container for action buttons
        buttons_container = MDBoxLayout(
            orientation='vertical',
            spacing=dp(16),
            size_hint_y=None,
            pos_hint={'center_x': 0.5},
            adaptive_size=True
        )

        # Add buttons for creating container, registering user, and managing containers
        self.create_container_button = MDRaisedButton(text="Create Container", on_release=self.create_container, size_hint_x=None)
        self.register_button = MDRaisedButton(text="Register", on_release=self.register_user, size_hint_x=None)
        self.manage_button = MDRaisedButton(text="Manage Containers", on_release=self.go_to_manage, size_hint_x=1)
        self.manage_button.width = central_layout.width

        buttons_container.add_widget(self.create_container_button)
        buttons_container.add_widget(self.register_button)
        buttons_container.add_widget(self.manage_button)

        # Add spacer and buttons to central layout
        central_layout.add_widget(Widget(size_hint_y=1))
        central_layout.add_widget(buttons_container)

        # Add central layout to main layout (fixes blank screen issue)
        layout.add_widget(central_layout)

        # Add result label for feedback
        self.result_label = MDLabel(text="", theme_text_color="Secondary", halign='center')
        layout.add_widget(self.result_label)

        # Add the main layout to the screen
        self.add_widget(layout)
        self.containers = {}  # Store container data
        self.is_creating_container = False  # Flag to track container creation status

    def go_to_manage(self, instance):
        # Navigate to the manage screen if conditions are met
        if self.is_creating_container:
            self.result_label.text = "A container creation is in progress. Please wait."
            return
        if not self.username_input.text or not self.password_input.text:
            self.result_label.text = "Enter username and password before managing."
            return
        self.send_user_info()
        self.manager.current = "manage"

    def register_user(self, instance):
        # Register a new user if conditions are met
        if self.is_creating_container:
            self.result_label.text = "A container creation is in progress. Please wait."
            return
        if not self.username_input.text or not self.password_input.text:
            self.result_label.text = "Enter username and password to register."
            return
        self.send_user_info()
        self.send_request("register")

    def create_container(self, instance):
        # Initiate container creation if conditions are met
        if self.is_creating_container:
            self.result_label.text = "Container creation already in progress. Please wait."
            return
        if not self.username_input.text or not self.password_input.text:
            self.result_label.text = "Enter username and password to create a container."
            return
        if not hasattr(self.manager, 'user_info') or 'username' not in self.manager.user_info or 'key' not in self.manager.user_info:
            self.result_label.text = "User info missing. Register or log in again."
            return
        self.is_creating_container = True
        self.create_container_button.disabled = True
        self.result_label.text = "Initiating container creation..."
        self.send_request("create")

    def send_user_info(self, instance=None):
        # Prepare and store user information
        username = self.username_input.text
        password = self.password_input.text
        key = base64.b64encode(get_random_bytes(32)).decode()
        encrypted_username, iv_username = CryptoHelper.encrypt(username, key)
        password_bytes = password.encode('utf-8')
        hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode('utf-8')
        data = {
            "username": encrypted_username,
            "username_iv": iv_username,
            "password": hashed_password,
            "key": key,
        }
        self.manager.user_info = data
        self.send_request("request")

    def send_request(self, endpoint, selected_tag=None, file_path=None, file_target_path=None):
        # Send HTTP request to the server based on the endpoint
        headers = {'Content-Type': 'application/json'}
        data_to_send = None

        if endpoint == "register":
            # Prepare data for user registration
            data_to_send = self.manager.user_info
        elif endpoint == "create":
            # Prepare data for container creation
            if not hasattr(self.manager, 'user_info'):
                self.result_label.text = "User info not found. Register first."
                self.is_creating_container = False
                self.create_container_button.disabled = False
                return
            password = self.password_input.text
            key = self.manager.user_info['key']
            encrypted_password, password_iv = CryptoHelper.encrypt(password, key)
            distroinfo = self.distro.text
            distroinfo = ''.join(filter(lambda x: re.match(r'[a-z0-9:.]', x), distroinfo))
            self.distro.text = distroinfo
            distro_and_version = distroinfo.split(":")
            if len(distro_and_version) < 2:
                self.result_label.text = "Invalid distro:version format. Use 'distro:version'."
                self.is_creating_container = False
                self.create_container_button.disabled = False
                return
            distro = distro_and_version[0]
            version = distro_and_version[1]
            modifiedformoftag = self.container_tag.text
            modifiedformoftag = re.sub(r'[^a-zA-Z0-9-]+', '-', modifiedformoftag)
            modifiedformoftag = modifiedformoftag.strip('-')
            if not modifiedformoftag:
                self.result_label.text = "Container label cannot be empty."
                self.is_creating_container = False
                self.create_container_button.disabled = False
                return
            self.container_tag.text = modifiedformoftag
            data_to_send = {
                "username": self.manager.user_info['username'],
                "username_iv": self.manager.user_info['username_iv'],
                "password": encrypted_password,
                "password_iv": password_iv,
                "key": self.manager.user_info['key'],
                "tag": modifiedformoftag,
                "distro": distro,
                "version": version
            }
        elif endpoint in ["start", "stop", "restart", "pause", "delete", "resume"]:
            # Prepare data for container actions
            if not selected_tag:
                return
            data_to_send = selected_tag
            headers = {}
        elif endpoint == "upload":
            # Prepare file upload data
            if not selected_tag or not file_path or not file_target_path:
                print("Missing info for file upload.")
                return
            data_to_send = file_path + '\u0000' + file_target_path
        else:
            # Prepare data for other requests (e.g., list containers)
            if not hasattr(self.manager, 'user_info'):
                self.result_label.text = "User info not found. Register or log in."
                return
            data_to_send = {
                "username": self.manager.user_info['username'],
                "username_iv": self.manager.user_info['username_iv'],
                "key": self.manager.user_info['key'],
            }

        # Start a thread to send the request
        threading.Thread(target=self._send_request_in_thread, args=(endpoint, headers, data_to_send, selected_tag)).start()

    def _send_request_in_thread(self, endpoint, headers, data_to_send, selected_tag):
        # Send HTTP request in a separate thread to avoid blocking the UI
        response_text = ""
        success = False
        containers_data = None
        try:
            if endpoint in ["start", "stop", "restart", "pause", "delete", "resume", "upload"]:
                if endpoint == "upload":

                    file_path, file_target_path  = data_to_send.split('\u0000')
                    try:
                        with open(file_path, 'rb') as f:
                            file_content = f.read()
                        headers = {
                            'X-Container-Name': selected_tag,
                            'X-File-Path': file_target_path,
                            'Content-Type': 'application/octet-stream'
                        }
                        data_to_send = file_content
                    except FileNotFoundError:
                        Clock.schedule_once(lambda dt: self._update_ui_after_request(endpoint, False, f"File not found: {file_path}", None, selected_tag), 0)
                        return

                    except Exception as e:
                        Clock.schedule_once(lambda dt: self._update_ui_after_request(endpoint, False, f"Error reading file: {e}",None, selected_tag), 0)
                        return
                    response = requests.post(f"{SERVER_URL}/{endpoint}", data=data_to_send, headers=headers, verify=cert_path, timeout=3600)
                else:
                    response = requests.post(f"{SERVER_URL}/{endpoint}", data=data_to_send, headers=headers, verify=cert_path)
            else:
                response = requests.post(f"{SERVER_URL}/{endpoint}", headers=headers, json=data_to_send, verify=cert_path)
            response.raise_for_status()
            if endpoint == "request":
                try:
                    containers_data = json.loads(response.text)
                    if isinstance(containers_data, dict) and 'containers' in containers_data:
                        containers_data = containers_data.get('containers', [])
                    elif not isinstance(containers_data, list):
                        containers_data = []
                        response_text = "Server returned invalid container list format."
                    success = True
                except json.JSONDecodeError:
                    response_text = "Failed to decode container list from server."
            else:
                response_text = response.text
                success = True
        except requests.exceptions.RequestException as e:
            response_text = f"Network Error: {e}"
        except Exception as e:
            response_text = f"Unexpected error: {e}"
        finally:
            # Schedule UI update on the main thread
            Clock.schedule_once(lambda dt: self._update_ui_after_request(endpoint, success, response_text, containers_data, selected_tag), 0)

    def _update_ui_after_request(self, endpoint, success, message, containers_data, selected_tag):
        # Update the UI based on the request outcome
        current_screen = self.manager.current_screen
        manage_screen = self.manager.get_screen("manage")
        if endpoint == "create":
            self.is_creating_container = False
            self.create_container_button.disabled = False
            if success:
                self.result_label.text = "Container creation successful! Refreshing list..."
                self.send_request("request")
            else:
                self.result_label.text = message
            return
        if success:
            if endpoint == "request" and containers_data is not None:
                self.containers = containers_data
                manage_screen.update_container_list(self.containers)
                if current_screen == self:
                    self.result_label.text = "Container list refreshed."
                elif current_screen == manage_screen:
                    manage_screen.feedback_label.text = "Container list refreshed."
                    if not self.is_creating_container:
                        manage_screen.is_processing_actions = False
                        manage_screen._toggle_action_buttons_state(True)
            elif endpoint == "register":
                self.result_label.text = "Registration successful!"
            elif endpoint == "upload":
                manage_screen.feedback_label.text = f"File uploaded"
                manage_screen.is_processing_actions = False
                manage_screen._toggle_action_buttons_state(True)
            else:
                if current_screen == manage_screen:
                    manage_screen.feedback_label.text = f"Action '{endpoint}' successful! Refreshing list..."
                if not self.is_creating_container:
                    self.send_request("request")
                else:
                    self.result_label.text = f"Action '{endpoint}' successful."
        else:
            if current_screen == self:
                self.result_label.text = message
            elif current_screen == manage_screen:
                manage_screen.feedback_label.text = message
                if not self.is_creating_container:
                    manage_screen.is_processing_actions = False
                    manage_screen._toggle_action_buttons_state(True)

# Custom widget for displaying container details in the manage screen
class ContainerListItem(MDBoxLayout):
    tag = StringProperty()  # Displayed container label
    actualTag = StringProperty()  # Actual container tag (including suffix)
    port = StringProperty()  # Container port
    status = StringProperty()  # Container status
    distro = StringProperty()  # Container distro
    version = StringProperty()  # Container version
    checkbox_active = ObjectProperty(False)  # Checkbox state

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Configure layout properties
        self.orientation = 'horizontal'
        self.padding = dp(8)
        self.spacing = dp(32)
        self.size_hint_y = None
        self.height = dp(70)

        # Add checkbox for selecting the container
        self._checkbox = MDCheckbox(on_release=self.on_checkbox_toggle)
        self.add_widget(self._checkbox)

        # Create a vertical layout for text labels
        self.text_container = MDBoxLayout(orientation='vertical', adaptive_height=True, size_hint_x=1)
        self.tag_label = MDLabel(text=f"Label: {self.tag}", halign='left', adaptive_height=True, theme_text_color='Primary')
        self.distro_label = MDLabel(text=f"Distro: {self.distro}", halign='left', adaptive_height=True, theme_text_color='Primary')
        self.port_status_label = MDLabel(text=f"Port: {self.port}, Status: {self.status.capitalize()}", halign='left', adaptive_height=True, theme_text_color='Secondary')

        # Add labels to text container
        self.text_container.add_widget(self.tag_label)
        self.text_container.add_widget(self.distro_label)
        self.text_container.add_widget(self.port_status_label)
        self.add_widget(self.text_container)

    def on_tag(self, instance, value):
        # Update tag label when tag property changes
        if hasattr(self, 'tag_label'):
            self.tag_label.text = f"Label: {value}"

    def on_port(self, instance, value):
        # Update port and status label when port property changes
        if hasattr(self, 'port_status_label'):
            self.port_status_label.text = f"Port: {value}, Status: {self.status.capitalize()}"

    def on_status(self, instance, value):
        # Update port and status label when status property changes
        if hasattr(self, 'port_status_label'):
            self.port_status_label.text = f"Port: {self.port}, Status: {value.capitalize()}"

    def on_distro(self, instance, value):
        # Update distro label when distro property changes
        if hasattr(self, 'distro_label'):
            self.distro_label.text = f"Distro: {value}"

    def on_version(self, instance, value):
        # Update distro label when version property changes
        if hasattr(self, 'distro_label'):
            self.distro_label.text = f"Distro: {self.distro}"

    def on_checkbox_toggle(self, checkbox):
        # Update checkbox state when toggled
        self.checkbox_active = checkbox.active

# Screen for managing containers
class ManageScreen(Screen):
    container_list = ObjectProperty(None)  # List widget for containers
    feedback_label = ObjectProperty(None)  # Label for feedback messages

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Create the main vertical layout
        self.layout = MDBoxLayout(orientation='vertical', padding=dp(8), spacing=dp(16), size_hint=(1, 1))

        # Add title layout
        title_layout = MDBoxLayout(orientation='horizontal', size_hint_y=None, padding=(dp(4), 0))
        title_label = MDLabel(text="Container Management", halign='center', theme_text_color="Primary")
        title_layout.add_widget(title_label)
        self.layout.add_widget(title_layout)

        self.inc_path_input = MDTextField(hint_text="Container Target Path (e.g., /home/user/my_file.txt)", size_hint_x=1)
        self.inc_path_input.size_hint_y = None
        self.inc_path_input.height = dp(32)
        self.layout.add_widget(self.inc_path_input)
        # Add scrollable container list
        self.scroll = MDScrollView()
        self.container_list = MDList(spacing=dp(35), padding=dp(20), size_hint_y=None, height=dp(70))
        self.scroll.add_widget(self.container_list)
        self.layout.add_widget(self.scroll)

        # Create button layouts for actions
        button_layout_bottom = MDBoxLayout(orientation='horizontal', spacing=dp(36), size_hint_y=None, height=dp(32), padding=(dp(8), 0))
        button_layout_second = MDBoxLayout(orientation='horizontal', spacing=dp(36), size_hint_y=None, height=dp(32), padding=(dp(8), 0))
        button_layout_third = MDBoxLayout(orientation='horizontal', spacing=dp(36), size_hint_y=None, height=dp(32), padding=(dp(8), 0))
        button_layout_fourth = MDBoxLayout(orientation='horizontal', spacing=dp(36), size_hint_y=None, height=dp(32), padding=(dp(8), 0))

        # Add action buttons
        self.start_button = MDRaisedButton(text="Start", on_release=lambda x: self.manage_container("start"), size_hint_x=1)
        self.stop_button = MDRaisedButton(text="Stop", on_release=lambda x: self.manage_container("stop"), size_hint_x=1)
        self.delete_button = MDRaisedButton(text="Delete", on_release=lambda x: self.manage_container("delete"), size_hint_x=1)
        self.pause_button = MDRaisedButton(text="Pause", on_release=lambda x: self.manage_container("pause"), size_hint_x=1)
        self.resume_button = MDRaisedButton(text="Resume", on_release=lambda x: self.manage_container("resume"), size_hint_x=1)
        self.restart_button = MDRaisedButton(text="Restart", on_release=lambda x: self.manage_container("restart"), size_hint_x=1)
        self.refresh_button = MDRaisedButton(text="Refresh", on_release=self.list_containers_and_display_json, size_hint_x=1)
        self.go_back_button = MDRaisedButton(text="Back", on_release=lambda x: setattr(self.manager, "current", "main"), size_hint_x=1)
        self.upload_file_button = MDRaisedButton(text="Push File", on_release=self.open_file_manager, size_hint_x=1)

        # Add input field for file upload path

        # Add buttons to their respective layouts
        button_layout_bottom.add_widget(self.start_button)
        button_layout_bottom.add_widget(self.stop_button)
        button_layout_bottom.add_widget(self.pause_button)
        button_layout_second.add_widget(self.resume_button)
        button_layout_second.add_widget(self.restart_button)
        button_layout_second.add_widget(self.delete_button)
        button_layout_third.add_widget(self.refresh_button)
        button_layout_third.add_widget(self.go_back_button)
        button_layout_fourth.add_widget(self.upload_file_button)

        # Add layouts and input field to main layout
        self.layout.add_widget(button_layout_bottom)
        self.layout.add_widget(button_layout_second)
        self.layout.add_widget(button_layout_third)
        self.layout.add_widget(button_layout_fourth)

        # Add feedback label
        self.feedback_label = MDLabel(text="", theme_text_color="Secondary", halign='center', size_hint_y=None, padding=(0, dp(5)))
        self.layout.add_widget(self.feedback_label) 

        # Add main layout to the screen
        self.add_widget(self.layout)
        self.selected_containers = {}  # Store selected containers
        self.is_processing_actions = False  # Flag for action status

        # Initialize file manager for file uploads
        self.file_manager = MDFileManager(
            exit_manager=self.exit_file_manager,
            select_path=self.select_file_path,
        )


        for style, font_props in self.file_manager.theme_cls.font_styles.items():
            print(f"Processing font style: {style}, props: {font_props}")
            cjk_font_path = GLOBAL_FONT_FILE
            if isinstance(font_props, list) and len(font_props) > 0 and cjk_font_path:
                if  style[:4] == 'Body' or style == 'Subtitle1':
                    font_props[0] = cjk_font_path  # Set font name only
    def _toggle_action_buttons_state(self, enable):
        # Enable or disable all action buttons and input field
        self.start_button.disabled = not enable
        self.stop_button.disabled = not enable
        self.pause_button.disabled = not enable
        self.resume_button.disabled = not enable
        self.restart_button.disabled = not enable
        self.delete_button.disabled = not enable
        self.refresh_button.disabled = not enable
        self.go_back_button.disabled = not enable
        self.upload_file_button.disabled = not enable
        self.inc_path_input.disabled = not enable

    def list_containers_and_display_json(self, instance):
        # Refresh the container list
        main_screen = self.manager.get_screen("main")
        if main_screen.is_creating_container:
            self.feedback_label.text = "Container creation in progress. Cannot refresh."
            return
        if self.is_processing_actions:
            self.feedback_label.text = "Please wait, an action is in progress."
            return
        if not hasattr(self.manager, 'user_info'):
            self.feedback_label.text = "User info not found. Log in again."
            return
        main_screen.send_request("request")

    def update_container_list(self, containers):
        # Update the container list UI with provided data
        if not isinstance(containers, list):
            print(f"Error: Expected list for containers, got {type(containers)}: {containers}")
            self.feedback_label.text = "Invalid container data received."
            self.container_list.clear_widgets()
            placeholder = MDLabel(
                text="No Containers Available",
                halign='center',
                theme_text_color="Hint",
                size_hint_y=None,
                height=dp(40),
                font_size=dp(9),
            )
            self.container_list.add_widget(placeholder)
            return

        self.container_list.clear_widgets()
        self.selected_containers = {}

        # Add placeholder label
        placeholder = MDLabel(
            text="Container List",
            halign='center',
            theme_text_color="Hint",
            size_hint_y=None,
            height=dp(40),
            font_size=dp(9),
        )
        self.container_list.add_widget(placeholder)

        # Add container items
        for container in containers:
            if not isinstance(container, dict):
                print(f"Error: Expected dict for container, got {type(container)}: {container}")
                continue
            tmp_tag = container.get('tag', 'unknown')
            tag_split = tmp_tag.split("-")
            container_label = "-".join(tag_split[:-1]) if len(tag_split) > 1 else tmp_tag
            item = ContainerListItem(
                tag=container_label,
                port=str(container.get('serverport', 'N/A')),
                distro=container.get('distro', 'N/A'),
                version=container.get('version', 'N/A'),
                status=container.get('vmstatus', 'unknown'),
                actualTag=tmp_tag
            )
            self.container_list.add_widget(item)
            self.selected_containers[tmp_tag] = item

    def manage_container(self, action):
        # Perform actions on selected containers
        main_screen = self.manager.get_screen("main")
        if main_screen.is_creating_container:
            self.feedback_label.text = "Container creation in progress. Cannot perform other actions."
            return
        if self.is_processing_actions:
            self.feedback_label.text = "Please wait, an action is in progress."
            return
        selected_items = [item for item in self.container_list.children if isinstance(item, ContainerListItem) and item.checkbox_active]
        if not selected_items:
            self.feedback_label.text = "Select at least one container."
            return
        self.is_processing_actions = True
        self._toggle_action_buttons_state(False)
        self.feedback_label.text = f"Sending '{action}' request for selected containers..."
        for item in selected_items:
            main_screen.send_request(action, selected_tag=item.actualTag)
        main_screen.send_request("request")
        self.feedback_label.text = "Container actions requested. List will refresh shortly."

    def open_file_manager(self, instance) -> None:
        # Request Android permissions for external storage.
        # This is crucial for accessing files on Android devices.
        request_permissions([
            Permission.READ_EXTERNAL_STORAGE,
            Permission.WRITE_EXTERNAL_STORAGE,
        ])

        # Get the main screen instance from the screen manager.
        main_screen = self.manager.get_screen("main")

        # Prevent opening the file manager if another operation (e.g., container creation)
        # or processing action is currently in progress.
        if main_screen.is_creating_container or self.is_processing_actions:
            self.feedback_label.text = "Please wait for the current operation to finish."
            return

        # Validate that exactly one container is selected for file upload.
        # Use isinstance correctly without 'obj:' or 'class_or_tuple:'.
        selected_items = [
            item for item in self.container_list.children
            if isinstance(item, ContainerListItem) and item.checkbox_active
        ]
        if len(selected_items) != 1:
            self.feedback_label.text = "Please select exactly ONE container to upload a file to."
            return

        # Validate that a target path within the container has been entered.
        # Use .strip() to account for whitespace-only input.
        if not self.inc_path_input.text.strip():
            self.feedback_label.text = "Please enter the target path in the container."
            return

        # If all validations pass, open the KivyMD file manager.
        # Ensure 'path' is passed as a keyword argument.
        import os # Ensure os module is imported if not already at the top.
        self.file_manager.show(path=os.path.expanduser("/storage/emulated/0/Documents"))
        # Set a flag indicating the file manager is open (useful for managing its state).
        self.manager_open = True

    def select_file_path(self, path):
        # Handle file selection for upload
        self.exit_file_manager()
        selected_items = [item for item in self.container_list.children if isinstance(item, ContainerListItem) and item.checkbox_active]
        if not selected_items:
            self.feedback_label.text = "No container selected. Cannot upload file."
            return
        container_target_path = self.inc_path_input.text.strip()
        if not container_target_path:
            self.feedback_label.text = "Container target path cannot be empty."
            return
        if not container_target_path.startswith('/'):
            self.feedback_label.text = "Target path must be an absolute path (start with '/')."
            return
        if container_target_path.startswith('..'):
            self.feedback_label.text = "Target path cannot start with '..'."
            return
        self.feedback_label.text = f"Pushing item ..."
        main_screen = self.manager.get_screen("main")
        main_screen.send_request("upload", selected_tag=selected_items[0].actualTag, file_path=path, file_target_path=container_target_path)
        self.feedback_label.text = ""

    def exit_file_manager(self):
        # Close the file manager
        self.file_manager.close()

# Main application class
class ContainerApp(MDApp):
    def build(self):
        # Configure the app and initialize screens
                # Font style for general body text (e.g., file/folder names)

        cjk_font_path = GLOBAL_FONT_FILE
        print(f"Checking font path: {cjk_font_path}")
        if not os.path.exists(cjk_font_path):
            print(f"Warning: Font file {cjk_font_path} not found. Using default font.")
            cjk_font_path = None
        for style, font_props in self.theme_cls.font_styles.items():
            print(f"Processing font style: {style}, props: {font_props}")
            if isinstance(font_props, list) and len(font_props) > 0 and cjk_font_path:
                if style[:4] == 'Body' or style == 'Subtitle1':
                    font_props[0] = cjk_font_path  # Set font name only
        kv_file_path = os.path.join(basedir, 'incuspeed.kv')
        print(f"Loading KV file: {kv_file_path}")
        if not os.path.exists(kv_file_path):
            print(f"Error: KV file {kv_file_path} not found.")
            raise FileNotFoundError(f"KV file {kv_file_path} not found")
        Builder.load_file(kv_file_path)
        self.theme_cls.theme_style = "Light"
        sm = ScreenManager()
        main_screen = MainScreen(name="main")
        sm.add_widget(main_screen)
        sm.add_widget(ManageScreen(name="manage"))
        print("Build completed, returning screen manager")
        return sm
    def on_start(self):
        request_permissions([
            Permission.READ_EXTERNAL_STORAGE,
            Permission.WRITE_EXTERNAL_STORAGE,
        ])

if __name__ == "__main__":
    # Set certificate path and run the app
    if getattr(sys, 'frozen', False):
        if platform.system() == 'Android':
            cert_path = os.path.join(basedir, 'certs', 'ca.crt')
        else:
            cert_path = os.path.join(basedir, 'certs', 'ca.crt')
    else:
        cert_path = './certs/ca.crt'
    ContainerApp().run()

