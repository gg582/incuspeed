import platform
import os
import sys
import json
import threading
import re
import base64
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import bcrypt
import requests
from kivy.logger import Logger

# KivyMD Imports for building the UI
from kivy.lang import Builder
from kivy.metrics import dp
from kivy.properties import StringProperty, ObjectProperty
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.core.window import Window
from kivy.clock import Clock
from kivy.uix.widget import Widget
from kivymd.app import MDApp
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.label import MDLabel
from kivymd.uix.textfield import MDTextField
from kivymd.uix.button import MDRaisedButton
from kivymd.uix.selectioncontrol import MDCheckbox
from kivymd.uix.list import MDList
from kivymd.uix.scrollview import MDScrollView
from kivymd.uix.filemanager import MDFileManager

# Permission handling for Android
try:
    from jnius import autoclass
    from android.permissions import request_permissions, Permission
    Activity = autoclass('org.kivy.android.PythonActivity')
    Settings = autoclass('android.provider.Settings')
    Intent = autoclass('android.content.Intent')
    Environment = autoclass('android.os.Environment')
    Uri = autoclass('android.net.Uri')
except:
    Window.size = (400, 700)

def request_permissions(permissions, callback=None):
    try:
        current_activity = Activity.mActivity
        permissions_to_request = []
        for perm in permissions:
            if current_activity.checkSelfPermission(perm) != PackageManager.PERMISSION_GRANTED:
                permissions_to_request.append(perm)
        if permissions_to_request:
            current_activity.requestPermissions(permissions_to_request, 0)
        if callback:
            callback(True)
    except Exception as e:
        Logger.error(f"Permission request failed: {e}")

# Configuration
if getattr(sys, 'frozen', False):
    if platform.system() == 'Android':
        basedir = '/data/data/org.gg582.incuspeed/files/app/'
    else:
        basedir = os.path.dirname(sys.executable)
else:
    basedir = os.path.dirname(os.path.abspath(__file__))

SERVER_URL = "https://hobbies.yoonjin2.kr:32000"
GLOBAL_FONT_FILE = os.path.join(basedir, 'RobotoCJKSC-Regular.ttf')

# Set certificate path
if getattr(sys, 'frozen', False) or platform.system() == 'Android':
    cert_path = os.path.join(basedir, 'certs', 'ca.crt')
else:
    cert_path = './certs/ca.crt'

# Utility class for AES encryption and decryption
class CryptoHelper:
    @staticmethod
    def pad(s):
        return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

    @staticmethod
    def unpad(s):
        return s[:-ord(s[len(s) - 1:])]

    @staticmethod
    def encrypt(text, key):
        key = base64.b64decode(key)
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(CryptoHelper.pad(text).encode())
        return base64.b64encode(encrypted_text).decode(), base64.b64encode(iv).decode()

    @staticmethod
    def decrypt(encrypted_text, key, iv):
        key = base64.b64decode(key)
        iv = base64.b64decode(iv)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return CryptoHelper.unpad(cipher.decrypt(base64.b64decode(encrypted_text)).decode())

# Main screen for user input and primary actions
class MainScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        layout = MDBoxLayout(orientation='vertical', padding=dp(8), spacing=dp(8), size_hint=(1, 1), adaptive_height=True)
        self.layout = layout
        central_layout = MDBoxLayout(
            orientation='vertical',
            size_hint=(None, None),
            width=min(dp(320), Window.width * 0.8),
            pos_hint={'center_x': 0.5},
            spacing=dp(16)
        )
        central_layout.bind(minimum_height=central_layout.setter('height'))
        title_label = MDLabel(text="Linux Container Manager", halign='center', theme_text_color="Primary")
        central_layout.add_widget(title_label)
        self.username_input = MDTextField(hint_text="Username", size_hint_x=None, width=central_layout.width)
        self.password_input = MDTextField(hint_text="Password", password=True, size_hint_x=None, width=central_layout.width)
        self.container_tag = MDTextField(hint_text="Container Label (e.g., my-web-app)", size_hint_x=None, width=central_layout.width, max_text_length=10)
        self.distro = MDTextField(hint_text="Distro:Version (e.g., ubuntu:22.04)", size_hint_x=None, width=central_layout.width)
        central_layout.add_widget(self.username_input)
        central_layout.add_widget(self.password_input)
        central_layout.add_widget(self.distro)
        central_layout.add_widget(self.container_tag)
        buttons_container = MDBoxLayout(
            orientation='vertical',
            spacing=dp(16),
            size_hint_y=None,
            pos_hint={'center_x': 0.5},
            adaptive_size=True
        )
        self.create_container_button = MDRaisedButton(text="Create Container", on_release=self.create_container, size_hint_x=None)
        self.register_button = MDRaisedButton(text="Register", on_release=self.register_user, size_hint_x=None)
        self.unregister_button = MDRaisedButton(text="Unregister", on_release=self.unregister_user, size_hint_x=None)
        self.manage_button = MDRaisedButton(text="Manage Containers", on_release=self.go_to_manage, size_hint_x=1)
        self.manage_button.width = central_layout.width
        buttons_container.add_widget(self.create_container_button)
        buttons_container.add_widget(self.register_button)
        buttons_container.add_widget(self.unregister_button)
        buttons_container.add_widget(self.manage_button)
        central_layout.add_widget(Widget(size_hint_y=1))
        central_layout.add_widget(buttons_container)
        layout.add_widget(central_layout)
        self.result_label = MDLabel(text="", theme_text_color="Secondary", halign='center')
        layout.add_widget(self.result_label)
        self.add_widget(layout)
        self.containers = {}
        self.is_creating_container = False

    def go_to_manage(self, instance):
        if self.is_creating_container:
            self.result_label.text = "A container creation is in progress. Please wait."
            return
        if not self.username_input.text or not self.password_input.text:
            self.result_label.text = "Enter username and password before managing."
            return
        self.send_user_info()
        self.manager.current = "manage"

    def register_user(self, instance):
        if self.is_creating_container:
            self.result_label.text = "A container creation is in progress. Please wait."
            return
        if not self.username_input.text or not self.password_input.text:
            self.result_label.text = "Enter username and password to register."
            return
        self.send_user_info()
        self.send_request("register")

    def unregister_user(self, instance):
        if self.is_creating_container:
            self.result_label.text = "A container creation is in progress. Please wait."
            return
        if not self.username_input.text or not self.password_input.text:
            self.result_label.text = "Enter username and password to unregister."
            return
        self.send_user_info()
        self.send_request("unregister")

    def create_container(self, instance):
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
        username = self.username_input.text.strip()
        password = self.password_input.text.strip()
        if not username or not password:
            self.result_label.text = "Username and password cannot be empty."
            return
        key = base64.b64encode(get_random_bytes(32)).decode()
        encrypted_username, iv_username = CryptoHelper.encrypt(username, key)
        password_bytes = password.encode('utf-8')
        hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode('utf-8')
        self.manager.user_info = {
            "username": encrypted_username,
            "username_iv": iv_username,
            "password": hashed_password,
            "key": key,
        }
        self.send_request("request")

    def send_request(self, endpoint, selected_tag=None, file_path=None, file_target_path=None):
        headers = {'Content-Type': 'application/json'}
        data_to_send = None
        if endpoint == "register":
            username = self.username_input.text.strip()
            password = self.password_input.text.strip()
            if not username or not password:
                self.result_label.text = "Username and password cannot be empty."
                return
            key = base64.b64encode(get_random_bytes(32)).decode()
            encrypted_username, iv_username = CryptoHelper.encrypt(username, key)
            encrypted_password, iv_password = CryptoHelper.encrypt(password, key)
            data_to_send = {
                "username": encrypted_username,
                "username_iv": iv_username,
                "password": encrypted_password,
                "password_iv": iv_password,
                "key": key,
            }
        elif endpoint == "create":
            if not hasattr(self.manager, 'user_info'):
                self.result_label.text = "User info not found. Register first."
                self.is_creating_container = False
                self.create_container_button.disabled = False
                return
            password = self.password_input.text.strip()
            if not password:
                self.result_label.text = "Password cannot be empty."
                self.is_creating_container = False
                self.create_container_button.disabled = False
                return
            key = self.manager.user_info['key']
            encrypted_password, password_iv = CryptoHelper.encrypt(password, key)
            distroinfo = self.distro.text.strip()
            distroinfo = ''.join(c for c in distroinfo if re.match(r'[a-z0-9:.]', c))
            self.distro.text = distroinfo
            distro_and_version = distroinfo.split(":")
            if len(distro_and_version) != 2 or not distro_and_version[0] or not distro_and_version[1]:
                self.result_label.text = "Invalid distro:version format. Use 'distro:version'."
                self.is_creating_container = False
                self.create_container_button.disabled = False
                return
            distro, version = distro_and_version
            tag = self.container_tag.text.strip()
            tag = re.sub(r'[^a-zA-Z0-9-]+', '-', tag).strip('-')
            if not tag:
                self.result_label.text = "Container label cannot be empty."
                self.is_creating_container = False
                self.create_container_button.disabled = False
                return
            self.container_tag.text = tag
            data_to_send = {
                "username": self.manager.user_info['username'],
                "username_iv": self.manager.user_info['username_iv'],
                "password": encrypted_password,
                "password_iv": password_iv,
                "key": key,
                "tag": tag,
                "distro": distro,
                "version": version
            }
        elif endpoint in ["start", "stop", "restart", "pause", "delete", "resume"]:
            if not selected_tag:
                return
            data_to_send = selected_tag
            headers = {}
        elif endpoint == "upload":
            if not selected_tag or not file_path or not file_target_path:
                Logger.error(f"Upload failed: Missing tag={selected_tag}, path={file_path}, target={file_target_path}")
                return
            headers = {
                'X-Container-Name': selected_tag,
                'X-Host-Path': file_path,
                'X-File-Path': file_target_path,
                'Content-Type': 'application/octet-stream'
            }
            data_to_send = file_path
        else:
            if not hasattr(self.manager, 'user_info'):
                self.result_label.text = "User info not found. Register or log in."
                return
            data_to_send = {
                "username": self.manager.user_info['username'],
                "username_iv": self.manager.user_info['username_iv'],
                "password": self.manager.user_info['password'],
                "key": self.manager.user_info['key'],
            }
        threading.Thread(target=self._send_request_in_thread, args=(endpoint, headers, data_to_send, selected_tag)).start()

    def _send_request_in_thread(self, endpoint, headers, data_to_send, selected_tag):
        response_text = ""
        success = False
        containers_data = None
        try:
            if endpoint == "upload":
                with open(data_to_send, 'rb') as f:
                    file_content = f.read()
                Logger.info(f"Uploading file: {data_to_send} to {headers['X-File-Path']}")
                response = requests.post(
                    f"{SERVER_URL}/{endpoint}",
                    data=file_content,
                    headers=headers,
                    verify=cert_path,
                    timeout=3600
                )
                response.raise_for_status()
                response_text = response.text
                success = True
                Logger.info(f"Upload successful: {data_to_send}")
                time.sleep(1)  # Add 1-second delay to ensure server processes the upload
            elif endpoint in ["start", "stop", "restart", "pause", "delete", "resume"]:
                response = requests.post(f"{SERVER_URL}/{endpoint}", data=data_to_send, headers=headers, verify=cert_path)
                response.raise_for_status()
                response_text = response.text
                success = True
            else:
                response = requests.post(f"{SERVER_URL}/{endpoint}", json=data_to_send, headers=headers, verify=cert_path)
                response.raise_for_status()
                if endpoint == "request":
                    containers_data = json.loads(response.text)
                    if isinstance(containers_data, dict) and 'containers' in containers_data:
                        containers_data = containers_data.get('containers', [])
                    elif not isinstance(containers_data, list):
                        containers_data = []
                        response_text = "Server returned invalid container list format."
                    success = True
                else:
                    response_text = response.text
                    success = True
        except FileNotFoundError:
            response_text = f"File not found: {data_to_send}"
            Logger.error(response_text)
        except requests.exceptions.RequestException as e:
            response_text = f"Network error: {e}"
            Logger.error(response_text)
        except json.JSONDecodeError:
            response_text = "Failed to decode server response."
            Logger.error(response_text)
        except Exception as e:
            response_text = f"Unexpected error: {e}"
            Logger.error(response_text)
        finally:
            Clock.schedule_once(lambda dt: self._update_ui_after_request(endpoint, success, response_text, containers_data, selected_tag), 0)

    def _update_ui_after_request(self, endpoint, success, message, containers_data, selected_tag):
        current_screen = self.manager.current_screen
        manage_screen = self.manager.get_screen("manage")
        if endpoint == "create":
            self.is_creating_container = False
            self.create_container_button.disabled = False
        if success:
            if endpoint == "request" and containers_data is not None:
                self.containers = containers_data
                manage_screen.update_container_list(self.containers)
                if current_screen == self:
                    self.result_label.text = "Container list refreshed."
                elif current_screen == manage_screen:
                    manage_screen.feedback_label.text = "Container list refreshed."
                    manage_screen.is_processing_actions = False
                    manage_screen._toggle_action_buttons_state(True)
            elif endpoint == "register":
                self.result_label.text = "Registration successful!"
            elif endpoint == "unregister":
                self.result_label.text = "Unregistration successful!"
            elif endpoint == "upload":
                manage_screen.feedback_label.text = "File uploaded successfully."
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
            if endpoint == "create":
                self.is_creating_container = False
                self.create_container_button.disabled = False
            if current_screen == manage_screen:
                manage_screen.is_processing_actions = False
                manage_screen._toggle_action_buttons_state(True)

# Custom widget for displaying container details
class ContainerListItem(MDBoxLayout):
    tag = StringProperty()
    actualTag = StringProperty()
    port = StringProperty()
    status = StringProperty()
    distro = StringProperty()
    version = StringProperty()
    checkbox_active = ObjectProperty(False)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'horizontal'
        self.padding = dp(8)
        self.spacing = dp(32)
        self.size_hint_y = None
        self.height = dp(70)
        self._checkbox = MDCheckbox(on_release=self.on_checkbox_toggle)
        self.add_widget(self._checkbox)
        self.text_container = MDBoxLayout(orientation='vertical', adaptive_height=True, size_hint_x=1)
        self.tag_label = MDLabel(text=f"Label: {self.tag}", halign='left', adaptive_height=True, theme_text_color='Primary')
        self.distro_label = MDLabel(text=f"Distro: {self.distro}", halign='left', adaptive_height=True, theme_text_color='Primary')
        self.port_status_label = MDLabel(text=f"Port: {self.port}, Status: {self.status.capitalize()}", halign='left', adaptive_height=True, theme_text_color='Secondary')
        self.text_container.add_widget(self.tag_label)
        self.text_container.add_widget(self.distro_label)
        self.text_container.add_widget(self.port_status_label)
        self.add_widget(self.text_container)

    def on_tag(self, instance, value):
        if hasattr(self, 'tag_label'):
            self.tag_label.text = f"Label: {value}"

    def on_port(self, instance, value):
        if hasattr(self, 'port_status_label'):
            self.port_status_label.text = f"Port: {value}, Status: {self.status.capitalize()}"

    def on_status(self, instance, value):
        if hasattr(self, 'port_status_label'):
            self.port_status_label.text = f"Port: {self.port}, Status: {value.capitalize()}"

    def on_distro(self, instance, value):
        if hasattr(self, 'distro_label'):
            self.distro_label.text = f"Distro: {value}"

    def on_version(self, instance, value):
        if hasattr(self, 'distro_label'):
            self.distro_label.text = f"Distro: {self.distro}"

    def on_checkbox_toggle(self, checkbox):
        self.checkbox_active = checkbox.active

# Screen for managing containers
class ManageScreen(Screen):
    container_list = ObjectProperty(None)
    feedback_label = ObjectProperty(None)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.layout = MDBoxLayout(orientation='vertical', padding=dp(8), spacing=dp(16), size_hint=(1, 1))
        title_layout = MDBoxLayout(orientation='horizontal', size_hint_y=None, padding=(dp(4), 0))
        title_label = MDLabel(text="Container Management", halign='center', theme_text_color="Primary")
        title_layout.add_widget(title_label)
        self.layout.add_widget(title_layout)
        self.inc_path_input = MDTextField(hint_text="Container Target Path (e.g., /home/user/my_file.txt)", size_hint_x=1)
        self.inc_path_input.size_hint_y = None
        self.inc_path_input.height = dp(32)
        self.layout.add_widget(self.inc_path_input)
        self.scroll = MDScrollView()
        self.container_list = MDList(spacing=dp(35), padding=dp(20), size_hint_y=None, height=dp(70))
        self.scroll.add_widget(self.container_list)
        self.layout.add_widget(self.scroll)
        button_layout_bottom = MDBoxLayout(orientation='horizontal', spacing=dp(36), size_hint_y=None, height=dp(32), padding=(dp(8), 0))
        button_layout_second = MDBoxLayout(orientation='horizontal', spacing=dp(36), size_hint_y=None, height=dp(32), padding=(dp(8), 0))
        button_layout_third = MDBoxLayout(orientation='horizontal', spacing=dp(36), size_hint_y=None, height=dp(32), padding=(dp(8), 0))
        button_layout_fourth = MDBoxLayout(orientation='horizontal', spacing=dp(36), size_hint_y=None, height=dp(32), padding=(dp(8), 0))
        self.start_button = MDRaisedButton(text="Start", on_release=lambda x: self.manage_container("start"), size_hint_x=1)
        self.stop_button = MDRaisedButton(text="Stop", on_release=lambda x: self.manage_container("stop"), size_hint_x=1)
        self.delete_button = MDRaisedButton(text="Delete", on_release=lambda x: self.manage_container("delete"), size_hint_x=1)
        self.pause_button = MDRaisedButton(text="Pause", on_release=lambda x: self.manage_container("pause"), size_hint_x=1)
        self.resume_button = MDRaisedButton(text="Resume", on_release=lambda x: self.manage_container("resume"), size_hint_x=1)
        self.restart_button = MDRaisedButton(text="Restart", on_release=lambda x: self.manage_container("restart"), size_hint_x=1)
        self.refresh_button = MDRaisedButton(text="Refresh", on_release=self.list_containers_and_display_json, size_hint_x=1)
        self.go_back_button = MDRaisedButton(text="Back", on_release=lambda x: setattr(self.manager, "current", "main"), size_hint_x=1)
        self.upload_file_button = MDRaisedButton(text="Push File", on_release=self.open_file_manager, size_hint_x=1)
        button_layout_bottom.add_widget(self.start_button)
        button_layout_bottom.add_widget(self.stop_button)
        button_layout_bottom.add_widget(self.pause_button)
        button_layout_second.add_widget(self.resume_button)
        button_layout_second.add_widget(self.restart_button)
        button_layout_second.add_widget(self.delete_button)
        button_layout_third.add_widget(self.refresh_button)
        button_layout_third.add_widget(self.go_back_button)
        button_layout_fourth.add_widget(self.upload_file_button)
        self.layout.add_widget(button_layout_bottom)
        self.layout.add_widget(button_layout_second)
        self.layout.add_widget(button_layout_third)
        self.layout.add_widget(button_layout_fourth)
        self.feedback_label = MDLabel(text="", theme_text_color="Secondary", halign='center', size_hint_y=None, padding=(0, dp(5)))
        self.layout.add_widget(self.feedback_label)
        self.add_widget(self.layout)
        self.selected_containers = {}
        self.is_processing_actions = False
        self.file_manager = MDFileManager(
            exit_manager=self.exit_file_manager,
            select_path=self.select_file_path,
            ext=[],
            selector="multi"  # Multi-file selection
        )
        for style, font_props in self.file_manager.theme_cls.font_styles.items():
            if isinstance(font_props, list) and len(font_props) > 0 and os.path.exists(GLOBAL_FONT_FILE):
                if style.startswith('Body') or style == 'Subtitle1':
                    font_props[0] = GLOBAL_FONT_FILE

    def _toggle_action_buttons_state(self, enable):
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
        main_screen = self.manager.get_screen("main")
        if main_screen.is_creating_container or self.is_processing_actions:
            self.feedback_label.text = "Please wait for the current operation to finish."
            return
        if not hasattr(self.manager, 'user_info'):
            self.feedback_label.text = "User info not found. Log in again."
            return
        main_screen.send_request("request")

    def update_container_list(self, containers):
        if not isinstance(containers, list):
            Logger.error(f"Invalid container data: {containers}")
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
        placeholder = MDLabel(
            text="Container List",
            halign='center',
            theme_text_color="Hint",
            size_hint_y=None,
            height=dp(40),
            font_size=dp(9),
        )
        self.container_list.add_widget(placeholder)
        for container in containers:
            if not isinstance(container, dict):
                Logger.error(f"Invalid container entry: {container}")
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
        main_screen = self.manager.get_screen("main")
        if main_screen.is_creating_container or self.is_processing_actions:
            self.feedback_label.text = "Please wait for the current operation to finish."
            return
        selected_items = [item for item in self.container_list.children if isinstance(item, ContainerListItem) and item.checkbox_active]
        if not selected_items:
            self.feedback_label.text = "Select at least one container."
            return
        self.is_processing_actions = True
        self._toggle_action_buttons_state(False)
        self.feedback_label.text = f"Sending '{action}' request..."
        for item in selected_items:
            main_screen.send_request(action, selected_tag=item.actualTag)
        main_screen.send_request("request")

    def open_file_manager(self, instance):
        main_screen = self.manager.get_screen("main")
        if main_screen.is_creating_container or self.is_processing_actions:
            self.feedback_label.text = "Please wait for the current operation to finish."
            return
        selected_items = [item for item in self.container_list.children if isinstance(item, ContainerListItem) and item.checkbox_active]
        if len(selected_items) != 1:
            self.feedback_label.text = "Please select exactly ONE container to upload a file to."
            return
        if not self.inc_path_input.text.strip():
            self.feedback_label.text = "Please enter the target path in the container."
            return
        try:
            if platform.system() == 'Android':
                request_permissions([
                    Permission.READ_EXTERNAL_STORAGE,
                    Permission.WRITE_EXTERNAL_STORAGE,
                    Permission.MANAGE_EXTERNAL_STORAGE,
                ])
                if not Environment.isExternalStorageManager():
                    intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION)
                    uri = Uri.fromParts("package", Activity.mActivity.getPackageName(), None)
                    intent.setData(uri)
                    Activity.mActivity.startActivity(intent)
                    self.feedback_label.text = "Please allow full disk access."
                    return
                path = "/storage/emulated/0/Documents"
            elif platform.system() == 'Windows':
                path = os.path.expanduser("~")
                print("Windows client is untested. if there are some bugs from Windows, please make PR to GitHub")
            elif platform.system() == 'Darwin':
                path = os.path.expanduser("~/Documents")
            else:
                path = os.path.expanduser("~")
            if not os.path.exists(path):
                path = os.path.expanduser("~")
            Logger.info(f"Opening file manager at path: {path}")
            self.file_manager.show(path)
            self.manager_open = True
        except Exception as e:
            Logger.error(f"Failed to open file manager: {e}")
            self.feedback_label.text = f"Failed to open file manager: {e}"

    def select_file_path(self, paths):
        if not paths:
            self.feedback_label.text = "No files selected."
            self.exit_file_manager(None)
            return
        selected_items = [item for item in self.container_list.children if isinstance(item, ContainerListItem) and item.checkbox_active]
        if not selected_items:
            self.feedback_label.text = "No container selected."
            self.exit_file_manager(None)
            return
        container_target_path = self.inc_path_input.text.strip()
        if not container_target_path:
            self.feedback_label.text = "Container target path cannot be empty."
            self.exit_file_manager(None)
            return
        if not container_target_path.startswith('/'):
            self.feedback_label.text = "Target path must be an absolute path (start with '/')."
            self.exit_file_manager(None)
            return
        if container_target_path.startswith('..'):
            self.feedback_label.text = "Target path cannot start with '..'."
            self.exit_file_manager(None)
            return
        if len(paths) > 1 and container_target_path.endswith('.txt'):
            self.feedback_label.text = "Multiple files cannot be uploaded to a file path. Please specify a directory."
            self.exit_file_manager(None)
            return
        self.feedback_label.text = f"Uploading {len(paths)} file(s)..."
        self.is_processing_actions = True
        self._toggle_action_buttons_state(False)
        main_screen = self.manager.get_screen("main")
        for path in paths:
            main_screen.send_request("upload", selected_tag=selected_items[0].actualTag, file_path=path, file_target_path=container_target_path)
        self.exit_file_manager(None)

    def exit_file_manager(self, args):
        self.manager_open = False
        self.file_manager.close()

# Main application class
class ContainerApp(MDApp):
    def build(self):
        cjk_font_path = GLOBAL_FONT_FILE
        if not os.path.exists(cjk_font_path):
            Logger.warning(f"Font file {cjk_font_path} not found. Using default font.")
            cjk_font_path = None
        for style, font_props in self.theme_cls.font_styles.items():
            if isinstance(font_props, list) and len(font_props) > 0 and cjk_font_path:
                if style.startswith('Body') or style == 'Subtitle1':
                    font_props[0] = cjk_font_path
        kv_file_path = os.path.join(basedir, 'incuspeed.kv')
        if not os.path.exists(kv_file_path):
            Logger.error(f"KV file {kv_file_path} not found.")
            raise FileNotFoundError(f"KV file {kv_file_path} not found")
        Builder.load_file(kv_file_path)
        self.theme_cls.theme_style = "Light"
        sm = ScreenManager()
        main_screen = MainScreen(name="main")
        sm.add_widget(main_screen)
        sm.add_widget(ManageScreen(name="manage"))
        return sm

    def on_start(self):
        if platform.system() == 'Android':
            try:
                request_permissions([
                    Permission.READ_EXTERNAL_STORAGE,
                    Permission.WRITE_EXTERNAL_STORAGE,
                    Permission.MANAGE_EXTERNAL_STORAGE,
                ])
                if not Environment.isExternalStorageManager():
                    intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION)
                    uri = Uri.fromParts("package", Activity.mActivity.getPackageName(), None)
                    intent.setData(uri)
                    Activity.mActivity.startActivity(intent)
                    Logger.info("Requested full disk access permission")
            except Exception as e:
                Logger.error(f"Failed to request Android permissions: {e}")

if __name__ == "__main__":
    ContainerApp().run()
