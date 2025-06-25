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

# KivyMD Imports
from kivy.lang import Builder
from kivy.metrics import dp
from kivy.properties import StringProperty, ObjectProperty
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.core.window import Window
from kivy.clock import Clock
from kivy.uix.widget import Widget

# KivyMD Widgets
from kivymd.app import MDApp
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.label import MDLabel
from kivymd.uix.textfield import MDTextField
from kivymd.uix.button import MDRaisedButton
from kivymd.uix.selectioncontrol import MDCheckbox
from kivymd.uix.list import MDList
from kivymd.uix.scrollview import MDScrollView
from kivymd.uix.filemanager import MDFileManager # For file selection


# Configuration
SERVER_URL = "https://hobbies.yoonjin2.kr:32000"
cert_path = "" # This will be set dynamically based on platform

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
            spacing=dp(20)
        )
        central_layout.bind(minimum_height=central_layout.setter('height'))

        title_label = MDLabel(text="Linux Container Manager", halign='center', theme_text_color="Primary", font_style="H6")
        central_layout.add_widget(title_label)

        self.username_input = MDTextField(hint_text="Username", size_hint_x=None, width=central_layout.width)
        self.password_input = MDTextField(hint_text="Password", password=True, size_hint_x=None, width=central_layout.width)
        self.container_tag = MDTextField(hint_text="Container Label (e.g., my-web-app)", size_hint_x=None, width=central_layout.width)
        self.distro = MDTextField(hint_text="Distro:Version (e.g., ubuntu:22.04)", size_hint_x=None, width=central_layout.width)

        central_layout.add_widget(self.username_input)
        central_layout.add_widget(self.password_input)
        central_layout.add_widget(self.distro)
        central_layout.add_widget(self.container_tag)

        buttons_container = MDBoxLayout(
            orientation='vertical',
            spacing=dp(15),
            size_hint_y=None,
            pos_hint={'center_x': 0.5},
            adaptive_size = True
        )

        self.create_container_button = MDRaisedButton(text="Create Container", on_release=self.create_container, size_hint_x=None)
        self.register_button = MDRaisedButton(text="Register", on_release=self.register_user, size_hint_x=None)
        self.manage_button = MDRaisedButton(text="Manage Containers", on_release=self.go_to_manage, size_hint_x=1)
        self.manage_button.width = central_layout.width

        buttons_container.add_widget(self.create_container_button)
        buttons_container.add_widget(self.register_button)
        buttons_container.add_widget(self.manage_button)


        central_layout.add_widget(Widget(size_hint_y=1))
        central_layout.add_widget(buttons_container)

        layout.add_widget(central_layout)

        self.result_label = MDLabel(text="", theme_text_color="Secondary", halign='center', font_style="Caption")
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

    def create_container(self, instance):
        if self.is_creating_container:
            self.result_label.text = "Container creation already in progress. Please wait."
            return

        if not self.username_input.text or not self.password_input.text:
            self.result_label.text = "Enter username and password to create a container."
            return
        if not hasattr(self.manager, 'user_info') or 'username' not in self.manager.user_info or 'key' not in self.manager.user_info or 'username_iv' not in self.manager.user_info:
            self.result_label.text = "User info missing. Register or log in again."
            return

        self.is_creating_container = True
        self.create_container_button.disabled = True
        self.result_label.text = "Initiating container creation..."
        self.send_request("create")

    def send_user_info(self, instance=None): # Added instance=None to allow calling without an event
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
        headers = {'Content-Type': 'application/json'}
        data_to_send = None

        if endpoint == "register":
            data_to_send = self.manager.user_info
        elif endpoint == "create":
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
            if not selected_tag:
                return
            data_to_send = selected_tag
            headers = {}
        elif endpoint == "upload":
            if not selected_tag or not file_path or not file_target_path:
                print("Missing info for file upload.")
                return
            
            try:
                with open(file_path, 'rb') as f:
                    file_content = f.read()
                
                headers = {
                    'X-Container-Name': selected_tag,
                    'X-File-Path': file_target_path, # Send the full absolute path as entered by the user
                    'Content-Type': 'application/octet-stream'
                }
                data_to_send = file_content
                
            except FileNotFoundError:
                Clock.schedule_once(lambda dt: self._update_ui_after_request(endpoint, False, f"File not found: {file_path}", None), 0)
                return
            except Exception as e:
                Clock.schedule_once(lambda dt: self._update_ui_after_request(endpoint, False, f"Error reading file: {e}", None), 0)
                return

        else:
            if not hasattr(self.manager, 'user_info'):
                self.result_label.text = "User info not found. Register or log in."
                return
            data_to_send = {
                "username": self.manager.user_info['username'],
                "username_iv": self.manager.user_info['username_iv'],
                "key": self.manager.user_info['key'],
            }
        
        threading.Thread(target=self._send_request_in_thread, args=(endpoint, headers, data_to_send, selected_tag)).start()

    def _send_request_in_thread(self, endpoint, headers, data_to_send, selected_tag):
        response_text = ""
        success = False
        containers_data = None
        
        try:
            if endpoint in ["start", "stop", "restart", "pause", "delete", "resume", "upload"]:
                response = requests.post(f"{SERVER_URL}/{endpoint}", data=data_to_send, headers=headers, verify=cert_path)
            else:
                response = requests.post(f"{SERVER_URL}/{endpoint}", headers=headers, json=data_to_send, verify=cert_path)

            response.raise_for_status()

            if endpoint == "request":
                try:
                    containers_data = json.loads(response.text)
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
            Clock.schedule_once(lambda dt: self._update_ui_after_request(endpoint, success, response_text, containers_data, selected_tag), 0)

    def _update_ui_after_request(self, endpoint, success, message, containers_data, selected_tag):
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
                # Update feedback message: no more '/root/' prefix
                manage_screen.feedback_label.text = f"File uploaded to {selected_tag} at {manage_screen.inc_path_input.text.strip()}: {message}"
                manage_screen.is_processing_actions = False
                manage_screen._toggle_action_buttons_state(True)
            else:
                if current_screen == manage_screen:
                    manage_screen.feedback_label.text = f"Action '{endpoint}' successful! Refreshing list..."
                if not self.is_creating_container:
                    self.send_request("request")
                else:
                    self.result_label.text = f"Action '{endpoint}' successful, waiting for container creation refresh."
        else:
            if current_screen == self:
                self.result_label.text = message
            elif current_screen == manage_screen:
                manage_screen.feedback_label.text = message
                if not self.is_creating_container:
                    manage_screen.is_processing_actions = False
                    manage_screen._toggle_action_buttons_state(True)

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
        self.spacing = dp(16)
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
        if hasattr(self, 'port_label'): # Corrected from port_status_label to port_label if exists
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

class ManageScreen(Screen):
    container_list = ObjectProperty(None)
    feedback_label = ObjectProperty(None)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.layout = MDBoxLayout(orientation='vertical', padding=dp(8), spacing=dp(4), size_hint=(1, 1))

        title_layout = MDBoxLayout(orientation='horizontal', size_hint_y=None, padding=(dp(4), 0))
        title_label = MDLabel(text="Container Management", halign='center', theme_text_color="Primary", font_style="H6")
        title_layout.add_widget(title_label)
        self.layout.add_widget(title_layout)

        self.scroll = MDScrollView()
        self.container_list = MDList(spacing=dp(12), padding=dp(12), size_hint_y=None)
        self.container_list.bind(minimum_height=self.container_list.setter('height'))
        self.scroll.add_widget(self.container_list)
        self.layout.add_widget(self.scroll)

        button_layout_bottom = MDBoxLayout(orientation='horizontal', spacing=dp(16), size_hint_y=None, height=dp(48), padding=(dp(8), 0))
        button_layout_bottom_second_line = MDBoxLayout(orientation='horizontal', spacing=dp(16), size_hint_y=None, height=dp(48), padding=(dp(8), 0))
        button_layout_bottom_third_line = MDBoxLayout(orientation='horizontal', spacing=dp(16), size_hint_y=None, height=dp(48), padding=(dp(8), 0))
        button_layout_bottom_fourth_line = MDBoxLayout(orientation='horizontal', spacing=dp(16), size_hint_y=None, height=dp(48), padding=(dp(8), 0))

        self.start_button = MDRaisedButton(text="Start", on_release=lambda x: self.manage_container("start"), size_hint_x=1)
        self.stop_button = MDRaisedButton(text="Stop", on_release=lambda x: self.manage_container("stop"), size_hint_x=1)
        self.delete_button = MDRaisedButton(text="Delete", on_release=lambda x: self.manage_container("delete"), size_hint_x=1)
        self.pause_button = MDRaisedButton(text="Pause", on_release=lambda x: self.manage_container("pause"), size_hint_x=1)
        self.resume_button = MDRaisedButton(text="Resume", on_release=lambda x: self.manage_container("resume"), size_hint_x=1)
        self.restart_button = MDRaisedButton(text="Restart", on_release=lambda x: self.manage_container("restart"), size_hint_x=1)
        self.refresh_button = MDRaisedButton(text="Refresh", on_release=self.list_containers_and_display_json, size_hint_x=1)
        self.go_back_button = MDRaisedButton(text="Back", on_release=lambda x: setattr(self.manager, "current", "main"), size_hint_x=1)
        
        self.upload_file_button = MDRaisedButton(text="Push File", on_release=self.open_file_manager, size_hint_x=1)
        # HINT TEXT UPDATED: Now prompts for an absolute path
        self.inc_path_input = MDTextField(hint_text="Container Target Path (e.g., /home/user/my_file.txt)", size_hint_x=1)
        self.inc_path_input.size_hint_y = None
        self.inc_path_input.height = dp(48)


        button_layout_bottom.add_widget(self.start_button)
        button_layout_bottom.add_widget(self.stop_button)
        button_layout_bottom.add_widget(self.pause_button)
        button_layout_bottom_second_line.add_widget(self.resume_button)
        button_layout_bottom_second_line.add_widget(self.restart_button)
        button_layout_bottom_second_line.add_widget(self.delete_button)
        button_layout_bottom_third_line.add_widget(self.refresh_button)
        button_layout_bottom_third_line.add_widget(self.go_back_button)
        
        button_layout_bottom_fourth_line.add_widget(self.upload_file_button)
        self.layout.add_widget(self.inc_path_input)


        self.layout.add_widget(button_layout_bottom)
        self.layout.add_widget(button_layout_bottom_second_line)
        self.layout.add_widget(button_layout_bottom_third_line)
        self.layout.add_widget(button_layout_bottom_fourth_line)


        self.feedback_label = MDLabel(text="", theme_text_color="Secondary", halign='center', font_style="Caption", size_hint_y=None, padding=(0, dp(5)))
        self.layout.add_widget(self.feedback_label)

        self.add_widget(self.layout)
        self.selected_containers = {}
        self.is_processing_actions = False

        self.file_manager = MDFileManager(
            exit_manager=self.exit_file_manager,
            select_path=self.select_file_path,
        )

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
        self.container_list.clear_widgets()
        self.selected_containers = {}

        placeholder = MDLabel(
            text="Container List",
            halign='center',
            theme_text_color="Hint",
            size_hint_y=None,
            height=dp(40),
        )
        self.container_list.add_widget(placeholder)

        for container in containers:
            tmp_tag = container['tag']
            tag_split = tmp_tag.split("-")
            if len(tag_split) > 1:
                container_label = "-".join(tag_split[:-1])
            else:
                container_label = tmp_tag

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

    def open_file_manager(self, instance):
        main_screen = self.manager.get_screen("main")
        if main_screen.is_creating_container or self.is_processing_actions:
            self.feedback_label.text = "Wait for current operation to finish."
            return

        selected_items = [item for item in self.container_list.children if isinstance(item, ContainerListItem) and item.checkbox_active]
        if len(selected_items) != 1:
            self.feedback_label.text = "Please select exactly ONE container to upload a file to."
            return
        
        if not self.inc_path_input.text.strip():
            self.feedback_label.text = "Please enter the target path in the container."
            return

        self.file_manager.show(os.path.expanduser("~"))

    def select_file_path(self, path):
        self.exit_file_manager()
        
        selected_items = [item for item in self.container_list.children if isinstance(item, ContainerListItem) and item.checkbox_active]
        if not selected_items:
            self.feedback_label.text = "No container selected. Cannot upload file."
            return
        
        container_target_path = self.inc_path_input.text.strip()

        if not container_target_path:
            self.feedback_label.text = "Container target path cannot be empty."
            return

        # The Go server now expects and requires an absolute path.
        # So, the client should not remove the leading slash or perform other path manipulations.
        # Just validate that the user input is an absolute path.
        if not container_target_path.startswith('/'):
            self.feedback_label.text = "Target path must be an absolute path (start with '/')."
            return
        
        # Prevent paths starting with '..' which are generally unsafe,
        # even though filepath.Clean handles '/../' within absolute paths on the server.
        if container_target_path.startswith('..'):
            self.feedback_label.text = "Target path cannot start with '..'."
            return

        self.is_processing_actions = True
        self._toggle_action_buttons_state(False)
        # Update feedback message: removed '/root/' prefix
        self.feedback_label.text = f"Pushing '{os.path.basename(path)}' to {selected_items[0].actualTag} at {container_target_path}..."
        
        main_screen = self.manager.get_screen("main")
        main_screen.send_request("upload", selected_tag=selected_items[0].actualTag, file_path=path, file_target_path=container_target_path)


    def exit_file_manager(self, *args):
        self.file_manager.close()


class ContainerApp(MDApp):
    def build(self):
        self.theme_cls.theme_style = "Light"
        sm = ScreenManager()
        sm.user_info = {}
        
        main_screen = MainScreen(name="main")
        sm.add_widget(main_screen)
        sm.add_widget(ManageScreen(name="manage"))
        
        return sm

if __name__ == "__main__":
    if getattr(sys, 'frozen', False):
        if platform.system() == 'Android':
            basedir = '/data/data/org.yoonjin67.lvirtfront/files/app/certs'
            cert_path = os.path.join(basedir, 'ca.crt')
        else:
            basedir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'certs')
            cert_path = os.path.join(basedir, 'ca.crt')
    else:
        cert_path = './certs/ca.crt'
        
    ContainerApp().run()
