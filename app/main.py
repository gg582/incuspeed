import bcrypt
from kivymd.app import MDApp
from kivy.uix.screenmanager import ScreenManager, Screen
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.textfield import MDTextField
from kivymd.uix.button import MDRaisedButton
from kivymd.uix.label import MDLabel
from kivy.uix.widget import Widget
from kivymd.uix.selectioncontrol import MDCheckbox
from kivymd.uix.list import MDList, OneLineAvatarIconListItem
from kivymd.uix.scrollview import MDScrollView
from kivy.properties import ObjectProperty, StringProperty
from kivy.metrics import dp
from kivy.utils import platform
from kivy.core.window import Window
import requests
import json
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sys

SERVER_URL = "http://hobbies.yoonjin2.kr:32000"

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
        central_layout = MDBoxLayout(orientation='vertical', size_hint=(None, None), width=min(dp(320), Window.width * 0.8), pos_hint={'center_x': 0.5}, spacing=dp(20))
        central_layout.bind(minimum_height=central_layout.setter('height'))

        title_label = MDLabel(text="Linux Container Manager", halign='center', theme_text_color="Primary", font_style="H6")
        central_layout.add_widget(title_label)

        self.username_input = MDTextField(hint_text="Username", size_hint_x=None, width=central_layout.width)
        self.password_input = MDTextField(hint_text="Password", password=True, size_hint_x=None, width=central_layout.width)
        central_layout.add_widget(self.username_input)
        central_layout.add_widget(self.password_input)

        buttons_container = MDBoxLayout(orientation='vertical', spacing=dp(15), size_hint_y=None, pos_hint={'center_x': 0.5}, adaptive_size = True)
        self.create_container_button = MDRaisedButton(text="Create Container", on_release=self.create_container, size_hint_x=None)
        self.register_button = MDRaisedButton(text="Register", on_release=self.register_user, size_hint_x=None)
        self.manage_button = MDRaisedButton(text="Manage Containers", on_release=self.go_to_manage, size_hint_x=None)

        buttons_container.add_widget(self.create_container_button)
        buttons_container.add_widget(self.register_button)
        buttons_container.add_widget(self.manage_button)

        central_layout.add_widget(Widget(size_hint_y=1))
        central_layout.add_widget(buttons_container)

        layout.add_widget(central_layout)

        self.result_label = MDLabel(text="", theme_text_color="Secondary", halign='center', font_style="Caption")
        layout.add_widget(self.result_label)

        self.add_widget(layout)

    def go_to_manage(self, instance):
        if not self.username_input.text or not self.password_input.text:
            self.result_label.text = "Please enter username and password before managing."
            return
        self.send_user_info()
        self.manager.current = "manage"

    def register_user(self, instance):
        if not self.username_input.text or not self.password_input.text:
            self.result_label.text = "Please enter username and password to register."
            return
        self.send_user_info()
        self.send_request("register")

    def create_container(self, instance):
        if not self.username_input.text or not self.password_input.text:
            self.result_label.text = "Please enter username and password to create a container."
            return
        if not hasattr(self.manager, 'user_info') or 'username' not in self.manager.user_info or 'key' not in self.manager.user_info or 'username_iv' not in self.manager.user_info:
            self.result_label.text = "User information not available. Please register or log in again."
            return
        self.send_request("create")

    def send_user_info(self):
        username = self.username_input.text
        password = self.password_input.text
        key = base64.b64encode(get_random_bytes(32)).decode()

        encrypted_username, iv_username = CryptoHelper.encrypt(username, key)
        password_bytes = password.encode('utf-8')
        hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode('utf-8') # Decode to string

        data = {
            "username": encrypted_username,
            "username_iv": iv_username,
            "password": hashed_password,
            "key": key,
        }
        self.manager.user_info = data

    def send_request(self, endpoint):
        headers = {'Content-Type': 'application/json'}
    
        if endpoint == "register":
            data = self.manager.user_info
    
        elif endpoint == "create":
            if not hasattr(self.manager, 'user_info'):
                self.result_label.text = "User information not found. Please register first."
                return
    
            password = self.password_input.text
            key = self.manager.user_info['key']
            encrypted_password, password_iv = CryptoHelper.encrypt(password, key)
            data = {
                "username": self.manager.user_info['username'],
                "username_iv": self.manager.user_info['username_iv'],
                "password": encrypted_password,
                "password_iv": password_iv,
                "key": self.manager.user_info['key'],
            }
    
        else:
            if not hasattr(self.manager, 'user_info'):
                self.result_label.text = "User information not found. Please register first."
                return
    
            # For action endpoints like start, stop, restart, pause, delete, etc.
            if endpoint in ["start", "stop", "restart", "pause", "delete", "freeze", "unfreeze"]:
                if not hasattr(self, 'current_selected_tag') or not self.current_selected_tag:
                    self.result_label.text = "No container selected. Please select a container first."
                    return
    
                # Send only the raw tag as the request body
                response = requests.post(f"{SERVER_URL}/{endpoint}", data=self.current_selected_tag)
            else:
                # For request or other actions that don't require container_tag
                data = {
                    "username": self.manager.user_info['username'],
                    "username_iv": self.manager.user_info['username_iv'],
                    "key": self.manager.user_info['key'],
                }
                response = requests.post(f"{SERVER_URL}/{endpoint}", headers=headers, json=data)
    
        try:
            response.raise_for_status()
            self.result_label.text = response.text
    
            # For 'request' endpoint, handle container list response
            if endpoint == "request":
                try:
                    containers = json.loads(response.text)
                    if self.manager.current == "manage":
                        manage_screen = self.manager.get_screen("manage")
                        manage_screen.update_container_list(containers)
                except json.JSONDecodeError:
                    if self.manager.current == "manage":
                        manage_screen = self.manager.get_screen("manage")
                        manage_screen.container_list.clear_widgets()
                        manage_screen.container_list.add_widget(MDLabel(text="Failed to decode container list", theme_text_color="Error", halign='center'))
    
        except requests.exceptions.RequestException as e:
            self.result_label.text = f"Error: {e}"
        except Exception as e:
            self.result_label.text = f"An unexpected error occurred: {e}"
    

class ContainerListItem(MDBoxLayout):
    tag = StringProperty()
    port = StringProperty()
    status = StringProperty()
    checkbox_active = ObjectProperty(False)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'horizontal'
        self.padding = dp(8)
        self.spacing = dp(8)
        self.size_hint_y = None
        self.height = dp(70)

        self._checkbox = MDCheckbox(on_release=self.on_checkbox_toggle)
        self.add_widget(self._checkbox)

        self.text_container = MDBoxLayout(orientation='vertical', adaptive_height=True, size_hint_x=1)
        self.tag_label = MDLabel(text=f"{self.tag}", halign='left', adaptive_height=True, theme_text_color='Primary')
        self.port_status_label = MDLabel(text=f"Port: {self.port}, Status: {self.status.capitalize()}", halign='left', adaptive_height=True, theme_text_color='Secondary')
        self.text_container.add_widget(self.tag_label)
        self.text_container.add_widget(self.port_status_label)
        self.add_widget(self.text_container)

    def on_tag(self, instance, value):
        if hasattr(self, 'tag_label'): # 속성이 생성되었는지 확인
            self.tag_label.text = f"Tag: {value}"

    def on_port(self, instance, value):
        if hasattr(self, 'port_status_label'): # 속성이 생성되었는지 확인
            self.port_status_label.text = f"Port: {value}, Status: {self.status.capitalize()}"

    def on_status(self, instance, value):
        if hasattr(self, 'port_status_label'): # 속성이 생성되었는지 확인
            self.port_status_label.text = f"Port: {self.port}, Status: {value.capitalize()}"

    def on_checkbox_toggle(self, checkbox):
        self.checkbox_active = checkbox.active

class ManageScreen(Screen):
    container_list = ObjectProperty(None)
    feedback_label = ObjectProperty(None)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.layout = MDBoxLayout(orientation='vertical', padding=dp(8), spacing=dp(4), size_hint=(1, 1)) # layout 간격 및 padding 줄임

        title_layout = MDBoxLayout(orientation='horizontal', size_hint_y=None, padding=(dp(4), 0)) # title padding 줄임
        title_label = MDLabel(text="Container Management", halign='center', theme_text_color="Primary", font_style="H6")
        title_layout.add_widget(title_label)
        self.layout.add_widget(title_layout)


        self.scroll = MDScrollView()
        self.container_list = MDList(spacing=dp(4), padding=dp(16), size_hint_y=None) # MDList 간격 줄임
        self.container_list.bind(minimum_height=self.container_list.setter('height'))
        self.scroll.add_widget(self.container_list)
        self.layout.add_widget(self.scroll)

        button_layout_bottom = MDBoxLayout(orientation='horizontal', spacing=dp(3), size_hint_y=None, padding=(dp(2), 0)) # 버튼 레이아웃 간격 및 padding 줄임
        button_layout_bottom_second_line = MDBoxLayout(orientation='horizontal', spacing=dp(3), size_hint_y=None, padding=(dp(2), 0)) # 버튼 레이아웃 간격 및 padding 줄임
        button_layout_bottom_third_line = MDBoxLayout(orientation='horizontal', spacing=dp(3), size_hint_y=None, padding=(dp(2), 0)) # 버튼 레이아웃 간격 및 padding 줄임
        self.start_button = MDRaisedButton(text="Start", on_release=lambda x: self.manage_container("start"), size_hint_x=0.2)
        self.stop_button = MDRaisedButton(text="Stop", on_release=lambda x: self.manage_container("stop"), size_hint_x=0.2)
        self.pause_button = MDRaisedButton(text="Pause", on_release=lambda x: self.manage_container("pause"), size_hint_x=0.2)
        self.restart_button = MDRaisedButton(text="Restart", on_release=lambda x: self.manage_container("restart"), size_hint_x=0.2)
        self.delete_button = MDRaisedButton(text="Delete", on_release=lambda x: self.manage_container("delete"), size_hint_x=0.2)
        self.refresh_button = MDRaisedButton(text="Refresh", on_release=self.list_containers_and_display_json, size_hint_x=0.5)
        self.go_back_button = MDRaisedButton(text="Back", on_release=lambda x: setattr(self.manager, "current", "main"), size_hint_x=0.5)
        button_layout_bottom.add_widget(self.start_button)
        button_layout_bottom.add_widget(self.stop_button)
        button_layout_bottom.add_widget(self.delete_button)
        button_layout_bottom_second_line.add_widget(self.pause_button)
        button_layout_bottom_second_line.add_widget(self.restart_button)
        button_layout_bottom_third_line.add_widget(self.refresh_button)
        button_layout_bottom_third_line.add_widget(self.go_back_button)
        self.layout.add_widget(button_layout_bottom)
        self.layout.add_widget(button_layout_bottom_second_line)
        self.layout.add_widget(button_layout_bottom_third_line)

        self.feedback_label = MDLabel(text="", theme_text_color="Secondary", halign='center', font_style="Caption", size_hint_y=None, padding=(0, dp(5))) # feedback label padding 줄임
        self.layout.add_widget(self.feedback_label)

        self.add_widget(self.layout)
        self.selected_containers = {}

    def list_containers_and_display_json(self, instance):
        if not hasattr(self.manager, 'user_info'):
            self.feedback_label.text = "User information not found. Please log in again."
            return
        self.manager.get_screen("main").send_request("request")

    def update_container_list(self, containers):
        self.container_list.clear_widgets()
        self.selected_containers = {}
        for container in containers:
            item = ContainerListItem(tag=container['tag'], port=container['serverport'], status=container['vmstatus'])
            self.container_list.add_widget(item)
            self.selected_containers[container['tag']] = item

    def manage_container(self, action):
        selected_items = [item for item in self.container_list.children if isinstance(item, ContainerListItem) and item.checkbox_active]
        if not selected_items:
            self.feedback_label.text = "Please select at least one container."
            return

        main_screen = self.manager.get_screen("main")
        for item in selected_items:
            main_screen.current_selected_tag = item.tag
            main_screen.send_request(action)
        main_screen.current_selected_tag = None # Reset selection after action
        self.list_containers_and_display_json(None)

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
    ContainerApp().run()
