from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.togglebutton import ToggleButton
from kivy.uix.gridlayout import GridLayout
import requests
import json
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

SERVER_URL = "http://hobbies.yoonjin2.kr:32000"

class CryptoHelper:
    """AES 암호화 및 복호화를 위한 유틸리티 클래스"""
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
        layout = BoxLayout(orientation='vertical')

        self.username_input = TextInput(hint_text="Username")
        self.password_input = TextInput(hint_text="Password", password=True)
        layout.add_widget(self.username_input)
        layout.add_widget(self.password_input)

        self.register_button = Button(text="Register")
        self.register_button.bind(on_press=self.register_user)
        layout.add_widget(self.register_button)

        self.create_container_button = Button(text="Create Container")
        self.create_container_button.bind(on_press=self.create_container)
        layout.add_widget(self.create_container_button)

        self.manage_button = Button(text="Manage Containers")
        self.manage_button.bind(on_press=self.go_to_manage)
        layout.add_widget(self.manage_button)

        self.result_label = Label(text="")
        layout.add_widget(self.result_label)

        self.add_widget(layout)

    def go_to_manage(self, instance):
        self.manager.current = "manage"

    def register_user(self, instance):
        self.send_request("register")

    def create_container(self, instance):
        self.send_request("create")

    def send_request(self, endpoint):
        username = self.username_input.text
        password = self.password_input.text
        key = base64.b64encode(get_random_bytes(32)).decode()

        encrypted_username, iv_username = CryptoHelper.encrypt(username, key)
        encrypted_password, iv_password = CryptoHelper.encrypt(password, key)

        data = {
            "username": encrypted_username,
            "username_iv": iv_username,
            "password": encrypted_password,
            "password_iv": iv_password,
            "key": key,
            "vmstatus": "stopped"
        }
        self.manager.user_info = data

        response = requests.post(f"{SERVER_URL}/{endpoint}", json=data)
        self.result_label.text = response.text

class ManageScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.layout = BoxLayout(orientation='vertical')

        self.container_grid = GridLayout(cols=3)
        self.layout.add_widget(self.container_grid)

        self.refresh_button = Button(text="Refresh Containers")
        self.refresh_button.bind(on_press=self.list_containers)
        self.layout.add_widget(self.refresh_button)

        self.stop_button = Button(text="Stop Selected")
        self.stop_button.bind(on_press=lambda x: self.manage_container("stop"))
        self.layout.add_widget(self.stop_button)

        self.start_button = Button(text="Start Selected")
        self.start_button.bind(on_press=lambda x: self.manage_container("start"))
        self.layout.add_widget(self.start_button)

        self.delete_button = Button(text="Delete Selected")
        self.delete_button.bind(on_press=lambda x: self.manage_container("delete"))
        self.layout.add_widget(self.delete_button)

        self.go_back_button = Button(text="Go Back")
        self.go_back_button.bind(on_press=lambda x: setattr(self.manager, "current", "main"))
        self.layout.add_widget(self.go_back_button)

        self.add_widget(self.layout)
        self.selected_containers = {}
        self.toggle_group = "container_group"

    def list_containers(self, instance):
        if not self.manager or not hasattr(self.manager, 'user_info'):
            return

        try:
            response = requests.post(f"{SERVER_URL}/request", json=self.manager.user_info)
            print(response.text)
            response.raise_for_status()
            containers = json.loads(response.text)
            self.container_grid.clear_widgets()
            self.selected_containers.clear()

            for container in containers:
                port_label = Label(text=str(container['serverport']))
                stats_label = Label(text=str(container['vmstatus']))
                tag_label = Label(text=container['tag'])
                toggle_button = ToggleButton(group=self.toggle_group)
                self.selected_containers[container['tag']] = toggle_button

                self.container_grid.add_widget(port_label)
                self.container_grid.add_widget(tag_label)
                self.container_grid.add_widget(toggle_button)
                self.container_grid.add_widget(stats_label)
        except requests.exceptions.RequestException as e:
            error_label = Label(text=f"Failed to refresh containers: {e}")
            self.container_grid.clear_widgets()
            self.container_grid.add_widget(error_label)
        except json.JSONDecodeError as e:
            error_label = Label(text=f"Failed to decode server response.")
            self.container_grid.clear_widgets()
            self.container_grid.add_widget(error_label)

    def manage_container(self, action):
        if not self.manager or not hasattr(self.manager, 'user_info'):
            return

        selected_tags = [tag for tag, tb in self.selected_containers.items() if tb.state == 'down']
        for tag in selected_tags:
            data = tag
            try:
                response = requests.post(f"{SERVER_URL}/{action}", json=data)
                response.raise_for_status()
            except requests.exceptions.RequestException as e:
                error_label = Label(text=f"Failed to {action} container {tag}.")
                self.container_grid.add_widget(error_label)

        self.list_containers(None)

class ContainerApp(App):
    def build(self):
        sm = ScreenManager()
        sm.user_info = {}
        sm.add_widget(MainScreen(name="main"))
        sm.add_widget(ManageScreen(name="manage"))
        return sm

if __name__ == "__main__":
    ContainerApp().run()
#Auto Generated by Gemini
