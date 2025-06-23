from kivymd.app import MDApp
from kivy.uix.screenmanager import ScreenManager, Screen
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.textfield import MDTextField
from kivymd.uix.button import MDRaisedButton
from kivymd.uix.label import MDLabel
from kivy.uix.widget import Widget
from kivymd.uix.selectioncontrol import MDCheckbox
from kivymd.uix.list import MDList
from kivymd.uix.scrollview import MDScrollView
from kivy.properties import ObjectProperty, StringProperty
from kivy.metrics import dp
from kivy.utils import platform
from kivy.core.window import Window
from kivy.clock import Clock # Kivy Clock for UI updates from threads

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

import sys
import bcrypt
import requests
import json
import base64
import os
import re
import threading # For running network requests in a separate thread
# import time # Not needed for blocking wait anymore

# Configuration
SERVER_URL = "https://hobbies.yoonjin2.kr:32000"
cert_path = "" # This will be set dynamically based on platform

class CryptoHelper:
    """Helper class for AES encryption and decryption."""
    @staticmethod
    def pad(s):
        """Pads the input string to be a multiple of AES block size."""
        return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

    @staticmethod
    def unpad(s):
        """Unpads the string after decryption."""
        return s[:-ord(s[len(s) - 1:])]

    @staticmethod
    def encrypt(text, key):
        """Encrypts text using AES in CBC mode."""
        key = base64.b64decode(key)
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(CryptoHelper.pad(text).encode())
        return base64.b64encode(encrypted_text).decode(), base64.b64encode(iv).decode()

    @staticmethod
    def decrypt(encrypted_text, key, iv):
        """Decrypts text using AES in CBC mode."""
        key = base64.b64decode(key)
        iv = base64.b64decode(iv)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return CryptoHelper.unpad(cipher.decrypt(base64.b64decode(encrypted_text)).decode())

class MainScreen(Screen):
    """
    Main screen for user authentication and container creation.
    Handles login, registration, and creation of new containers.
    """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Main layout of the screen
        layout = MDBoxLayout(orientation='vertical', padding=dp(8), spacing=dp(8), size_hint=(1, 1), adaptive_height=True)
        self.layout = layout # Keep a reference to the main layout

        # Central layout for input fields and buttons, responsive width
        central_layout = MDBoxLayout(
            orientation='vertical',
            size_hint=(None, None),
            width=min(dp(320), Window.width * 0.8), # Responsive width
            pos_hint={'center_x': 0.5},
            spacing=dp(20)
        )
        central_layout.bind(minimum_height=central_layout.setter('height')) # Adjust height based on content

        # Title label
        title_label = MDLabel(text="Linux Container Manager", halign='center', theme_text_color="Primary", font_style="H6")
        central_layout.add_widget(title_label)

        # Input fields for user credentials and container details
        self.username_input = MDTextField(hint_text="Username", size_hint_x=None, width=central_layout.width)
        self.password_input = MDTextField(hint_text="Password", password=True, size_hint_x=None, width=central_layout.width)
        self.container_tag = MDTextField(hint_text="Container Label (e.g., my-web-app)", size_hint_x=None, width=central_layout.width)
        self.distro = MDTextField(hint_text="Distro:Version (e.g., ubuntu:22.04)", size_hint_x=None, width=central_layout.width)

        central_layout.add_widget(self.username_input)
        central_layout.add_widget(self.password_input)
        central_layout.add_widget(self.distro)
        central_layout.add_widget(self.container_tag)

        # Container for action buttons
        buttons_container = MDBoxLayout(
            orientation='vertical',
            spacing=dp(15),
            size_hint_y=None,
            pos_hint={'center_x': 0.5},
            adaptive_size = True
        )

        # Action buttons
        self.create_container_button = MDRaisedButton(text="Create Container", on_release=self.create_container, size_hint_x=None)
        self.register_button = MDRaisedButton(text="Register", on_release=self.register_user, size_hint_x=None)
        self.manage_button = MDRaisedButton(text="Manage Containers", on_release=self.go_to_manage, size_hint_x=None)

        buttons_container.add_widget(self.create_container_button)
        buttons_container.add_widget(self.register_button)
        buttons_container.add_widget(self.manage_button)

        central_layout.add_widget(Widget(size_hint_y=1)) # Spacer widget
        central_layout.add_widget(buttons_container)

        layout.add_widget(central_layout)

        # Label to display operation results or errors
        self.result_label = MDLabel(text="", theme_text_color="Secondary", halign='center', font_style="Caption")
        layout.add_widget(self.result_label)

        self.add_widget(layout)
        self.container_info = {} # To store info about containers (will be populated by 'request' endpoint)
        self.is_creating_container = False # Flag specifically for container creation to debounce

    def go_to_manage(self, instance):
        """Navigates to the ManageScreen after sending user info."""
        # Check if a create operation is in progress, as it might affect the current state.
        if self.is_creating_container:
            self.result_label.text = "A container creation is in progress. Please wait until it completes."
            return

        if not self.username_input.text or not self.password_input.text:
            self.result_label.text = "Please enter username and password before managing."
            return
        self.send_user_info() # Send user info and trigger container list refresh
        self.manager.current = "manage" # Change screen

    def register_user(self, instance):
        """Registers a new user."""
        # Check if a create operation is in progress.
        if self.is_creating_container:
            self.result_label.text = "A container creation is in progress. Please wait until it completes."
            return

        if not self.username_input.text or not self.password_input.text:
            self.result_label.text = "Please enter username and password to register."
            return
        self.send_user_info() # Prepare user info for sending
        self.send_request("register") # Send registration request

    def create_container(self, instance):
        """Initiates container creation."""
        if self.is_creating_container: # Prevent multiple concurrent create requests
            self.result_label.text = "Container creation already in progress. Please wait."
            return

        if not self.username_input.text or not self.password_input.text:
            self.result_label.text = "Please enter username and password to create a container."
            return
        # Ensure user info is available before creating a container
        if not hasattr(self.manager, 'user_info') or 'username' not in self.manager.user_info or 'key' not in self.manager.user_info or 'username_iv' not in self.manager.user_info:
            self.result_label.text = "User information not available. Please register or log in again."
            return

        self.is_creating_container = True # Set flag to prevent further create clicks
        self.create_container_button.disabled = True # Disable button visually
        self.result_label.text = "Initiating container creation..."
        self.send_request("create") # Send container creation request

    def send_user_info(self):
        """Prepares user information for API requests."""
        username = self.username_input.text
        password = self.password_input.text
        key = base64.b64encode(get_random_bytes(32)).decode() # Generate a new key for encryption

        # Encrypt username and hash password
        encrypted_username, iv_username = CryptoHelper.encrypt(username, key)
        password_bytes = password.encode('utf-8')
        hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode('utf-8')

        # Store user info in manager for access across screens
        data = {
            "username": encrypted_username,
            "username_iv": iv_username,
            "password": hashed_password,
            "key": key,
        }
        self.manager.user_info = data
        self.send_request("request") # Request updated container list upon setting user info

    def send_request(self, endpoint):
        """
        Sends an API request to the server in a separate thread to prevent UI freezing.
        Handles data preparation based on the endpoint.
        """
        # No global is_processing check here, specific debouncing for create is handled
        # ManageScreen handles its own processing actions
        headers = {'Content-Type': 'application/json'}
        data_to_send = None # Data payload for the request

        if endpoint == "register":
            # For registration, send the prepared user_info
            data_to_send = self.manager.user_info
        elif endpoint == "create":
            # Data preparation for container creation
            if not hasattr(self.manager, 'user_info'):
                self.result_label.text = "User information not found. Please register first."
                self.is_creating_container = False # Reset flag on error
                self.create_container_button.disabled = False # Re-enable button
                return

            password = self.password_input.text
            key = self.manager.user_info['key']
            encrypted_password, password_iv = CryptoHelper.encrypt(password, key)

            # Sanitize distro and version input
            distroinfo = self.distro.text
            # Allow alphanumeric, colon, and dot characters for distro:version
            distroinfo = ''.join(filter(lambda x: re.match(r'[a-z0-9:.]', x), distroinfo))
            self.distro.text = distroinfo # Update text field with sanitized value

            distro_and_version = distroinfo.split(":")
            if len(distro_and_version) < 2:
                self.result_label.text = "Invalid distro:version format. Please use 'distro:version'."
                self.is_creating_container = False # Reset flag on error
                self.create_container_button.disabled = False # Re-enable button
                return
            distro = distro_and_version[0]
            version = distro_and_version[1]

            # Sanitize container tag input: allow alphanumeric and hyphens, replace others with hyphens
            modifiedformoftag = self.container_tag.text
            modifiedformoftag = re.sub(r'[^a-zA-Z0-9-]+', '-', modifiedformoftag)
            # Ensure tag doesn't start or end with a hyphen if it's solely due to replacement
            modifiedformoftag = modifiedformoftag.strip('-')
            if not modifiedformoftag: # If after sanitization, it's empty
                self.result_label.text = "Container label cannot be empty after sanitization."
                self.is_creating_container = False # Reset flag on error
                self.create_container_button.disabled = False # Re-enable button
                return
            self.container_tag.text = modifiedformoftag # Update text field with sanitized value

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
            # For container actions, the current_selected_tag is sent as raw data
            if not hasattr(self, 'current_selected_tag') or not self.current_selected_tag:
                self.result_label.text = "No container selected. Please select a container first."
                # Don't disable buttons here, as this might be called from ManageScreen's batch actions
                return
            data_to_send = self.current_selected_tag # The actual tag string
            headers = {} # No Content-Type for raw body string
        else: # For "request" or other endpoints that just need user_info for authentication
            if not hasattr(self.manager, 'user_info'):
                self.result_label.text = "User information not found. Please register or log in first."
                return
            data_to_send = {
                "username": self.manager.user_info['username'],
                "username_iv": self.manager.user_info['username_iv'],
                "key": self.manager.user_info['key'],
            }
        
        # Start a new thread to perform the HTTP request
        threading.Thread(target=self._send_request_in_thread, args=(endpoint, headers, data_to_send)).start()

    def _send_request_in_thread(self, endpoint, headers, data_to_send):
        """
        Internal method executed in a separate thread to handle the actual HTTP request.
        """
        response_text = ""
        success = False
        containers_data = None
        
        # This try-finally block ensures that the is_creating_container flag is reset
        # even if an error occurs during the request.
        try:
            if endpoint in ["start", "stop", "restart", "pause", "delete", "resume"]:
                response = requests.post(f"{SERVER_URL}/{endpoint}", data=data_to_send, verify=cert_path)
            else:
                response = requests.post(f"{SERVER_URL}/{endpoint}", headers=headers, json=data_to_send, verify=cert_path)

            response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)

            if endpoint == "request":
                # For 'request' endpoint, parse JSON response for container list
                try:
                    containers_data = json.loads(response.text)
                    success = True
                except json.JSONDecodeError:
                    response_text = "Failed to decode container list from server."
            else:
                # For other endpoints, assume success if no HTTPError and get generic response text
                response_text = response.text
                success = True

        except requests.exceptions.RequestException as e:
            # Handle network-related errors
            response_text = f"Network Error: {e}"
        except Exception as e:
            # Catch any other unexpected errors
            response_text = f"An unexpected error occurred: {e}"
        finally:
            # Schedule UI update on the main Kivy thread
            Clock.schedule_once(lambda dt: self._update_ui_after_request(endpoint, success, response_text, containers_data), 0)

    def _update_ui_after_request(self, endpoint, success, message, containers_data):
        """
        Callback method executed on the main Kivy thread to update the UI
        after an API request completes.
        """
        current_screen = self.manager.current_screen
        manage_screen = self.manager.get_screen("manage") # Get reference to manage screen

        if endpoint == "create":
            # Reset create-specific flags and re-enable the button
            self.is_creating_container = False
            self.create_container_button.disabled = False
            if success:
                self.result_label.text = "Container creation successful! Refreshing list..."
                self.send_request("request") # Immediately refresh the list after creation
            else:
                self.result_label.text = message
            return # Create operation handled, exit.

        # For other endpoints (request, register, actions from manage screen)
        if success:
            if endpoint == "request" and containers_data is not None:
                # Update container list on both screens
                self.containers = containers_data
                manage_screen.update_container_list(self.containers)
                # Display feedback on the appropriate screen
                if current_screen == self: # If on MainScreen
                    self.result_label.text = "Container list refreshed."
                elif current_screen == manage_screen: # If on ManageScreen
                    manage_screen.feedback_label.text = "Container list refreshed."
                    # Re-enable manage screen buttons after list refresh completes
                    # Only if MainScreen's create is not in progress.
                    if not self.is_creating_container: # Check if create is not active
                        manage_screen.is_processing_actions = False
                        manage_screen._toggle_action_buttons_state(True)
            elif endpoint == "register":
                self.result_label.text = "Registration successful!"
            else: # For container actions (start, stop, delete, etc.)
                # Provide feedback on manage screen and trigger list refresh
                if current_screen == manage_screen:
                    manage_screen.feedback_label.text = f"Action '{endpoint}' successful! Refreshing list..."
                # Trigger a list refresh, which will then re-enable manage screen buttons
                # Only if MainScreen's create is not in progress.
                if not self.is_creating_container: # Check if create is not active
                    self.send_request("request")
                else:
                    # If create is in progress, just update its label and let create's refresh handle it
                    self.result_label.text = f"Action '{endpoint}' successful, waiting for container creation refresh."
        else:
            # Display error message on the appropriate screen
            if current_screen == self:
                self.result_label.text = message
            elif current_screen == manage_screen:
                manage_screen.feedback_label.text = message
                # Re-enable manage screen buttons on error
                # Only if MainScreen's create is not in progress.
                if not self.is_creating_container: # Check if create is not active
                    manage_screen.is_processing_actions = False
                    manage_screen._toggle_action_buttons_state(True)

class ContainerListItem(MDBoxLayout):
    """
    Custom list item widget to display individual container details.
    Includes a checkbox for selection.
    """
    tag = StringProperty() # User-friendly label for the container
    actualTag = StringProperty() # The actual unique tag used by the backend
    port = StringProperty()
    status = StringProperty()
    distro = StringProperty()
    version = StringProperty()
    checkbox_active = ObjectProperty(False) # State of the checkbox

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'horizontal'
        self.padding = dp(8)
        self.spacing = dp(16)
        self.size_hint_y = None
        self.height = dp(70) # Fixed height for consistency

        # Checkbox for selecting the container
        self._checkbox = MDCheckbox(on_release=self.on_checkbox_toggle)
        self.add_widget(self._checkbox)

        # Container for text labels
        self.text_container = MDBoxLayout(orientation='vertical', adaptive_height=True, size_hint_x=1)
        self.tag_label = MDLabel(text=f"Label: {self.tag}", halign='left', adaptive_height=True, theme_text_color='Primary')
        self.distro_label = MDLabel(text=f"Distro: {self.distro}", halign='left', adaptive_height=True, theme_text_color='Primary')
        self.port_status_label = MDLabel(text=f"Port: {self.port}, Status: {self.status.capitalize()}", halign='left', adaptive_height=True, theme_text_color='Secondary')
        
        self.text_container.add_widget(self.tag_label)
        self.text_container.add_widget(self.distro_label) # Added distro label
        self.text_container.add_widget(self.port_status_label)
        self.add_widget(self.text_container)

    # Property observers to update labels when properties change
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
        """Callback for checkbox state change."""
        self.checkbox_active = checkbox.active # Update internal state

class ManageScreen(Screen):
    """
    Screen for managing existing containers.
    Displays a list of containers and provides actions (start, stop, delete, etc.).
    """
    container_list = ObjectProperty(None) # MDList widget for containers
    feedback_label = ObjectProperty(None) # Label for displaying feedback to the user

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Main layout for the screen
        self.layout = MDBoxLayout(orientation='vertical', padding=dp(8), spacing=dp(4), size_hint=(1, 1))

        # Title layout
        title_layout = MDBoxLayout(orientation='horizontal', size_hint_y=None, padding=(dp(4), 0))
        title_label = MDLabel(text="Container Management", halign='center', theme_text_color="Primary", font_style="H6")
        title_layout.add_widget(title_label)
        self.layout.add_widget(title_layout)

        # Scrollable container list
        self.scroll = MDScrollView()
        self.container_list = MDList(spacing=dp(12), padding=dp(12), size_hint_y=None) # Adjusted spacing/padding
        self.container_list.bind(minimum_height=self.container_list.setter('height'))
        self.scroll.add_widget(self.container_list)
        self.layout.add_widget(self.scroll)

        # Buttons for container actions, arranged in multiple lines for better layout
        button_layout_bottom = MDBoxLayout(orientation='horizontal', spacing=dp(16), size_hint_y=None, height=dp(48), padding=(dp(8), 0))
        button_layout_bottom_second_line = MDBoxLayout(orientation='horizontal', spacing=dp(16), size_hint_y=None, height=dp(48), padding=(dp(8), 0))
        button_layout_bottom_third_line = MDBoxLayout(orientation='horizontal', spacing=dp(16), size_hint_y=None, height=dp(48), padding=(dp(8), 0))

        # Action buttons
        self.start_button = MDRaisedButton(text="Start", on_release=lambda x: self.manage_container("start"), size_hint_x=1)
        self.stop_button = MDRaisedButton(text="Stop", on_release=lambda x: self.manage_container("stop"), size_hint_x=1)
        self.delete_button = MDRaisedButton(text="Delete", on_release=lambda x: self.manage_container("delete"), size_hint_x=1)
        self.pause_button = MDRaisedButton(text="Pause", on_release=lambda x: self.manage_container("pause"), size_hint_x=1)
        self.resume_button = MDRaisedButton(text="Resume", on_release=lambda x: self.manage_container("resume"), size_hint_x=1)
        self.restart_button = MDRaisedButton(text="Restart", on_release=lambda x: self.manage_container("restart"), size_hint_x=1)
        self.refresh_button = MDRaisedButton(text="Refresh", on_release=self.list_containers_and_display_json, size_hint_x=1)
        self.go_back_button = MDRaisedButton(text="Back", on_release=lambda x: setattr(self.manager, "current", "main"), size_hint_x=1)

        # Add buttons to their respective layouts
        button_layout_bottom.add_widget(self.start_button)
        button_layout_bottom.add_widget(self.stop_button)
        button_layout_bottom.add_widget(self.pause_button)
        button_layout_bottom_second_line.add_widget(self.resume_button)
        button_layout_bottom_second_line.add_widget(self.restart_button)
        button_layout_bottom_second_line.add_widget(self.delete_button)
        button_layout_bottom_third_line.add_widget(self.refresh_button)
        button_layout_bottom_third_line.add_widget(self.go_back_button)

        # Add all button layouts to the main screen layout
        self.layout.add_widget(button_layout_bottom)
        self.layout.add_widget(button_layout_bottom_second_line)
        self.layout.add_widget(button_layout_bottom_third_line)

        # Feedback label for displaying messages on this screen
        self.feedback_label = MDLabel(text="", theme_text_color="Secondary", halign='center', font_style="Caption", size_hint_y=None, padding=(0, dp(5)))
        self.layout.add_widget(self.feedback_label)

        self.add_widget(self.layout)
        self.selected_containers = {} # Dictionary to store references to selected items (not strictly used for selection logic, but can be for state)
        self.is_processing_actions = False # Flag to prevent multiple concurrent actions on this screen

    def _toggle_action_buttons_state(self, enable):
        """Enables or disables action buttons on the manage screen."""
        self.start_button.disabled = not enable
        self.stop_button.disabled = not enable
        self.pause_button.disabled = not enable
        self.resume_button.disabled = not enable
        self.restart_button.disabled = not enable
        self.delete_button.disabled = not enable
        self.refresh_button.disabled = not enable # Disable refresh too during processing
        self.go_back_button.disabled = not enable # Disable back button too during processing


    def list_containers_and_display_json(self, instance):
        """Triggers a refresh of the container list."""
        main_screen = self.manager.get_screen("main")
        # Prevent refresh if create is in progress on MainScreen
        if main_screen.is_creating_container:
            self.feedback_label.text = "A container creation is in progress. Cannot refresh list."
            return

        if self.is_processing_actions:
            self.feedback_label.text = "Please wait, an action is already in progress."
            return

        if not hasattr(self.manager, 'user_info'):
            self.feedback_label.text = "User information not found. Please log in again."
            return
        main_screen.send_request("request") # Request the updated list from the server

    def update_container_list(self, containers):
        """
        Updates the displayed list of containers on the UI.
        This method is called from the main thread after the 'request' API call completes.
        """
        self.container_list.clear_widgets() # Clear existing items
        self.selected_containers = {} # Reset selection state

        # Add a placeholder/header label if the list is empty or for clarity
        placeholder = MDLabel(
            text="Container List",
            halign='center',
            theme_text_color="Hint",
            size_hint_y=None,
            height=dp(40),
        )
        self.container_list.add_widget(placeholder)

        # Populate the list with new container items
        for container in containers:
            tmp_tag = container['tag']
            # Logic to derive a user-friendly label from the backend tag
            tag_split = tmp_tag.split("-")
            # Assuming the last part is a random ID, remove it for display
            if len(tag_split) > 1:
                container_label_parts = tag_split[:-1]
                container_label = "-".join(container_label_parts)
            else:
                container_label = tmp_tag # Fallback if tag doesn't match expected format

            item = ContainerListItem(
                tag=container_label,
                port=str(container.get('serverport', 'N/A')), # Use .get for safety
                distro=container.get('distro', 'N/A'),
                version=container.get('version', 'N/A'),
                status=container.get('vmstatus', 'unknown'),
                actualTag=tmp_tag
            )
            self.container_list.add_widget(item)
            self.selected_containers[tmp_tag] = item # Store reference by actualTag

    def manage_container(self, action):
        """
        Handles requests to perform actions (start, stop, etc.) on selected containers.
        """
        main_screen = self.manager.get_screen("main")
        # Prevent actions if create is in progress on MainScreen
        if main_screen.is_creating_container:
            self.feedback_label.text = "A container creation is in progress. Cannot perform other actions."
            return

        if self.is_processing_actions:
            self.feedback_label.text = "Please wait, an action is already in progress."
            return

        # Find all selected container items
        selected_items = [item for item in self.container_list.children if isinstance(item, ContainerListItem) and item.checkbox_active]
        if not selected_items:
            self.feedback_label.text = "Please select at least one container."
            return

        self.is_processing_actions = True # Set flag to indicate processing actions
        self._toggle_action_buttons_state(False) # Disable action buttons

        self.feedback_label.text = f"Sending '{action}' request for selected containers..."

        # Iterate through selected items and send an action request for each
        # Each send_request initiates a new thread, so these are non-blocking and can run in parallel.
        for item in selected_items:
            main_screen.current_selected_tag = item.actualTag # Set the tag for the main screen's send_request
            main_screen.send_request(action) # This call is now non-blocking
            main_screen.current_selected_tag = None # Clear the selection after sending the request

        # After all actions are initiated, trigger a refresh of the container list.
        # The actual UI update will happen when the 'request' API call completes,
        # which will then re-enable manage screen buttons.
        main_screen.send_request("request")
        self.feedback_label.text = "Container actions requested. List will refresh shortly."


class ContainerApp(MDApp):
    """Main application class for the Linux Container Manager."""
    def build(self):
        """Builds the KivyMD application UI."""
        self.theme_cls.theme_style = "Light" # Set theme to light
        sm = ScreenManager() # ScreenManager to manage different screens
        sm.user_info = {} # Global storage for user information across screens
        
        # Add main and manage screens to the manager
        main_screen = MainScreen(name="main")
        sm.add_widget(main_screen)
        sm.add_widget(ManageScreen(name="manage"))
        
        return sm

if __name__ == "__main__":
    # Determine the certificate path based on the execution environment
    if getattr(sys, 'frozen', False): # True when running as a compiled app (e.g., APK)
        if platform == 'android':
            # Path for Android APKs where certificates are usually bundled
            basedir = '/data/data/org.yoonjin67.lvirtfront/files/app/certs'
            cert_path = os.path.join(basedir, 'ca.crt')
        else:
            # Path for other frozen environments (e.g., PyInstaller on desktop)
            basedir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'certs')
            cert_path = os.path.join(basedir, 'ca.crt')
    else:
        # Path for development environment (running from source code)
        cert_path = './certs/ca.crt'
        
    ContainerApp().run() # Run the KivyMD application

