from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, ScrollableContainer, Center, Middle
from textual.widgets import Header, Footer, Input, ListItem, ListView, Static, Label, Button
from textual.screen import Screen
from textual.binding import Binding

from client.chat_client import ChatClient

class Message(Static):
    """Widget to display a single chat message."""
    def __init__(self, sender: str, text: str, self_sent: bool = False):
        super().__init__(text)
        self.sender = sender
        self.self_sent = self_sent
        self.add_class("message")
        if self_sent:
            self.add_class("self-sent")

class LoginScreen(Screen):
    """The initial login screen of the application."""
    def compose(self) -> ComposeResult:
        with Center():
            with Middle():
                with Vertical(id="login-form"):
                    yield Label("SECURE E2EE CHAT", id="login-title")
                    yield Input(placeholder="Username", id="username") 
                    yield Input(placeholder="Password", password=True, id="password")
                    with Horizontal(id="login-buttons"):
                        yield Button("Register", id="register-btn")
                        yield Button("Login", variant="primary", id="login-btn")
        yield Footer()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle login and registration button clicks."""
        username = self.query_one("#username").value
        password = self.query_one("#password").value

        if not username or not password:
            self.app.notify("Please enter credentials", severity="warning")
            return

        try:
            if event.button.id == "login-btn":
                # Authenticate with the backend server
                self.app.client.login(username, password)
                # Transition to the main chat interface
                self.app.push_screen(MainScreen())
                self.app.notify(f"Logged in as {username}")
            
            elif event.button.id == "register-btn":
                # Register a new user and generate RSA keys
                self.app.client.register(username, password)
                self.app.notify("Registration successful! Please login.")
        
        except Exception as e:
            self.app.notify(f"Auth Error: {e}", severity="error")

class MainScreen(Screen):
    """The main chat interface screen."""
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="main-container"):
            # Sidebar showing registered/online users
            with Vertical(id="sidebar"):
                yield Label(" ONLINE USERS", id="sidebar-title")
                yield ListView(id="user-list")
                yield Button("Logout", variant="error", id="logout-btn")
            
            # Main chat area
            with Vertical(id="chat-area"):
                yield Label("Select a contact to start chatting", id="chat-header")
                yield ScrollableContainer(id="message-list")
                yield Input(placeholder="Type a message...", id="chat-input")
        yield Footer()

    def on_mount(self) -> None:
        """Fetch users from the server and start periodic updates."""
        self.current_recipient = None
        # Register callback *when this screen is active*
        self.app.client.on_message_received = self.handle_new_message
        # Initial fetch
        self.update_user_list()
        # Periodically update the user list every 3 seconds
        self.user_refresh = self.set_interval(3, self.update_user_list)

    def on_unmount(self) -> None:
        if self.app.client.on_message_received is self.handle_new_message:
            self.app.client.on_message_received = None
        if hasattr(self, "user_refresh"):
            self.user_refresh.stop()

    def update_user_list(self) -> None:
        try:
            users = self.app.client.get_users()
            user_list = self.query_one("#user-list")
            user_list.clear()

            for user in users:
                status = "🟢" if user.get("online") else "⚪"
                username = user["username"] + " (You)" if user["username"] == self.app.client.username else user["username"]
                item = ListItem(Static(f"{status} {username}"))
                item.username = user["username"]
                user_list.mount(item)
                
        except Exception as e:
            self.app.notify(f"Error: {e}", severity="error")
    
    def on_list_view_selected(self, event: ListView.Selected) -> None:
        """Switch chat context when a user is selected in the list."""
        self.current_recipient = event.item.username
        self.query_one("#chat-header").update(f"Chatting with [bold]{self.current_recipient}[/]")
        # Clear the message area for the new contact
        self.query_one("#message-list").remove_children()
        # Load message history for the selected contact
        self.update_selected_chat()

    
    def update_selected_chat(self) -> None:
        """Refresh the message list for the currently selected contact."""
        if not self.current_recipient:
            return
        try:
            history = self.app.client.get_message_history(self.current_recipient)
            msg_list = self.query_one("#message-list")
            msg_list.remove_children()
            for msg in history:
                self_sent = (msg["sender"] == self.app.client.username)
                msg_list.mount(Message(msg["sender"], msg["message"], self_sent=self_sent))
            msg_list.scroll_end()
        except Exception as e:
            self.app.notify(f"History Load Error: {e}", severity="error")

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        """Send an encrypted message when Enter is pressed."""
        if not self.current_recipient:
            self.app.notify("Please select a user first", severity="warning")
            return

        message_text = event.value.strip()
        if message_text:
            try:
                self.app.client.send_message(self.current_recipient, message_text)
                
                # Display the message locally
                msg_list = self.query_one("#message-list")
                msg_list.mount(Message("Me", message_text, self_sent=True))
                
                # Reset input and scroll to bottom
                self.query_one("#chat-input").value = ""
                msg_list.scroll_end()
            except Exception as e:
                self.app.notify(f"Send Error: {e}", severity="error")
    
    def handle_new_message(self, sender: str, message: str, timestamp: str) -> None:
        """Callback triggered by the backend's MessageWorker thread."""
        if sender == self.current_recipient:
            # Use call_from_thread to safely update UI from the background thread
            self.app.call_from_thread(self.display_incoming, sender, message)
        else:
            self.app.call_from_thread(self.app.notify, f"New message from {sender}")

    def display_incoming(self, sender: str, text: str) -> None:
        """Render the incoming message in the UI."""
        msg_list = self.query_one("#message-list")
        msg_list.mount(Message(sender, text, self_sent=(sender == self.app.client.username)))
        msg_list.scroll_end()
    
    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle logout button click."""
        if event.button.id == "logout-btn":
            try:
                self.app.client.logout()
                self.app.pop_screen()
                self.app.notify("Logged out successfully")
            except Exception as e:
                self.app.notify(f"Logout Error: {e}", severity="error")

class ChatApp(App):
    """The main application class managing state and screens."""
    CSS_PATH = "chat.tcss"
    BINDINGS = [Binding("q", "quit", "Exit")]

    def __init__(self):
        super().__init__()
        # Initialize the backend client pointing to the FastAPI server
        self.client = ChatClient("http://localhost:8000")

    def on_mount(self) -> None:
        """Start the application with the login screen."""
        self.push_screen(LoginScreen())
    
    def on_unmount(self) -> None:
        """Ensure client cleanup on app exit."""
        self.client.logout()


if __name__ == "__main__":
    app = ChatApp()
    app.run()