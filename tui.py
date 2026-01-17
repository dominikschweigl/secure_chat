from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, ScrollableContainer, Center, Middle, Container
from textual.widgets import Header, Footer, Input, ListItem, ListView, Static, Label, Button
from textual.screen import Screen
from textual.binding import Binding

from client.chat_client import ChatClient

class Message(Container):
    """
    Represents a single message row.
    Container = The Row (Full Width)
    Static    = The Bubble (Text Content)
    """
    def __init__(self, sender: str, text: str, self_sent: bool = False):
        super().__init__()
        self.sender = sender
        self.text_content = text
        self.self_sent = self_sent
        
        # Apply alignment classes to the ROW
        if self_sent:
            self.add_class("row-sent")
        else:
            self.add_class("row-received")

    def compose(self) -> ComposeResult:
        # The bubble contains the text
        yield Static(self.text_content, classes="bubble")

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
        username = self.query_one("#username").value
        password = self.query_one("#password").value

        if not username or not password:
            self.app.notify("Please enter credentials", severity="warning")
            return

        try:
            if event.button.id == "login-btn":
                self.app.client.login(username, password)
                # Transition to the main chat interface
                self.app.push_screen(MainScreen())
                self.app.notify(f"Logged in as {username}")
            
            elif event.button.id == "register-btn":
                self.app.client.register(username, password)
                self.app.notify("Registration successful! Please login.")
        
        except Exception as e:
            self.app.notify(f"Auth Error: {e}", severity="error")

class MainScreen(Screen):
    """The main chat interface screen."""
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True, id="header")
        with Horizontal(id="main-container"):
            # Sidebar
            with Vertical(id="sidebar"):
                current_user = self.app.client.username or "Unknown"
                yield Label(f"👤 {current_user}", id="user-label")
                
                yield Label(" ONLINE USERS", id="sidebar-title")
                yield ListView(id="user-list")
                # This is the button you added
                yield Button("Logout", variant="error", id="logout-btn")
            
            # Main chat area
            with Vertical(id="chat-area"):
                yield Label("Select a contact to start chatting", id="chat-header")
                yield ScrollableContainer(id="message-list")
                yield Input(placeholder="Type a message...", id="chat-input")
        yield Footer()

    def on_mount(self) -> None:
        try:
            header = self.query_one(Header)
            header.title = f"Secure Chat - {self.app.client.username}"
        except:
            pass

        self.current_recipient = None
        self.app.client.on_message_received = self.handle_new_message

        # Initial fetch and periodic update
        self.update_user_list()
        self.user_refresh = self.set_interval(3, self.update_user_list)

    def on_unmount(self) -> None:
        if self.app.client.on_message_received is self.handle_new_message:
            self.app.client.on_message_received = None
        if hasattr(self, "user_refresh"):
            self.user_refresh.stop()

    # Handle the Logout Button
    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button clicks (specifically Logout)."""
        if event.button.id == "logout-btn":
            try:
                self.app.client.logout()
            except Exception:
                # Even if the server request fails, we still want to exit the screen
                pass
            
            # Remove MainScreen, revealing LoginScreen underneath
            self.app.pop_screen()
            self.app.notify("Logged out")

    def update_user_list(self) -> None:
        try:
            users = self.app.client.get_users()
            users.sort(key=lambda u: u["username"])
            
            user_list = self.query_one("#user-list")
            
            existing_items = {
                child.username: child 
                for child in user_list.children 
                if hasattr(child, "username")
            }
            
            seen_usernames = set()

            for user in users:
                username = user["username"]
                seen_usernames.add(username)
                
                status = "🟢" if user.get("online") else "⚪"
                display_name = f"{username} (You)" if username == self.app.client.username else username
                label_text = f"{status} {display_name}"
                
                if username in existing_items:
                    item = existing_items[username]
                    try:
                        static_widget = item.query_one(Static)
                        static_widget.update(label_text)
                    except:
                        pass
                else:
                    item = ListItem(Static(label_text))
                    item.username = username
                    user_list.mount(item)
            
            for username, item in existing_items.items():
                if username not in seen_usernames:
                    item.remove()
                
        except Exception as e:
            pass
    
    def on_list_view_selected(self, event: ListView.Selected) -> None:
        self.current_recipient = event.item.username
        self.query_one("#chat-header").update(f"Chatting with [bold]{self.current_recipient}[/]")
        
        msg_list = self.query_one("#message-list")
        msg_list.query("*").remove()

        try:
            my_username = self.app.client.username
            history = self.app.client.message_store.load_messages(my_username, self.current_recipient)
            
            for msg in history:
                sender = msg.get("sender", "Unknown")
                text = msg.get("message", "")
                is_me = (sender == my_username)
                msg_list.mount(Message(sender, text, self_sent=is_me))
            
            msg_list.scroll_end()
            
        except Exception as e:
            self.app.notify(f"Failed to load history: {e}", severity="error")

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        if not self.current_recipient:
            self.app.notify("Please select a user first", severity="warning")
            return

        message_text = event.value.strip()
        if message_text:
            try:
                self.app.client.send_message(self.current_recipient, message_text)
                
                msg_list = self.query_one("#message-list")
                msg_list.mount(Message("Me", message_text, self_sent=True))
                
                self.query_one("#chat-input").value = ""
                msg_list.scroll_end()
            except Exception as e:
                self.app.notify(f"Send Error: {e}", severity="error")
        
    def handle_new_message(self, sender: str, message: str, timestamp: str) -> None:
        if sender == self.current_recipient:
            self.call_from_thread(self.display_incoming, sender, message)
        else:
            self.call_from_thread(self.app.notify, f"New message from {sender}")

    def display_incoming(self, sender: str, text: str) -> None:
        msg_list = self.query_one("#message-list")
        msg_list.mount(Message(sender, text, self_sent=(sender == self.app.client.username)))
        msg_list.scroll_end()

class ChatApp(App):
    CSS_PATH = "chat.tcss"
    BINDINGS = [Binding("q", "quit", "Exit")]

    def __init__(self):
        super().__init__()
        self.client = ChatClient("http://localhost:8000")

    def on_mount(self) -> None:
        self.push_screen(LoginScreen())
    
    def on_unmount(self) -> None:
        if self.client.is_logged_in():
            try:
                self.client.logout()
            except Exception:
                pass

if __name__ == "__main__":
    app = ChatApp()
    app.run()
