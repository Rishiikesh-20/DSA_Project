import curses

class TrieNode:
    def __init__(self):
        self.children = {}
        self.is_end_of_word = False
        self.encrypted_word = None  # To store the encrypted word at leaf nodes
        self.frequency = 0  # To track search frequency for this word


class Trie:
    def __init__(self):
        self.root = TrieNode()

    def insert(self, word):
        node = self.root
        for char in word:
            if char not in node.children:
                node.children[char] = TrieNode()
            node = node.children[char]
        node.is_end_of_word = True

    def search(self, prefix):
        node = self.root
        for char in prefix:
            if char not in node.children:
                return None
            node = node.children[char]
        return node

    def autocomplete(self, prefix):
        node = self.search(prefix)
        if not node:
            return []
        suggestions = []
        self._dfs(node, prefix, suggestions)
        return suggestions

    def _dfs(self, node, prefix, suggestions):
        if node.is_end_of_word:
            suggestions.append((prefix, node.frequency))  # Append word with frequency
        for char, child in node.children.items():
            self._dfs(child, prefix + char, suggestions)


# Import necessary cryptographic libraries
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Generate RSA key pair for encryption and decryption
key = RSA.generate(2048)
public_key = key.publickey()
cipher = PKCS1_OAEP.new(public_key)
decipher = PKCS1_OAEP.new(key)


class EncryptedTrie(Trie):
    def __init__(self, public_key, decipher):
        super().__init__()
        self.public_key = public_key
        self.decipher = decipher

    def encrypt_word(self, word):
        # Encrypt the entire word using RSA encryption
        encrypted_word = cipher.encrypt(word.encode())
        return encrypted_word

    def decrypt_word(self, encrypted_word):
        # Decrypt the encrypted word back to plaintext
        decrypted_word = self.decipher.decrypt(encrypted_word).decode()
        return decrypted_word

    def insert_encrypted(self, word):
        node = self.root
        for char in word:
            if char not in node.children:
                node.children[char] = TrieNode()
            node = node.children[char]
        # At the leaf node, store the encrypted word
        node.is_end_of_word = True
        node.encrypted_word = self.encrypt_word(word)
        node.frequency = 0  # Initialize frequency to 0

    def autocomplete_encrypted(self, prefix):
        node = self.search(prefix)  # Search using the plaintext prefix
        if not node:
            return []
        suggestions = []
        self._dfs_encrypted(node, suggestions)
        # Sort the suggestions based on frequency in descending order
        suggestions.sort(key=lambda x: x[1], reverse=True)
        return [s[0] for s in suggestions]  # Return only the encrypted words

    def _dfs_encrypted(self, node, suggestions):
        if node.is_end_of_word:
            # Append the encrypted word and its frequency
            suggestions.append((node.encrypted_word, node.frequency))
        for char, child in node.children.items():
            self._dfs_encrypted(child, suggestions)

    def increase_word_frequency(self, word):
        node = self.search(word)
        if node and node.is_end_of_word:
            node.frequency += 1  # Increment the frequency count


# Client-side decryption function
def client_decrypt_suggestions(suggestions, decipher):
    decrypted_suggestions = []
    for suggestion in suggestions:
        decrypted_word = decipher.decrypt(suggestion).decode()
        decrypted_suggestions.append(decrypted_word)
    return decrypted_suggestions


# Predefined list of 100 words
predefined_words = [
    "apple", "application", "banana", "bat", "ball", "cat", "car", "camera",
    "dog", "doll", "dinosaur", "elephant", "eagle", "egg", "fish", "frog",
    "giraffe", "goat", "hat", "house", "ice", "igloo", "jacket", "juice",
    "kangaroo", "key", "lamp", "lion", "monkey", "moon", "notebook", "needle",
    "octopus", "owl", "pencil", "panda", "queen", "quilt", "rabbit", "robot",
    "snake", "sun", "tiger", "table", "umbrella", "unicorn", "vase", "van",
    "whale", "watch", "xylophone", "xenon", "yacht", "yak", "zebra", "zero",
    "grape", "green", "blue", "yellow", "orange", "black", "white", "purple",
    "red", "chair", "computer", "phone", "tablet", "book", "glass", "bottle",
    "fan", "clock", "television", "radio", "speaker", "monitor", "laptop",
    "printer", "keyboard", "mouse", "piano", "guitar", "drum", "violin",
    "carrot", "broccoli", "potato", "tomato", "corn", "lettuce", "peach",
    "pear", "plum", "watermelon", "strawberry", "blueberry", "raspberry"
]


# Main function to handle user input
def main():
    stdscr = curses.initscr()
    curses.echo()
    stdscr.clear()
    stdscr.refresh()
    stdscr.keypad(True)

    # Create an encrypted trie
    encrypted_trie = EncryptedTrie(public_key, decipher)

    # Insert predefined words into the Trie (stored as encrypted)
    for word in predefined_words:
        encrypted_trie.insert_encrypted(word)

    stdscr.addstr(1, 2, f"{len(predefined_words)} predefined words have been inserted into the Trie.")
    stdscr.getch()

    while True:
        stdscr.clear()
        curses.curs_set(1)
        # User inputs a prefix to search for auto-complete suggestions
        # stdscr.addstr(2, 2, "Enter a prefix to search (or type 'exit' to stop): ")
        prefix = inputStr(stdscr)
        # prefix = stdscr.getstr(2, 0)
        stdscr.addstr(3, 3, f"\nPrefix: {prefix}")

        if prefix.lower() == 'exit':
            break

        encrypted_suggestions = encrypted_trie.autocomplete_encrypted(prefix)

        # If no suggestions found
        if not encrypted_suggestions:
            stdscr.addstr(3, 2, f"No suggestions found for prefix '{prefix}'")
            continue

        # Client decrypts the suggestions
        decrypted_suggestions = client_decrypt_suggestions(encrypted_suggestions, decipher)
        # stdscr.addstr(4, 2, f"Autocomplete suggestions for '{prefix}'")
        selected_word = menu_select(stdscr, decrypted_suggestions)
        curses.curs_set(1)
        # User can choose a word from suggestions, which increases the frequency of that word
        # stdscr.addstr(5, 2, f"Select a word from the suggestions (or 'none' to skip): ")
        # selected_word = inputStr(stdscr, 5)
        # selected_word = stdscr.getstr(9, 0)
        stdscr.clear()
        if selected_word in decrypted_suggestions:
            encrypted_trie.increase_word_frequency(selected_word)
            stdscr.addstr(1, 2, f"Frequency of '{selected_word}' increased.")
            stdscr.getch()
            stdscr.clear()
        else:
            stdscr.addstr(1, 2, "Word not found in suggestions or skipped.")
            stdscr.getch()
            stdscr.clear()

        # stdscr.refresh()

def inputStr(stdscr):
    input_str = []                   # List to store input characters
    cursor_x = 0                     # Position of cursor within the input

    while True:
        # Display the input field
        stdscr.clear()
        stdscr.addstr(1, 2, "Enter text (Press Enter to finish, ESC to cancel):")
        stdscr.addstr(2, 2, "> ")
        stdscr.addstr(2, 4, "".join(input_str) + " ")  # Clear the last character position
        stdscr.move(2, cursor_x+4)                       # Move cursor to current position
        stdscr.refresh()

        # Get user input
        key = stdscr.getch()

        if key == 27:  # ESC key to cancel
            return ""
        elif key in (curses.KEY_BACKSPACE, 127):  # Handle backspace
            if cursor_x > 0:
                cursor_x -= 1
                input_str.pop(cursor_x)            # Remove character at cursor position
        elif key == curses.KEY_LEFT:  # Move cursor left
            if cursor_x > 0:
                cursor_x -= 1
        elif key == curses.KEY_RIGHT:  # Move cursor right
            if cursor_x < len(input_str):
                cursor_x += 1
        elif key == ord('\n'):  # Enter key to submit
            return "".join(input_str)
        elif 32 <= key <= 126:  # Printable characters (ASCII range for simplicity)
            input_str.insert(cursor_x, chr(key))  # Insert character at cursor position
            cursor_x += 1
    return ''.join(input_str)

def menu_select(stdscr, items):
    # Initial setup
    curses.curs_set(0)              # Hide the cursor
    current_row = 0                 # Track which row is selected

    while True:
        # Clear and refresh the screen for a new display
        stdscr.clear()

        # Display all menu items with highlighting
        for idx, item in enumerate(items):
            if idx == current_row:
                stdscr.addstr(idx + 1, 2, item, curses.A_REVERSE)  # Highlighted selection
            else:
                stdscr.addstr(idx + 1, 2, item)

        stdscr.refresh()

        # Get user input
        key = stdscr.getch()

        if key == curses.KEY_UP and current_row > 0:
            current_row -= 1
        elif key == curses.KEY_DOWN and current_row < len(items) - 1:
            current_row += 1
        elif key == ord('\n'):  # Enter key
            return items[current_row]  # Return the index of the selected item
        elif key == 27:  # ESC key to cancel
            break

if __name__ == "__main__":
    curses.wrapper(main())
