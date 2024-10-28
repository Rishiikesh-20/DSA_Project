import curses, heapq

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
        self.max_heap = []  # A list to store the max-heap of (frequency, word)

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
        
        # Clear the heap before starting the new search to avoid duplicates
        self.max_heap = []

        suggestions = []
        self._dfs_encrypted(node, suggestions)
        
        # Sort suggestions using the max-heap, returning in order of highest frequency
        sorted_suggestions = heapq.nlargest(len(suggestions), self.max_heap, key=lambda x: -x[0])
        
        # Return only the unique encrypted words
        unique_encrypted_words = []
        seen_words = set()
        for _, encrypted_word in sorted_suggestions:
            if encrypted_word not in seen_words:
                unique_encrypted_words.append(encrypted_word)
                seen_words.add(encrypted_word)
        
        return unique_encrypted_words

    def _dfs_encrypted(self, node, suggestions):
        if node.is_end_of_word:
        # Append the encrypted word and its frequency
            suggestions.append((node.encrypted_word, node.frequency))
        # Add the word and its frequency to the heap (simulating a max-heap)
            heapq.heappush(self.max_heap, (-node.frequency, node.encrypted_word))
        for char, child in node.children.items():
            self._dfs_encrypted(child, suggestions)

    def increase_word_frequency(self, word):
        node = self.search(word)
        if node and node.is_end_of_word:
            node.frequency += 1  # Increment the frequency count
            # Add the updated frequency to the heap
            heapq.heappush(self.max_heap, (-node.frequency, node.encrypted_word))

# Client-side decryption function
def client_decrypt_suggestions(suggestions, decipher):
    decrypted_suggestions = []
    for encrypted_word in suggestions:  # Only decrypt the word
        decrypted_word = decipher.decrypt(encrypted_word).decode()
        decrypted_suggestions.append(decrypted_word)
    return decrypted_suggestions

# Predefined list of 100 words
predefined_words = ["the", "of", "and", "to", "in", "for", "is", "on", "that", "by", "this", "with", "you", "it", "not", "or", "be", "are", "from", "at", "as", "your", "all", "have", "new", "more", "an", "was", "we", "will", "home", "can", "us", "about", "if", "page", "my", "has", "search", "free", "but", "our", "one", "other", "do", "no", "information", "time", "they", "site", "he", "up", "may", "what", "which", "their", "news", "out", "use", "any", "there", "see", "only", "so", "his", "when", "contact", "here", "business", "who", "web", "also", "now", "help", "get", "pm", "view", "online", "first", "am", "been", "would", "how", "were", "me", "services", "some", "these", "click", "its", "like", "service", "than", "find", "price", "date", "back", "top", "people", "had", "list", "name", "just", "over", "state", "year", "day", "into", "email", "two", "health", "world", "re", "next", "used", "go", "work", "last", "most", "products", "music", "buy", "data", "make", "them", "should", "product", "system", "post", "her", "city", "add", "policy", "number", "such", "please", "available", "copyright", "support", "message", "after", "best", "software", "then", "jan", "good", "video", "well", "where", "info", "rights", "public", "books", "high", "school", "through", "each", "links", "she", "review", "years", "order", "very", "privacy", "book", "items", "company", "read", "group", "need", "many", "user", "said", "de", "does", "set", "under", "general", "research", "university", "january", "mail", "full", "map", "reviews", "program", "life", "know", "games", "way", "days", "management", "part", "could", "great", "united", "hotel", "real", "item", "international", "center", "ebay", "must", "store", "travel", "comments", "made", "development", "report", "off", "member", "details", "line", "terms", "before", "hotels", "did", "send", "right", "type", "because", "local", "those", "using", "results", "office", "education", "national", "car", "design", "take", "posted", "internet", "address", "community", "within", "states", "area", "want", "phone", "dvd", "shipping", "reserved", "subject", "between", "forum", "family", "long", "based", "code", "show", "even", "black", "check", "special", "prices", "website", "index", "being", "women", "much", "sign", "file", "link", "open", "today", "technology", "south", "case", "project", "same", "pages", "uk", "version", "section", "own", "found", "sports", "house", "related", "security", "both", "county", "american", "photo", "game", "members", "power", "while", "care", "network", "down", "computer", "systems", "three", "total", "place", "end", "following", "download", "him", "without", "per", "access", "think", "north", "resources", "current", "posts", "big", "media", "law", "control", "water", "history", "pictures", "size", "art", "personal", "since", "including", "guide", "shop", "directory", "board", "location", "change", "white", "text", "small", "rating", "rate", "government", "children", "during", "usa", "return", "students", "shopping", "account", "times", "sites", "level", "digital", "profile", "previous", "form", "events", "love", "old", "john", "main", "call", "hours", "image", "department", "title", "description", "non", "insurance", "another", "why", "shall", "property", "class", "cd", "still", "money", "quality", "every", "listing", "content", "country", "private", "little", "visit", "save", "tools", "low", "reply", "customer", "december", "compare", "movies", "include", "college", "value", "article", "york", "man", "card", "jobs", "provide", "food", "source", "author", "different", "press", "learn", "sale", "around", "print", "course", "job", "canada", "process", "teen", "room", "stock", "training", "too", "credit", "point", "join", "science", "men", "categories", "advanced", "west", "sales", "look", "english", "left", "team", "estate", "box", "conditions", "select", "windows", "photos", "gay", "thread", "week", "category", "note", "live", "large", "gallery", "table", "register", "however", "june", "october", "november", "market", "library", "really", "action", "start", "series", "model", "features", "air", "industry", "plan", "human", "provided", "tv", "yes", "required", "second", "hot", "accessories", "cost", "movie", "forums", "march", "la", "september", "better", "say", "questions", "july", "yahoo", "going", "medical", "test", "friend", "come", "dec", "server", "pc", "study", "application", "cart", "staff", "articles", "san", "feedback", "again", "play", "looking", "issues", "april", "never", "users", "complete", "street", "topic", "comment"]

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
        prefix = inputStr(stdscr, encrypted_trie, decipher)
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
        selected_word = menu_select(stdscr, decrypted_suggestions)
        curses.curs_set(1)

        # User can choose a word from suggestions, which increases the frequency of that word
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


def inputStr(stdscr, encrypted_trie, decipher):
    input_str = []  # List to store input characters
    cursor_x = 0  # Position of cursor within the input
    suggestions = []  # Store suggestions for autocomplete

    while True:
        # Display the input field
        stdscr.clear()
        stdscr.addstr(1, 2, "Enter text (Press Enter to finish, ESC to cancel, Tab for autocomplete):")
        stdscr.addstr(2, 2, "> ")
        stdscr.addstr(2, 4, "".join(input_str) + " ")  # Clear the last character position
        stdscr.move(2, cursor_x + 4)  # Move cursor to current position
        stdscr.refresh()

        # Get user input
        key = stdscr.getch()

        if key == 27:  # ESC key to cancel
            return ""
        elif key in (curses.KEY_BACKSPACE, 127):  # Handle backspace
            if cursor_x > 0:
                cursor_x -= 1
                input_str.pop(cursor_x)  # Remove character at cursor position
        elif key == curses.KEY_LEFT:  # Move cursor left
            if cursor_x > 0:
                cursor_x -= 1
        elif key == curses.KEY_RIGHT:  # Move cursor right
            if cursor_x < len(input_str):
                cursor_x += 1
        elif key == ord('\n'):  # Enter key to submit
            return "".join(input_str)
        elif key == ord('\t'):  # Tab key for autocomplete
            prefix = "".join(input_str)
            encrypted_suggestions = encrypted_trie.autocomplete_encrypted(prefix)
            if encrypted_suggestions:
                decrypted_suggestions = client_decrypt_suggestions(encrypted_suggestions, decipher)
                if decrypted_suggestions:
                    # Autocomplete with the most frequent suggestion (first one in sorted list)
                    most_frequent_suggestion = decrypted_suggestions[0]
                    input_str = list(most_frequent_suggestion)
                    cursor_x = len(input_str)
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
                stdscr.addstr(idx + 1, 2, " "+item+" ", curses.A_REVERSE)  # Highlighted selection
            else:
                stdscr.addstr(idx + 1, 2, " "+item+" ")

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
