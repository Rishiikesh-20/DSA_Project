
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


import heapq

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


# The rest of the code remains the same, including the client-side decryption.



# Client-side decryption function
def client_decrypt_suggestions(suggestions, decipher):
    decrypted_suggestions = []
    for encrypted_word in suggestions:  # Only decrypt the word
        decrypted_word = decipher.decrypt(encrypted_word).decode()
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
    # Create an encrypted trie
    encrypted_trie = EncryptedTrie(public_key, decipher)

    # Insert predefined words into the Trie (stored as encrypted)
    for word in predefined_words:
        encrypted_trie.insert_encrypted(word)

    print(f"{len(predefined_words)} predefined words have been inserted into the Trie.")

    while True:
        # User inputs a prefix to search for auto-complete suggestions
        prefix = input("\nEnter a prefix to search (or type 'exit' to stop): ").strip()
        if prefix.lower() == 'exit':
            break

        encrypted_suggestions = encrypted_trie.autocomplete_encrypted(prefix)

        # If no suggestions found
        if not encrypted_suggestions:
            print(f"No suggestions found for prefix '{prefix}'")
            continue

        # Client decrypts the suggestions
        decrypted_suggestions = client_decrypt_suggestions(encrypted_suggestions, decipher)
        print(f"Autocomplete suggestions for '{prefix}': {decrypted_suggestions}")

        # User can choose a word from suggestions, which increases the frequency of that word
        selected_word = input(f"Select a word from the suggestions (or 'none' to skip): ").strip()
        if selected_word in decrypted_suggestions:
            encrypted_trie.increase_word_frequency(selected_word)
            print(f"Frequency of '{selected_word}' increased.")
        else:
            print("Word not found in suggestions or skipped.")


if __name__ == "__main__":
    main()

