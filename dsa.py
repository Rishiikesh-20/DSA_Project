class TrieNode:
    def __init__(self):
        self.children = {}
        self.is_end_of_word = False
        self.encrypted_word = None  # To store the encrypted word at leaf nodes

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
            suggestions.append(prefix)
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

    def autocomplete_encrypted(self, prefix):
        node = self.search(prefix)  # Search using the plaintext prefix
        if not node:
            return []
        suggestions = []
        self._dfs_encrypted(node, suggestions)
        return suggestions

    def _dfs_encrypted(self, node, suggestions):
        if node.is_end_of_word:
            # Append the encrypted word at the leaf node
            suggestions.append(node.encrypted_word)
        for char, child in node.children.items():
            self._dfs_encrypted(child, suggestions)


# Client-side decryption function
def client_decrypt_suggestions(suggestions, decipher):
    decrypted_suggestions = []
    for suggestion in suggestions:
        decrypted_word = decipher.decrypt(suggestion).decode()
        decrypted_suggestions.append(decrypted_word)
    return decrypted_suggestions


# Main function to test the encrypted Trie autocomplete system
def main():
    # Create an encrypted trie
    encrypted_trie = EncryptedTrie(public_key, decipher)

    # Insert words into the Trie (plaintext words, but stored as encrypted)
    words = ['apple', 'app', 'application', 'apex', 'banana']
    for word in words:
        encrypted_trie.insert_encrypted(word)

    # Get encrypted suggestions for a prefix
    prefix = 'app'
    encrypted_suggestions = encrypted_trie.autocomplete_encrypted(prefix)

    # Client decrypts the suggestions
    decrypted_suggestions = client_decrypt_suggestions(encrypted_suggestions, decipher)

    print(f"Autocomplete suggestions for '{prefix}': {decrypted_suggestions}")


if __name__ == "__main__":
    main()
