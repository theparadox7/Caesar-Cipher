def caesar_decrypt(ciphertext, shift):
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            # Determine if the character is uppercase or lowercase
            offset = 65 if char.isupper() else 97
            # Shift the character within the alphabet range
            decrypted_char = chr((ord(char) - offset - shift) % 26 + offset)
            plaintext += decrypted_char
        else:
            # Non-alphabetic characters remain unchanged
            plaintext += char
    return plaintext

def main():
    print("Caesar Cipher Decryption Tool")
    
    # Get the ciphertext from the user
    ciphertext = input("Enter the ciphertext: ")
    
    while True:
        try:
            # Get the guessed key (shift value) from the user
            shift = int(input("Enter the shift value (0-25): "))
            
            if shift < 0 or shift > 25:
                raise ValueError("Shift value must be between 0 and 25.")
            
            # Decrypt the message with the guessed key
            plaintext = caesar_decrypt(ciphertext, shift)
            print(f"Decrypted message: {plaintext}")
            
            # Ask if the user wants to try another key
            try_again = input("Try another key? (y/n): ").lower()
            if try_again != 'y':
                break
        except ValueError as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()
