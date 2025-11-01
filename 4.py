import math

# -------------------------------
# Substitution: Caesar Cipher
# -------------------------------
def caesar_encrypt(text, shift):
    result = []
    for ch in text:
        if 'A' <= ch <= 'Z':
            result.append(chr((ord(ch) - ord('A') + shift) % 26 + ord('A')))
        elif 'a' <= ch <= 'z':
            result.append(chr((ord(ch) - ord('a') + shift) % 26 + ord('a')))
        else:
            result.append(ch)
    return ''.join(result)

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)


# -------------------------------
# Transposition: Columnar
# -------------------------------
def key_order_from_keyword(keyword):
    pairs = list(enumerate(keyword))
    sorted_pairs = sorted(pairs, key=lambda x: (x[1], x[0]))
    return [orig_idx for orig_idx, _ in sorted_pairs]

def columnar_encrypt(text, keyword, padchar='X'):
    cols = len(keyword)
    rows = math.ceil(len(text) / cols)
    total = rows * cols
    padded = text + padchar * (total - len(text))

    # build matrix row-wise
    matrix = [list(padded[i * cols:(i + 1) * cols]) for i in range(rows)]
    order = key_order_from_keyword(keyword)

    # build ciphertext by reading columns in keyword order
    ciphertext = []
    for col in order:
        for r in range(rows):
            ciphertext.append(matrix[r][col])
    return ''.join(ciphertext), matrix, order, padded

def columnar_decrypt(ciphertext, keyword, padchar='X'):
    cols = len(keyword)
    rows = math.ceil(len(ciphertext) / cols)
    total = rows * cols
    if len(ciphertext) != total:
        ciphertext += padchar * (total - len(ciphertext))

    order = key_order_from_keyword(keyword)
    matrix = [[''] * cols for _ in range(rows)]

    idx = 0
    for col in order:
        for r in range(rows):
            matrix[r][col] = ciphertext[idx]
            idx += 1

    substituted_padded = ''.join(''.join(row) for row in matrix)
    return substituted_padded, matrix, order

def print_matrix(matrix, keyword, order, title):
    print(f"\n{title}")
    rows = len(matrix)
    cols = len(matrix[0])
    header = "    " + "  ".join(f"{i}" for i in range(cols))
    print(header)
    print("    " + "---" * cols)
    for r in range(rows):
        print("r{:02d}| {}".format(r, "  ".join(matrix[r])))
    print("Keyword:", keyword)
    print("Column read order:", order)


# -------------------------------
# Product Cipher Demo
# -------------------------------
if __name__ == "__main__":
    # Take user input
    plaintext = input("Enter the plaintext: ")
    shift = int(input("Enter Caesar shift (e.g., 3): "))
    keyword = input("Enter keyword for transposition: ")

    print("\n--- ENCRYPTION ---")
    # Step 1: Caesar substitution
    substituted = caesar_encrypt(plaintext, shift)
    print("After Caesar substitution:", substituted)

    # Step 2: Columnar transposition
    ciphertext, matrix, order, padded = columnar_encrypt(substituted, keyword)
    print_matrix(matrix, keyword, order, "Transposition Matrix (Encryption)")
    print("Final Ciphertext (Product Cipher):", ciphertext)

    print("\n--- DECRYPTION ---")
    # Step A: Reverse transposition
    recovered_substituted_padded, dec_matrix, dec_order = columnar_decrypt(ciphertext, keyword)
    recovered_substituted = recovered_substituted_padded.rstrip('X')
    print_matrix(dec_matrix, keyword, dec_order, "Transposition Matrix (Decryption)")
    print("Recovered substituted text:", recovered_substituted)

    # Step B: Reverse Caesar
    recovered_plaintext = caesar_decrypt(recovered_substituted, shift)
    print("Recovered Plaintext:", recovered_plaintext)
