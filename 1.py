# --- Key matrix (5x5) ---
def create_key_matrix(key):
    key = key.lower().replace('j', 'i')
    seen = set()
    matrix = []
    for ch in key:
        if 'a' <= ch <= 'z' and ch != 'j' and ch not in seen:
            seen.add(ch)
            matrix.append(ch)
    for ch in 'abcdefghijklmnopqrstuvwxyz':
        if ch != 'j' and ch not in seen:
            seen.add(ch)
            matrix.append(ch)
    return matrix  # flat list of 25 chars

# --- Display matrix ---
def display_matrix(matrix):
    print("\n5x5 Key Matrix:")
    for i in range(0, 25, 5):
        print(' '.join(matrix[i:i+5]))
    print()

# --- Prepare plaintext into digraphs (insert 'x' between duplicate letters, pad odd length) ---
def prepare_text(plain_text):
    s = ''.join(ch for ch in plain_text.lower().replace('j', 'i') if 'a' <= ch <= 'z')
    pairs = []
    i = 0
    while i < len(s):
        a = s[i]
        if i + 1 < len(s):
            b = s[i + 1]
            if a == b:
                pairs.append(a + 'x')
                i += 1
            else:
                pairs.append(a + b)
                i += 2
        else:
            pairs.append(a + 'x')
            i += 1
    return pairs

# --- Helpers ---
def find_position(letter, matrix):
    idx = matrix.index(letter)
    return divmod(idx, 5)  # (row, col)

def _pairwise(s):
    return [s[i:i+2] for i in range(0, len(s), 2)]

def _clean_plaintext(pt):
    chars = list(pt)
    i = 0
    cleaned = []
    while i < len(chars):
        if i + 2 < len(chars) and chars[i] == chars[i + 2] and chars[i + 1] == 'x':
            cleaned.append(chars[i])
            cleaned.append(chars[i + 2])
            i += 3
        else:
            cleaned.append(chars[i])
            i += 1
    if cleaned and cleaned[-1] == 'x':
        cleaned.pop()
    return ''.join(cleaned)

# --- Encrypt ---
def encrypt(plain_text, key):
    m = create_key_matrix(key)
    ct = []
    for pair in prepare_text(plain_text):
        r1, c1 = find_position(pair[0], m)
        r2, c2 = find_position(pair[1], m)
        if r1 == r2:  # same row -> shift right
            ct.append(m[r1 * 5 + (c1 + 1) % 5])
            ct.append(m[r2 * 5 + (c2 + 1) % 5])
        elif c1 == c2:  # same column -> shift down
            ct.append(m[((r1 + 1) % 5) * 5 + c1])
            ct.append(m[((r2 + 1) % 5) * 5 + c2])
        else:  # rectangle
            ct.append(m[r1 * 5 + c2])
            ct.append(m[r2 * 5 + c1])
    return ''.join(ct).upper()

# --- Decrypt ---
def decrypt(cipher_text, key, auto_clean=True):
    m = create_key_matrix(key)
    s = ''.join(ch for ch in cipher_text.lower() if 'a' <= ch <= 'z')
    if len(s) % 2 != 0:
        s += 'x'
    pt = []
    for pair in _pairwise(s):
        r1, c1 = find_position(pair[0], m)
        r2, c2 = find_position(pair[1], m)
        if r1 == r2:  # same row -> shift left
            pt.append(m[r1 * 5 + (c1 - 1) % 5])
            pt.append(m[r2 * 5 + (c2 - 1) % 5])
        elif c1 == c2:  # same column -> shift up
            pt.append(m[((r1 - 1) % 5) * 5 + c1])
            pt.append(m[((r2 - 1) % 5) * 5 + c2])
        else:  # rectangle
            pt.append(m[r1 * 5 + c2])
            pt.append(m[r2 * 5 + c1])
    dec = ''.join(pt)
    return _clean_plaintext(dec) if auto_clean else dec

# --- Restore spaces to decrypted text ---
def restore_spaces(clean_text, template_with_spaces):
    out = []
    it = iter(clean_text)
    for ch in template_with_spaces:
        if ch == ' ':
            out.append(' ')
        elif 'a' <= ch.lower() <= 'z':
            out.append(next(it, ''))
    rest = ''.join(it)
    if rest:
        out.append(rest)
    return ''.join(out)

# --- Example usage ---
if __name__ == "__main__":
    key = "simplekey"
    plain_text = "hello world"

    key_matrix = create_key_matrix(key)
    print("Key:", key)
    display_matrix(key_matrix)

    cipher_text = encrypt(plain_text, key)
    decrypted_text = decrypt(cipher_text, key)
    decrypted_with_spaces = restore_spaces(decrypted_text, plain_text)

    print("Original Message:", plain_text)
    print("Encrypted Message:", cipher_text)
    print("Decrypted Message (clean):", decrypted_text)
    print("Decrypted Message (spaces restored):", decrypted_with_spaces)
