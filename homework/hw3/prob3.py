def strxor(a, b):
    """XOR two ASCII strings (trims the longer input if they're different lengths).

    If a and b are hexadecimal strings, convert them to ASCII before calling
    this function; e.g.,
        strxor(a.decode('hex'), b.decode('hex')) # Python 2.7
        strxor(bytes.fromhex(a), bytes.fromhex(b)) # Python 3
    """
    return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b)])  # Python 2.7
    # return bytes(x ^ y for (x, y) in zip(a, b))  # For Python 3

Ciphertext_1 = '9dc26aa8bc3f39ba761ea6f583e705a9d1c7f2da07301c004812f2e9143' +\
'61f73361645611785f8b6a9d2af7083e0c70eb2abf14d10de3ce52bceac79a90dc24fe74b0' +\
'6838365'
Ciphertext_2 = '9dc26aa8b43d27b6701ea6a6c7ea09bb9fd0e494077818020d19e4e85c' \
'3e137b6404177715d0fefea19bb46a8eebcc40e69db8402ccb34ad68cea47ae71bc102f60' \
'45f958b658551'
# Ciphertext 3:
# 9ecf2fe6b43533f3761ef4edcaeb0abb8194e3dc126459124c12e5bd083
# a10777e1959695ac4ffada581b37889f08217fa9db84f3a9f21a03adfed64b218cb1db3455
# 2da8f628e55584f
# Ciphertext 4:
# 808a7ce9a67023bb6305f4f2cbea44bf9cc4fec616300a1e5814eff20b31
# 51557814456114ccefb1bfd2a67783a4cf09f59aec062bda77b620d3b963ae06c94ff74b51
# 94cc54b9640c6c173ce744f6
# Ciphertext 5:
# 86c22fe6be7039bc765190c8e2af28b584daf0d1536411175913abea143
# a037136045f6b5ad5e3aebc9ba97ec7e7ce15f0d2fb4725d332a168e4a278b301cb4ffa57
# Ciphertext 6:
# 8cdc6afaa83238b77b51a7f2ccff44ae90d8fcdd1d7759184217aabd5c7f
# 51343650172e3385f8b6a59cac3993eccb13f19af94827da3bad29d5ed75a20dc00de1414
# 799847593
# Ciphertext 7:
# 9ac363edbf3332f3221ebaa6d7e701fa86dde5d1533058560d40c8f5153
# 31566731e1a475ad6edb7a8d2b4708be1cc03f7d2b806699f77e568869e63a8188e4fb304
# 06da98719b4e454e1f

asciiStr_Ciphertext_1 = Ciphertext_1.decode('hex')
print(asciiStr_Ciphertext_1)

asciiStr_Ciphertext_2 = Ciphertext_2.decode('hex')
print(asciiStr_Ciphertext_2)

t = strxor(asciiStr_Ciphertext_1, asciiStr_Ciphertext_2)
print(t)