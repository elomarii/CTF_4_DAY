## Challenge
### Description
I wanted an encryption service that's more secure than regular DES, but not as slow as 3DES... The flag is not in standard format.

### Hints
1- How large is the keyspace?

## Resolution
DES is a block cipher encryption scheme. The blocks are 64 bits in size, and so are the keys. The small key size makes the scheme very vulnerable to brute force attacks.
2DES tries to fix the issue by using DES twice in a row using different keys. However, this doesn't increase the key size much, and can be easily cracked using a meet-in-the-middle attack which we'll be employing below. All that we need is a pair of plain/cipher texts.

Let's connect and get our encrypted flag:
```
$ nc mercury.picoctf.net 29980

Here is the flag:
a0cb6b86229afb1d909ff0d2a3542460cfce09d8f3d022fa4c1b994831e1e9275ec195b47bd0d111
```

We can provide our inputs to the app to get their encryption:
```
What data would you like to encrypt? 1a2b3c4d1a2b3c4d
b87a84bf965e28fe5ec195b47bd0d111
```

The attack works as follows:
1- Encrypt the known plain text using all possible keys
2- Decrypt the corresponding cipher text using all possible keys
3- Find the match between the two sets and retrieve the corresponding keys
4- Decrypt the flag

The following python script does the job:
```Python
from Crypto.Cipher import DES
import binascii

def pad(msg):
    block_len = 8
    over = len(msg) % block_len
    pad = block_len - over
    return (msg + " " * pad).encode()


"""
Useful data. The encrypted flag and the known plain/cipher pair
"""
flag = binascii.unhexlify("a0cb6b86229afb1d909ff0d2a3542460cfce09d8f3d022fa4c1b994831e1e9275ec195b47bd0d111")
plain = pad(binascii.unhexlify("1a2b3c4d1a2b3c4d").decode())
cipher = binascii.unhexlify("b87a84bf965e28fe5ec195b47bd0d111")

"""
Generating the key space. Keys are of the form [b'XXXXXX  ']
"""
key_space = [pad(str(value)[1:]) for value in range(1000000, 2000000)]

"""
Generating all possible encryptions (decryptions) of the plain (cipher) text
"""
encrypted = [DES.new(key, DES.MODE_ECB).encrypt(plain) for key in key_space]
decrypted = [DES.new(key, DES.MODE_ECB).decrypt(cipher) for key in key_space]

"""
Find the match and retrieve the keys
"""
key1, key2 = None, None
try:
  a_match = (set(decrypted) & set(encrypted)).pop()
  key1 = key_space[encrypted.index(a_match)]
  key2 = key_space[decrypted.index(a_match)]
except:
  print("Didn't find a match, verify your plain/cipher text entries")
  exit()

"""
Decrypt the flag :)
"""
flag = DES.new(key2, DES.MODE_ECB).decrypt(flag)
flag = DES.new(key1, DES.MODE_ECB).decrypt(flag)
print("Your flag: " + flag.decode())

```

Output: `Your flag: 45d6631b0c4d52b801a0fa7f6d3bda3c`






