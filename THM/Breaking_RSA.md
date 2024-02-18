# Breaking RSA
Hop in and break poorly implemented RSA using Fermat's factorization algorithm.

## Resolution
Here, we're given a machine running an HTTP server and an ssh-agent.

Enumerating the hosted website, we find a hidden folder `/development`. Navigating there, we find the public RSA key in the file `id_rsa.pub`.

```Python
#!/usr/bin/python3

import sys
import base64
import struct
from gmpy2 import isqrt
from Crypto.PublicKey import RSA

"""
The article in the reference [1] is very helpful in understanding the format of the file.
The following adapted code extracts the values of n and e from the file
"""
keydata = base64.b64decode(open('id_rsa.pub').read().split(None)[1])
parts = []
while keydata:
    # read the length of the data
    dlen = struct.unpack('>I', keydata[:4])[0]
    # read in <length> bytes
    data, keydata = keydata[4:dlen+4], keydata[4+dlen:]
    parts.append(data)

e = int.from_bytes(parts[1], 'big')
n = int.from_bytes(parts[2], 'big')

"""
To factorize n, we use the given implementation of Fermat's algorithm.
Once we compute the prime factors of n, we can compute phi(n) and then the private key d
"""
def factorize(n):
    if (n & 1) == 0: return (n/2, 2)

    a = isqrt(n)
    if a * a == n:
        return a, a

    while True:
        a = a + 1
        bsq = a * a - n
        b = isqrt(bsq)
        if b * b == bsq: break
    return a + b, a - b

p, q = factorize(n)
phi_n = (p-1) * (q-1)
d = pow(e, -1, phi_n)

"""
I was trying at first to encode the private key file's content myself based on its format. But found that this can be done
in Python without all the burden. See the documentation [2].
Note: PEM is the right encoding format. At least other formats were rejected in ssh connection.
"""
private_key = RSA.construct((n, e, d))
content = private_key.exportKey(format='PEM', passphrase=None, pkcs=1)
with open("id_rsa", "wb") as file: file.write(content)

```

We execute the above script in the same directory as the public RSA key:
```
$ ./script.py
```

Now, we ssh to the machine using that private key:
```
$ ssh -i id_rsa root@ip_machine
```

The flag is in the home directory.


### Ref
\[1\] [Converting OpenSSH public keys](https://blog.oddbit.com/post/2011-05-08-converting-openssh-public-keys/)

\[2\] [RSA construct docs](https://www.dlitz.net/software/pycrypto/api/current/Crypto.PublicKey.RSA-module.html#construct)

