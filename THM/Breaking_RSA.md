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
Having all the relevant RSA variables, we need to create the OpenSSH private key file
to be able to ssh to the machine. Considering the private key file format below, we can
adapt the code from the mentioned article to generate id_rsa.

RSAPrivateKey ::= SEQUENCE {
    version           Version,
    modulus           INTEGER,  -- n
    publicExponent    INTEGER,  -- e
    privateExponent   INTEGER,  -- d
    prime1            INTEGER,  -- p
    prime2            INTEGER,  -- q
    exponent1         INTEGER,  -- d mod (p-1)
    exponent2         INTEGER,  -- d mod (q-1)
    coefficient       INTEGER,  -- (inverse of q) mod p
    otherPrimeInfos   OtherPrimeInfos OPTIONAL
}
"""
from pyasn1.type import univ
from pyasn1.codec.der import encoder as der_encoder

pkcs1_seq = univ.Sequence()
pkcs1_seq.setComponentByPosition(0, univ.Integer(n))
pkcs1_seq.setComponentByPosition(1, univ.Integer(e))
pkcs1_seq.setComponentByPosition(1, univ.Integer(d))
pkcs1_seq.setComponentByPosition(1, univ.Integer(p))
pkcs1_seq.setComponentByPosition(1, univ.Integer(q))
pkcs1_seq.setComponentByPosition(1, univ.Integer(d % (p-1)))
pkcs1_seq.setComponentByPosition(1, univ.Integer(d % (q-1)))
pkcs1_seq.setComponentByPosition(1, univ.Integer(pow(q, -1, p)))

print('-----BEGIN OPENSSH PRIVATE KEY-----')
content = base64.b64encode(der_encoder.encode(pkcs1_seq)).decode()
# content = "\n".join(content[i: min(i+70, len(content))] for i in range(0, len(content), 70))
# print(content)
print('-----END OPENSSH PRIVATE KEY-----')

```

We execute the above script in the same directory as the public RSA key redirecting the output to the private key file:
```
$ ./script.py > id_rsa
```

Now, we ssh to the machine using that private key:
```
$ ssh -i id_rsa root@ip_machine
```

### Ref
\[1\] [Converting OpenSSH public keys](https://blog.oddbit.com/post/2011-05-08-converting-openssh-public-keys/)

