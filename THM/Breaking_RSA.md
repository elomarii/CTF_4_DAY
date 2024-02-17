# Breaking RSA
Hop in and break poorly implemented RSA using Fermat's factorization algorithm.

## Resolution
Here, we're given a machine running an HTTP server and an ssh-agent.

Enumerating the hosted website, we find a hidden folder `/development`. Navigating there, we find the public RSA key in the file `id_rsa.pub`.

Now, we need to get the public params `n` and `e` from the file. [This](https://blog.oddbit.com/post/2011-05-08-converting-openssh-public-keys/) article is very helpful
in understanding the OpenSSH key formats.

We make use of the given script to get `n` and `e`
```Python
import sys
import base64
import struct

# get the second field from the public key file.
keydata = base64.b64decode(
  open('id_rsa.pub').read().split(None)[1])

parts = []
while keydata:
    # read the length of the data
    dlen = struct.unpack('>I', keydata[:4])[0]

    # read in <length> bytes
    data, keydata = keydata[4:dlen+4], keydata[4+dlen:]

    parts.append(data)

e = int.from_bytes(parts[1], 'big')
n = int.from_bytes(parts[2], 'big')
```

To factorize `n`, we use the given implementation of Fermat's algorithm.
```Python
# gmpy2 is a C-coded Python extension module that supports
from gmpy2 import isqrt

def factorize(n):
    # since even nos. are always divisible by 2, one of the factors will
    # always be 2
    if (n & 1) == 0:
        return (n/2, 2)

    # isqrt returns the integer square root of n
    a = isqrt(n)

    # if n is a perfect square the factors will be ( sqrt(n), sqrt(n) )
    if a * a == n:
        return a, a

    while True:
        a = a + 1
        bsq = a * a - n
        b = isqrt(bsq)
        if b * b == bsq:
            break
    return a + b, a - b
```

Now that we have access to the prime factors of `n`, we can compute `phi(n)` and then the private key `d`:
```Python
phi_n = (p-1) * (q-1)
d = pow(e, -1, phi_n)
```

Having all the relevant RSA variables, we need to create the OpenSSH private key file to be able to ssh to the machine. Considering the private key file format below, we can adapt the code from the above article to generate `id_rsa`.

```
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
```

```Python
from pyasn1.type import univ
from pyasn1.codec.der import encoder as der_encoder

pkcs1_seq = univ.Sequence()
pkcs1_seq.setComponentByPosition(0, univ.Integer(n))
pkcs1_seq.setComponentByPosition(1, univ.Integer(e))
pkcs1_seq.setComponentByPosition(1, univ.Integer(d))
pkcs1_seq.setComponentByPosition(1, univ.Integer(p))
pkcs1_seq.setComponentByPosition(1, univ.Integer(q))
pkcs1_seq.setComponentByPosition(1, univ.Integer(d_p))
pkcs1_seq.setComponentByPosition(1, univ.Integer(d_q))
pkcs1_seq.setComponentByPosition(1, univ.Integer(q_p))

print '-----BEGIN RSA PUBLIC KEY-----'
print base64.encodestring(der_encoder.encode(pkcs1_seq))
print '-----END RSA PUBLIC KEY-----'
```




