# STROBE lite
STROBE lite is an experimental symmetric cryptography framework which can be used to construct systems as simple as hash functions and symmetric encryption, up to protocol handshakes and even entire protocols.

# Motivation and Scope
This framework is motivated by the goal of PANAMA, RadioGatún and Keccak to build simple tools for many different cryptographic constructions.

It is targeted primarily at constrained devices such as security cores and Internet of Things (IoT) devices, where code and memory come at a premium.  It should be particularly simple to implement on 32-bit microprocessors.

STROBE lite should make it easy to build hashing, encryption, and half-duplex protocols over reliable, in-order transports.  It is also possible to use the framework for asynchronous or unreliable messaging systems, but this is not as elegant.  Full-duplex systems are handled with a half-duplex channel in each direction.

# Security
STROBE lite provides approximately 128-bit provable security against classical adversaries (and 85-bit security against quantum adversaries) in the random permutation or random function (i.e. random oracle) model, even if they cause legitimate users to process up to 2^128 bytes of data.

TODO: there is a simple variant which should provide 128-bit security for some operations in the standard model.  Is it worth using?

# The duplex construction
STROBE lite is based on a duplexing sponge construction.  Each instance of STROBE lite has a rate _r_ := 8_R_+2 bits and a capacity _c_ = 8_C_-2 bits.  That is, it works on byte-aligned or larger data, with 2 bits of padding.  It also has a function F from _R_+_C_ bytes to _R_+_C_ bytes; F may be a permutation.  In the suggested implementation, _R_ = 68, _C_ = 32, and F is Keccak-F[800].

The state of a STROBE lite duplex object is an _R_+_C_-byte array `st`, and an offset `off` in that array which is between 0 bits and _R_ bytes, inclusive.  The state is initialized in a way that makes it distinct from SHA3, SHAKE, Keyak, different STROBE lite instances, and and STROBE lite with different rates.

```
class StrobeLite(object):
    def __init__(self,protoDescription,version="0.9",R=68,C=32,F=KeccakF(800)):
        self.R = R
        self.C = C
        self.F = F
        self.st = [0] * (R+C)
        self.off = 0
        
        # distinguish the rate
        self.st[R] ^= 4
        
        # distinguish the version
        aString = "STROBE lite v" + version
        self.st[-len(aString):] = (ord(c) for c in aString)
        
        # distinguish the instance
        self.duplex(protoDescription)
```

_Duplexing_ a sequence of bytes into the state uses the standard construction with a trailing 1 on every block:

```
    def duplex(self,bytes):
        out = []
        for byte in bytes:
            if self.off == self.R:
                self.st[self.off] ^= 1
                self.st = F(self.st)
                self.off = 0
            out.append(self.st[self.off] ^ byte)
            self.st[self.off] ^= byte
            self.off += 1
        return out
```

