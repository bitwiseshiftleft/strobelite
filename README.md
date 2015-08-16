# STROBE lite
STROBE lite is an experimental symmetric cryptography framework which can be used to construct systems as simple as hash functions and symmetric encryption, up to protocol handshakes and even entire protocols.

This MD describes the design of STROBE lite, with several **TODO**s which are possibilities for improving the design.  It also contains Python pseudocode (**TODO**: make it real code).

# Motivation and Scope
This framework is motivated by the goal of PANAMA, RadioGatún and Keccak to build simple tools for many different cryptographic constructions.

It is targeted primarily at constrained devices such as security cores and Internet of Things (IoT) devices, where code and memory come at a premium.  It should be particularly simple to implement on 32-bit microprocessors.

STROBE lite should make it easy to build hashing, encryption, and half-duplex protocols over reliable, in-order transports.  It is also possible to use the framework for asynchronous or unreliable messaging systems, but this is not as elegant.  Full-duplex systems are handled with a half-duplex channel in each direction.

# Summary
STROBE lite-based primitives and protocols are carried out as a sequence of transactions on a sponge state.  Each transaction has a _control word_, an _operation_ (forward or reverse duplex), and changes some amount of data by xor-ing it with the sponge state.

This acts as a hash function, just like Keccak.  Since the operation is broken up into transactions, it is easy to hash tuples.  If one of the inputs is a key, then the construction becomes both a stream cipher and a MAC.

When used in a protocol, each participant shares a sponge object which is kept in the same state as the other party's sponge object.  Each party duplexes all the messages they send or receive into the sponge.  This includes a direction flag to indicate who sent the message.  Then either the message can be sent in plaintext, or the duplex construction's output can be used as ciphertext.  This makes all the operations sensitive to all the data which has been exchanged so far.  An adversary cannot gain information about the messages exchanged (other than their length, who sent them, and any headers or messages deliberately sent as plaintext) unless she can reproduce everything which has been fed into the sponge including shared secret keys.

# Security
STROBE lite provides approximately 128-bit provable security against classical adversaries (and 85-bit security against quantum adversaries) in the random permutation or random function (i.e. random oracle) model, even if they cause legitimate users to process up to 2^128 bytes of data.

**TODO**: there is a simple variant which should provide 128-bit security for some operations in the standard model.  This is to xor in the capacity-bytes after applying the function.  Is it worth using?

# The duplex construction
STROBE lite is based on a duplexing sponge construction.  Each instance of STROBE lite has a rate _r_ := 8_R_+2 bits and a capacity _c_ = 8_C_-2 bits.  That is, it works on byte-aligned or larger data, with 2 bits of padding.  It also has a function F from _R_+_C_ bytes to _R_+_C_ bytes; F may be a permutation.  In the suggested implementation, _R_ = 68, _C_ = 32, and F is Keccak-F[800].

The state of a STROBE lite duplex object is an _R_+_C_-byte array `st`, and an offset `off` in that array which is between 0 bits and _R_ bytes, inclusive.  The state is initialized in a way that makes it distinct from SHA3, SHAKE, Keyak, different STROBE lite instances, and and STROBE lite with different rates.

```
class StrobeLite(object):
    def __init__(self,protoDescription,version="v0.9",R=68,C=32,F=KeccakF(800)):
        self.R = R
        self.C = C
        self.F = F
        self.st = [0] * (R+C)
        self.off = 0
        
        # distinguish the rate
        self.st[R] ^= 4
        
        # distinguish the version.  For the standard-model version, use "s" instead of "v"
        aString = "STROBE lite " + version
        self.st[-len(aString):] = (ord(c) for c in aString)
        
        # distinguish the instance
        self.duplex(protoDescription)
```

_Duplexing_ a sequence of bytes into the state uses the standard construction with a trailing 1 on every block:

```
# ...
    def duplex(self,bytes,forward=True):
        out = []
        for byte in bytes:
            if self.off == self.R:
                self.st[self.off] ^= 1
                self.st = F(self.st)
                self.off = 0
            out.append(self.st[self.off] ^ byte)
            if forward: self.st[self.off] ^= byte
            else: # ... next paragraph
            self.off += 1
        return out
```

This building block is useful for encryption (among other things).  The opposite construction is _unduplexing_:
```
# ...
            else: self.st[self.off] = byte
```
It is important to note that these operations **do not call F afterward**, even if they end on the rate _R_.

# Control words
Each operation against the sponge uses a control word and a forward or reverse duplex.  Control words describe what the operation means to the protocol, and what will be done with the output.  The meaning of the control word can vary across protocols.  In principle, control words may be free-form, so long as they are suffix-free (i.e. no control word is the suffix of another control word).  For STROBE lite as implemented, they are always exactly 4 bytes long.  They consist of a tag byte, a flag byte, and two length bytes:

```
# ...
    @staticmethod
    def makeControlWord(tag,forward,length):
        assert(length >= 0 and length < 0x10000)
        flags = int(forward) # MIKE TODO: add directions etc
        return [tag,flags,length%256,length>>8]
```

**TODO**: Possibly this should be in the opposite order, because that's better for suffix-freedom.

Note well that the length is not necessary for security.  It is included for two reasons:
* Sending the control word for all messages which will be transmitted (i.e. not keys, session IDs, sig challenges, etc) makes a half-decent framing protocol.
* This makes it slightly harder to screw up by using a MAC or something of a different length.

Control words are applied using the unduplex operation, followed by padding with the byte 3 and applying the F function.  **TODO**: Why 3 and not 2?  No good reason.  Maybe make it 2.

**TODO**: Why unduplex and not duplex?  It's so that you can forget more state, but maybe that's not worth a slightly weird construction.

```
# ...
    def useControlWord(self,cw):
        self.duplex(cw,forward=False) # and ignore output
        self.st[self.off] ^= 3
        self.st = self.F(self.st)
        self.off = 0
```

