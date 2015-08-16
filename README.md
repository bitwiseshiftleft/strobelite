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

STROBE lite is not nonce-misuse resistant.

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

**TODO**: Do we really care about marking the rate?

_Duplexing_ a sequence of bytes into the state uses the standard construction with a trailing 1 on every block:

```
# ...
    def _duplex(self,bytes,forward=True):
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

This building block is useful for encryption (among other things).  The opposite construction, mostly for decryption and state erasure, is _unduplexing_:
```
# ...
            else: self.st[self.off] = byte
```
It is important to note that these operations **do not call F afterward**, even if they end on the rate _R_.

# Control words
Each operation against the sponge uses a control word and a forward or reverse duplex.  Control words describe what the operation means to the protocol, and what will be done with the output.  The meaning of the control word can vary across protocols.  Call a control word _possible_ if, at some stage in the protocol, it could be used given the protocol initialization parameters and the previously exchanged control words.  These are the requirements on control words in principle:
* No possible control word can be the suffix of another possible control word.  This ensures parseability.
* It must be easy to decide if some string is a possible code word.
* Each possible control word should uniquely determine who sent the message (if anyone).  It must determine whether its data is duplexed or unduplexed.
* The control words are used to describe the meaning of the message _to the protocol_ as well as to the sponge.  Therefore, they should capture as accurately as possible what any plaintext being hashed means to the protocol, and what will be done with the output of the dulpex construction (including ignoring it).
* The empty control word is illegal.

**TODO** Should "possible" code words take into account the previous plaintext message, in case there's a TAG_HELLO version header?  There's a conflict between this and the statement of suffix-freedom.

For STROBE lite as implemented, control words are always exactly 4 bytes long.  They consist of a tag byte, a flag byte, and two length bytes:

```
# ...
    @staticmethod
    def makeControlWord(tag,length,forward=True):
        assert(length >= 0 and length < 0x10000)
        flags = int(forward)
        return [tag,flags,length%256,length>>8]
```

**TODO**: Possibly the bytes should be in the other order, because that's better for suffix-freedom if someone wants to mix and match.

**FIXME**: STROBE lite includes a direction indicator which goes in the flags, but it's not shown above.

**TODO**: Should there be other flags included into the control word, like "output is not used" or something?

**TODO**: Since there are only a few bits of flags, tags can be longer than one byte.

Note well that the length here is not necessary for security, so that it could be omitted or set to a fixed value by a protocol which uses some sort of streaming crypto.  It is included above for two reasons:
* Sending the control word for all messages which will be transmitted (i.e. not keys, session IDs, sig challenges, etc) makes a half-decent framing protocol.
* This makes it slightly harder to screw up by using a MAC or something of a different length.  (It better describes the meaning of the message and what the output will be used for.)

Tags will be written TAG_FOO, which means some protocol-specific constant byte.

Control words are applied using the unduplex operation, followed by padding with the byte 3 and applying the F function.  **TODO**: Why 3 and not 2?  No good reason.  Maybe make it 2.

**TODO**: Why unduplex and not duplex?  It's so that you can forget more state, but maybe that's not worth a slightly weird construction.

**TODO**: BLINKER xor's the control word into a fixed place in the _C_ region.  This probably leads to less performance, less code and a slightly weirder design.  Worth it?

```
# ...
    def _useControlWord(self,cw):
        self._duplex(cw,forward=False) # and ignore output
        self.st[self.off] ^= 3
        self.st = self.F(self.st)
        self.off = 0
```

# Transactions
The combination of a control word, an operation and some data is a transaction.

```
# ...
    def transaction(self,tag,data,forward=True,cw=None):
        if cw is None: cw = self._makeControlWord(tag,len(data),forward)
        self._useControlWord(self,cw)
        return self._duplex(data,forward)
```

**TODO** thread through direction flags etc

Some possible example transactions:
* TAG_KEY,keybytes to key a cipher.
* TAG_ENCRYPT,plaintext to send an encrypted message (but see MAC code below).
* TAG_ENCRYPT,ciphertext,reverse to decrypt an encrypted message.
* TAG_NONCE,nonce to include a nonce.
* TAG_AD,associatedData to include associated data.
* TAG_DHEPH,g^x to send an ephemeral DH key
* TAG_PRF,[0]*n to extract _n_ bytes of pseudorandom data from the state.
* TAG_HASH,[0]*n to finalize a hash context.

# Parseability
The duplexing-sponge lemma shows that the state data used in each transaction is indifferentiable from a random oracle on all the past data xor'd into the sponge (or unduplexed, if it is clear which has happened).  This is a pretty good security guarantee if the history of transactions can be obtained from the history of data xor'd into the sponge.

This is so because:
* The last byte xor'd into a block is always 1 or 3.  If it's a 3, then this block and possibly the previous ones contain a code word.  The block ends just before the 1 or 3.
* Concatenating the 1-blocks followed by the 3-blocks gives the data followed by the next code word.
* The protocol can be parsed in the order that the transactions occur.  First the following code word is parsed, and then the data.
* The code word was unduplexed.  It can be recovered from the queries (or as xordata^state), starting from the end of the block, until a possible code word is obtained.
* The rest of the data is actually data.
* Since the previous code word has already been parsed, it can be determined what that data means to the protocol and whether it was duplexed or unduplexed.
* When the permutation is called in a streaming fashion, it is clear what the previous control words were, but it is not clear whether the last few bytes of the call are data or the beginning a new control word.
** It's clear in the base STROBELITE because of the length field, but that isn't required in variants.
** This isn't a problem, because if the last few bytes are the beginning of a new control word, the output will not be returned from the transaction() routine.

**TODO** The init routine conflicts with variable length code words.  Fix it, possibly by adding a F(st^3) to the end of init.

# MAC and forget
To send a message authentication code (which authenticates **every transaction** performed so far on the state), we use TAG_MAC.  However, there is also a minor problem with using the sponge as written: forward secrecy.  Since F is (in the common case) a permutation, an attacker who recovers the state at some time can undo most transactions, possibly revealing encrypted messages or PRF calls.

To fix this problem, there is a "forget" operation of unduplexing a sufficient number of 0s.  Since unduplex overwrites the state, this transformation is irreversible.

It is convenient to combine this operation with a MAC operation:
```
# ...
    def macForget(self,tag=TAG_MACFORGET,length=16,forget_length=None):
        if forget_length is None:
            forget_length = self.R-length-4
            assert(forget_length >= 32)
        else: assert(length+forget_length <= self.R)
        
        taggedForgot = self.transaction(tag,[0]*(length+forget_length),forward=False))
        return taggedForgot[:length]
```

Each protocol must set forget_length to a unique function of length (or rather, of the control word which includes the length).

The reason for the default `forget_length = self.R-length-4` is that in the base version of the protocol, control words are always 4 bytes.  This means that exactly the first _R_ bytes can be erased from the state without losing information, reducing the state size to _C_ = 32 bytes.

# Example protocols

**TODO** (that's enough typing for one day...)

# The DPA-resistant key tree
**WARNING** This section may be covered by Rambus Cryptography Research (or other) patents.

STROBE lite is naturally DPA-resistant since it's a stream cipher.  Furthermore, Keccak-F should be relatively easy to mask aganist power analysis.  However, if the adversary can cause the same key to be injected repeatedly (eg, it is built into the hardware) with different states or different following messages, then the system may be vulnerable to DPA.

The simplest approach to solve this problem at Cryptography Research is to stir in a unique identifier only a few bits at a time.  This causes each secret key or state to be used in only a few ways, which hampers the "differential" part of DPA.  This is easy enough to implement:
```
# ...
    def macForget(self,tag=TAG_KEYTREE,data,bits_at_a_time = 2):
        assert(bits_at_a_time >= 1 and bits_at_a_time <= 7)
        cw = self._makeControlWord(tag,len(data),forward)
        self._useControlWord(self,cw)
        
        mask = (1<<bits_at_a_time)-1
        for byte in data:
            for sh in xrange(0,8,bits_at_a_time):
                self.st[0] ^= (byte>>sh)&mask
                self.st[0] ^= 1<<bits_at_a_time
                self.st = F(self.st)
                
        macForget(self,TAG_KEYTREE_DONE,length=0)
        # doesn't return anything
```

This doesn't harm parseability, because it creates blocks which cannot be produced in any other way (since control words must be at least a byte, and non-control-word blocks can't be empty without having a following control word).  Furthermore, those blocks determine the rate (`bits_at_a_time`) of the operation.

# Change cipher suite and round count
**WARNING** This section is speculative.  And a hack.

Some protocols may wish to use a stronger sponge protocol for the header, and a weaker (eg reduced-round) system for the rest of the protocol.  This is a performance hack, but it is defensible since Keccak is likely to resist attacks with many fewer rounds if it is keyed.  (See eg Keyak.)

The correct way to change the cipher suite in use is to use a TAG_PRF or similar operation to initialize the new cipher.  However, a passable hack for reducing the round count is to apply a codeword with TAG_RESPEC and the new round count (**as part of the codeword**, i.e. not using the standard STROBE lite code word scheme), and then to forget self.R-4 bytes of the state as above.