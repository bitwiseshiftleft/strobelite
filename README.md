#Version
This is version 0.2 of the STROBE Lite document.

# Disclaimer
I am not a lawyer.  This code may be covered by patents, export restrictions, and the like.  Please consult a lawyer before deploying this code, specifications or anything based on them.  I would be especially careful in adapting TripleDH to run on STROBE lite.

I am a cryptographer.  However, I sometimes make mistakes.  Also, while STROBE lite is designed to be relatively easy to use, it is not by any means foolproof.  Please consult another cryptographer before implementing or deploying STROBE lite.

# STROBE lite
STROBE lite is an experimental symmetric cryptography framework which can be used to construct systems as simple as hash functions and symmetric encryption, up to protocol handshakes and even entire protocols.

This MD describes the design of STROBE lite, with several **TODO**s which are possibilities for improving the design.  There is a python implementation of this design in the repository.

# Motivation and Scope
This framework is motivated by the goal of PANAMA, RadioGatún and Keccak to build simple tools for many different cryptographic constructions.

It is targeted primarily at constrained devices such as security cores and Internet of Things (IoT) devices, where code and memory come at a premium.  It should be particularly simple to implement on 32-bit microprocessors.

STROBE lite should make it easy to build hashing, encryption, and half-duplex protocols over reliable, in-order transports.  It is also possible to use the framework for asynchronous or unreliable messaging systems, but this is not as elegant.  Full-duplex systems are handled with a half-duplex channel in each direction.

# Summary
STROBE lite-based primitives and protocols are carried out as a sequence of transactions on a sponge state.  Each transaction has a _control word_, an _operation_ (forward or reverse duplex), and changes some amount of data by xor-ing it with the sponge state.  Transactions may be batched for slightly higher performance.

This acts as a hash function, just like Keccak.  Since the operation is broken up into transactions, it is easy to hash tuples.  If one of the inputs is a key, then the construction becomes both a stream cipher and a MAC.

When used in a protocol, each participant shares a sponge object which is kept in the same state as the other party's sponge object.  Each party duplexes all the messages they send or receive into the sponge.  This includes a direction flag to indicate who sent the message.  Then either the message can be sent in plaintext, or the duplex construction's output can be used as ciphertext.  This makes all the operations sensitive to all the data which has been exchanged so far.  An adversary cannot gain information about the messages exchanged (other than their length, who sent them, and any headers or messages deliberately sent as plaintext) unless she can reproduce everything which has been fed into the sponge including shared secret keys.

# Security
STROBE lite provides approximately 128-bit provable security against classical (non-quantum) adversaries in the random permutation or random function (i.e. random oracle) model.  The probability that an attacker can differentiate it from a random oracle should be bounded by approximately (_M_+_N_)^2 / 2^250, where _M_ is the number of F-queries the legitimate users make and _N_ is the number of F-queries the adversary makes.  This should be written up formally, but the argument should be straightforward.

(This is slightly less than 2^256 because of padding words and so on, but it will be > 2^250 in the recommended protocols and > 2^245 everywhere I think; **TODO** bound more precisely.)

**TODO** I'm not an expert in quantum adversaries, but I would guess that the ^2 should be replaced by ^3.

**TODO**: there is a simple variant which should provide approximately 128-bit security for some operations in the standard model instead of the random permutation model.  This is to xor in the capacity-bytes after applying the function.  Is it worth using?

STROBE lite is not nonce-misuse resistant.

# The duplex construction
STROBE lite is based on a duplexing sponge construction.  Each instance of STROBE lite has a rate _r_ := 8_R_+8 bits and a capacity _c_ = 8_C_-8 bits.  That is, it works on byte-aligned or larger data, with one byte of padding.  It uses a function F from _R_+_C_ bytes to _R_+_C_ bytes; F may be a permutation.  In the suggested implementation, _R_ = 68, _C_ = 32, and F is Keccak-F[800].  (For larger devices, a "STROBE" protocol would use full Keccak-F[1600].)

The state of a STROBE lite duplex object is an _R_+_C_-byte array `st`, and an offset `off` in that array which is between 0 bits and _R_ bytes, inclusive.  The state is initialized in a way that makes it distinct from SHA3, SHAKE, Keyak, different STROBE lite instances, and and STROBE lite with different rates.

**TODO** If NIST publishes their domain-separation design, and it's a prefix and not a postfix, then we should switch to that.

Duplexed blocks are padded with a padding byte 0x02 to indicate that they have exceeded the rate, but that they are not the beginning of a new transaction (or rather, a new batch of transactions).
```
# ...
    def _runF(self,pad):
        self.st[self.off] ^= pad
        self.st = self.F(self.st)
        self.off = 0

    def _duplex(self,op,data):
        out = []
        
        for byte in bytearray(data):
            if self.off == self.rate:
                self._runF(0x02)
            
            if op in ("duplex","duplex_r"): out.append(self.st[self.off] ^ byte)
            elif op in ("absorb","absorb_r"): out.append(byte)
            
            if op in ("duplex_r","absorb_r"): self.st[self.off] = byte
            else: self.st[self.off] ^= byte
            
            self.off += 1
            
        return bytearray(out)
```
The _reversed_ modes (ending in `_r`) above overwrite the state of the sponge instead of xoring into it.  This is useful for decryption (à la Keyak) and for forgetting the current state.

It is important to note that these operations **do not automatically call F afterward**, even if they end on the rate _R_.

# Transactions

STROBE lite commands are divided into transactions.  Each one includes a _control word_ with a protocol-specific tag, an operation, and some data.  The control word's representation in the sponge includes the tag, and a flag field which depends on the operation and who sent the message (client or server).  The control word's bytes are _reverse_-duplexed (for unimportant reasons having to do with state forgetting).

Control words use the pad byte 0xCn for a control word of n<16 bytes.  This ensures parseability: by looking at which blocks used as input to the sponge end in 0x02 and which end in 0xCn, one can divide the sponge's input into (control word, transaction) pairs.  If the transaction uses the sponge's output at all (which can be determined by the operation byte), that output will depend on the control word and on all previous (control word, transaction) pairs.

STROBE lite control words are always exactly 4 bytes long, but extensions may use other lengths.
```
def transact(self,cw,data=None,receive=False):
        # serialize the control word
        cwb,pad = cw.toBytes(len(data),self.am_client,receive=receive)
        
        # reverse-absorb the control word
        self._duplex("absorb_r",cwb)
        
        # run F if necessary
        if pad: self._runF(pad)
        
        # apply the duplex operation to the data
        op = cw.op
        if receive:
            # Effectively switch encrypt <-> decrypt
            if op == "duplex": op = "duplex_r"
            elif op == "duplex_r": op = "duplex"
        ret = self._duplex(op,data)
            
        return cwb,ret
```

The reason for 0x02 and 0xC4 is for extensions: a padding byte that ends in the bits _bs_ + 01 is a to be concatenated (this is used for the key tree).  A padding byte ending in _n_0011 indicates the end of input, where the output will be used as determined by an n-byte control word.  Bytes ending in bb11 are reserved for future use.

## Batching
Transactions which don't use the sponge's output don't use the 0xC4 pad byte, and do not forcibly run _F_.  This amends the previous section's statement: one can divide the sponge's input into (control word, batch) pairs, where the control word covers the first transaction in the batch.

For the recommended STROBE lite control words, the control word is always exactly 4 bytes long and one can determine the length and operation from the control word.  This ensures that the control words and data within a batch can be parsed.  If an extension deviates from this design for certain transactions, it is strongly recommended that they ensure parseability by always placing such transactions in their own batch.  The example code's "noparse" flag implements this behavior, but is not used from within unextended STROBE lite.

## Forgetting

Some transactions may "forget" state, by erasing the rest of the block after the transaction is complete, minus 4 bytes.  This is best combined with reversed transactions of fixed length, which will cause the entire block will be 0.  Forgetting transactions begin a new batch.  If at least 16 bytes are forgetten in this way, it will prevent an adversary who compromises the state of the object from compromising earlier states; this would otherwise be possible when F is a permutation (eg Keccak-F[800]).

# Control words

The recommended control words have a serialized form, and several additional flags and fields which impact how they will be used.

* An `implicit` transaction will not be sent on the wire.
* A transaction with the `forget` flag will use the forgetting mechanism described above.
* A transaction can be marked `no_send_tag` or `no_send_len`, to tell the protocol handler to send only part of the control word in framed messages (to save bandwdith).
* A message can be marked `input_zero` to indicate that the input (or output, on receipt) is always a sequences of zeros.
* The Python control word class includes a length field for convenience, so that applications don't need to pass a length.

The following options are not used in the Python code at all, and are included as a guideline for extensions:

* A transaction can be marked `noparse` to indicate that no message can follow it in a batch.
* * This would be used if the serialized form of a tag has been modified not to include the length of the data, eg for streaming encryption.
* A message can be marked `run_f` to indicate that the handler should always append the 0xC4 pad and run F().  This means that 
* A message can be marked `implicit_dir` to indicate that even though it will not be sent, it should be considered directional when serializing the control word; that is, it is considered to originate on the client or server.  This is for extensions.
* A message can be marked `keytree` to indicate that it is a diversifier for the DPA-resistant key tree.

The serialized forms of the recommended control words are exactly 4 bytes long. It consists of

* A one-byte operation, whose bits are:
* * Bit 0: The data will be sent.  (Other transactions, such as setting keys, are called "implicit".)
* * Bit 1: The data will be sent by the client.
* * Bit 2: The sponge's output will be used.
* * Bit 3: The operation is reversed (i.e. `duplex_r` or `absorb_r`)
* * Bit 4: After the operation, the rest of the block will be erased up to _R_-4.
* A one-byte tag, indicating what the transaction means to the protocol.
* A two-byte little-endian length.

## Example control words

The file [Strobelite/ControlWord.py](Strobelite/ControlWord.py) lists many examples of control words that might be used for STROBE lite protocols.  In practice, unless you're trying to replace TLS, you'll use only a small subset of these.

# Framing
The simplest framing mechanism is to simply to send the serialized control word for all non-implicit operations.  However, ths can be made more efficient.  In particular, since the first byte of the control word (the op tag) should be a function of the second byte and direction, it does not need to be sent.

The example code's framing mechanism is to optionally send the tag, and then optionally send the length, in each case depending on the control word.  That way, protocols which need to be forward-compatible or easy to parse can send the tag and length on all transactions, whereas ones where bandwidth is more important can omit the tag or length when it is understood from context.

# Signatures

STROBE lite supports a very simple Schnorr-style signature algorithm, which does not require any external hashing mechanism.  The signature is over a STROBE lite object, so it can be over simple plaintext, an encrypted message, or an entire session.

To sign the STROBE lite object with a discrete-log secret key _x_, the signer chooses a (pseudo)random _k_ and computes g^k.  In the random oracle model, this may be done by copying the STROBE lite object; executing a `FIXED_KEY` transaction with the signing key; and then extracting _k_ (of 3*_B_/2 bytes for a B-byte field) using a `PRNG` operation.  This allows deterministic signing.

The signer puts in a `SIG_EPH` transaction with g^k, then runs a `SIG_CHAL` implicit transaction (with length _B_, since the challenge need not be uniform) to obtain a challenge _c_.  It then returns a `SIG_RESP` transaction with the value cx+k mod q.  The `SIG_RESP` is a duplexed transaction, not a plaintext one; this makes the signature function also as a MAC (i.e. it prevents the signature with k=x=response=0 from verifying on every state).

To verify such a signature with public key X=g^x, the verifier decodes K=g^k, the challenge _c_ and the response r.  It then computes whether g^r / X^c = K.

# Example protocols

**TODO**: Come up with a scheme for initialization protocols.  Probably it should be a URI scheme.

**WARNING**: while it would be simple to implement double- or triple-DH on top of STROBE lite, you might run into trouble with the KEA+ patents if you are not careful.  Furthermore, it would be easy to build FHMQV on STROBE lite, but again this is patented.

## Signature protocol
STROBE lite can be used for things as simple as signed messages.
* Initialize with "http://example.com/sign".
* Put in a plaintext message `SIG_SCHEME`, (an identifier for Schnorr on your elliptic curve).
* Put in a plaintext message `SIG_PK` with the public key of the signer.
* Put in any other relevant context with suitable tags.
* Put in one or more `PAYLOAD_PLAINTEXT` blocks, possibly without the headers (or modified for streaming hashing, i.e. `noparse`).
* Put in an `OVER` transaction.
* Run the above signature protocol with `SIG_EPH`, `SIG_CHAL` and `SIG_RESP` transactions.
* * For safe streaming decryption, you could interleave such signatures with blocks of the message.  If you do this, don't put an `OVER` transaction before the intermediate signatures.

## Authenticated encryption
Likewise, authenticated encryption is easy.  An authenticated encrypted message can be signed (much as above) or MAC'd:
* Initialize with "http://example.com/auth_encrypt".
* Put in a plaintext message `HELLO` with a description of the scheme.
* Put in the other party's long-term public key with `STATIC_PUB`.
* Put in your long-term public key with `STATIC_PUB`.
* Put in your ephemeral key with `DH_EPH`.
* Put in the shared long-term/long-term and ephemeral/long-term keys, each with `DH_KEY`.
* Put in any authenticated data with `EXPLICIT_AD` messages.
* Put in one or more `PAYLOAD_CIPHERTEXT` blocks, possibly without the headers (or modified for streaming hashing, i.e. `noparse`).
* Put in an `OVER` transaction
* Finally, add a `MAC` block.
* * For safe streaming decryption, you can put `MAC` blocks in between the message blocks at any interval.  If you do this, don't put the `OVER` transaction before the intermediate `MAC`s.

## Signed handshake
A TLS-style signed handshake is also straightforward.
* Initialize with "http://example.com/handshake".
* Client->server: `VERSION` (0,2) or whatever.
* Client->server: HELLO (any relevant hello data, ciphersuites, etc).
* Client->server: `DH_EPH`, g^x.
* Client->server: `OVER`. (For forward compatibility.)
* Server->client: `VERSION` (0,2).
* Server->client: `DH_EPH`, g^y
* Both: `DH_KEY`, g^xy
* Server->client: `CERTIFICATE`, server cert(s).  The certs are encrypted with the ephemeral key.
* Server->client: signature protocol as above.
* Server->client: `OVER`.
* Client->server: if the context established by HELLO messages requires it, certificate and signature.
* Client->server: `PAYLOAD_CIPHERTEXT`, `MAC`, ...

## Full duplex and asynchronous protocols

STROBE lite is a half-duplex protocol framework, designed for handshakes.  However, if handshake messages are sent in cleartext, they can (depending on protocol) be sent early to reduce latency.  If the protocol eventually goes full-duplex, this can be accomplished by forking the protocol using a `FORK` transaction. Then for each direction (or for each pipe in each direction), a copy of the state can be fed an `INSTANCE` transaction with a unique identifier for that pipe and direction.

If a protocol is asynchronous, and needs to acknowledge in one stream that a message in another stream has been sent, it can use an `ACKNOWLEDGE` transaction with the nonce or MAC of the other message.  If the MAC is used instead of the nonce, one must be careful of the birthday bound: if there are 2^30 messages in the window which one might want to acknowledge, and a 128-bit MAC, then there is a 1/2^68 probability that the wrong message will be acknowledged.

## Steganographic protocols

The framing and transactions can be modified as follows for steganographic protocols:

* No plaintext messages should be used.
* Until a secret key can be absorbed, all transactions must use data which is indistinguishable from uniformly random.
* Until a secret key can be absorbed, the control word must not be part of the framing protocol.
* Batching is disabled; every transaction is in its own batch.
* The control words are applied using `duplex_r` instead of `absorb_r`.  This is the same as far as the sponge is concerned, but ciphertext is sent down the wire instead of plaintext.
* Optionally, every control word can be MAC'd.  This can be done by squeezing out _M_ bytes before each transaction.
* Some sort of length padding should be used to disguise the length of messages.

This design needs a rigorous security analysis before it can be used (**TODO**).

## Forward-compatibility

Protocols can be made forward-compatible by the following mechanism:

* All control words in the first flight have both the tag and length in the frame, unless they were present in the first version.
* * Control words from the first version can omit the length.
* The first flight includes a VERSION transaction, with a major and minor version number (say, one byte each).
* No implicit operations are performed in the first flight.
* The first flight ends with an OVER transaction.
* If the initiator's VERSION has a major version which is higher than what the responder supports, it responds with a lower VERSION tag, and possibly additional information.
* * Perhaps a select few fields will have a fixed meaning across major versions; the initiator and responder might use these fields.
* * All other fields will be ignored, except that they are hashed into the STROBE lite state as usual.
* If the initiator's VERSION has a minor version which is higher than what the responder supports, it responds with a lower VERSION tag.
* * If this happens, then fields defined since the responder's version are ignored.
* If the responder has a higher version than the initiator, the responder speaks the initiator's version.
* * If the initiator's version of the protocol is known to be broken, then the responder sends a fatal error.  The error code is authenticated if possible.

# The DPA-resistant key tree
**WARNING** This section may be covered by Rambus Cryptography Research (or other) patents.

STROBE lite is naturally DPA-resistant since it's a stream cipher.  Furthermore, Keccak-F should be relatively easy to mask aganist power analysis.  However, if the adversary can cause the same key to be injected repeatedly (eg, it is built into the hardware) with different states or different following messages, then the system may be vulnerable to DPA.

The simplest approach to solve this problem at Cryptography Research is to stir in a unique identifier only a few bits at a time.  This causes each secret key or state to be used in only a few ways, which hampers the "differential" part of DPA.

This doesn't harm parseability, because each block still ends in the bits 2'b01 (for non-control words) or 2'b11 (for control words).

# Change cipher suite and round count
**WARNING** This section is speculative.  And a hack.

Some protocols may wish to use a stronger sponge protocol for the header, and a weaker (eg reduced-round) system for the rest of the protocol.  This is a performance hack, but it is defensible since Keccak is likely to resist attacks with many fewer rounds if it is keyed.  (See eg Keyak.)

The correct way to change the cipher suite in use is to use a TAG_PRF or similar operation to initialize the new cipher.  However, a passable hack for reducing the round count is to apply a codeword with TAG_RESPEC and the new round count (**as part of the codeword**, i.e. not using the standard STROBE lite code word scheme), and then to forget self.R-4 bytes of the state as above.