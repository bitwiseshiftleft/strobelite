from collections import namedtuple

class StrobeliteError(Exception):
    """
    Class of error used in the Strobelite implementation

    Use: raise Strobelite.StrobeliteError("Text to be displayed")
    
    WARNING! The error messages used in this document are very explicit for
    purposes of tinkering.  They contain information which should not be
    returned to an attacker.
    """
    def __init__(self, value): self.value = value
    def __str__(self): return repr(self.value)

class ControlWord(namedtuple("ControlWord",("name","op","id","flags","length"))):
    """
    Control word for STROBE lite.
    
    This class represents a sponge operation, a 12-bit identifier and some flags.
    
    The sponge operations are:
        Absorb: Absorb data into the sponge (roughly state ^= input)
            Used for keys, nonces, and data sent in plaintext on the wire.
        
        Absorb_r: Overwrite part of the state with input.
            Used for erasing part of keys, because KeccakF is a permutation.
            Also used for the control word itself, basically for forgetfulness
            reasons.
        
        Duplex: output = state = state ^ input
            Used for encryption.
            Used with input = 0 as a "squeeze" operation (PRNG, hashing, etc)
        
        Duplex_r: output = state ^ input; state = input
            Used for decryption
            Used with input = 0 to simultaneously "squeeze" and forget
                Used in this context for MACcing.
    
    The ControlWord class also has a way to produce a 4-byte length field, which
    includes:
        * The identifier.
        * Whether the operation is "implicit", i.e. not to be sent on the wire.
        * If the operation is sent, whether the client or server is sending it.
        * A 2-byte length field.
    """
    
    # The possible flags (others will be rejected as a sanity check).
    knownflags = frozenset((
        "implicit",    # The data won't be sent on the wire.  Eg, keys.
        "client_sent", # The data was sent by the client
        "forget",      # Erase state after sending.  Implies run_f.
        "no_send_tag", # The tag should not be sent.
        "no_send_len", # The length should not be sent.
        "input_zero",  # The input is all zeros
        "implicit_dir",# EXT: The data won't be sent, but has a well-defined direction
        "noparse",     # The tag doesn't have a length field, and so causes the next tag to be runF.
        "run_f",       # The user MUST run F after the tag, even though there is no squeeze.
        "keytree",     # EXT: Use the DPA-resistant key ladder.
    ))
    
    """
    The possible flags (others will be rejected as a sanity check).
    """
    knownops = {
        "absorb"   : 0, # Absorb the data into the sponge.  If sent, send in plaintext
        "absorb_r" : 2, # Clobber the data in the sponge with this data
        "duplex"   : 1, # Absorb and xor with squeeze.  (Pass all zeros for squeeze)
        "duplex_r" : 3  # Reverse absorb and xor with squeeze
    }
    
    def __new__(cls,id,op,name,flags=(),length=None):
        op = op.lower()
        flags = frozenset((flag.lower() for flag in flags))
        
        # Sanity checks
        if op not in ControlWord.knownops:
            raise StrobeliteError("Unknown op " + repr(op))
            
        badFlags = [ flag
                     for flag in flags
                     if flag not in ControlWord.knownflags
                   ]
        if len(badFlags) != 0:
            raise StrobeliteError("Bad flag(s): " + str(badFlags))
            
        if id < 0 or id >= 1<<8:
            raise StrobeliteError("Bad id: " + str(id))
        
        # It's a namedTuple
        return super(ControlWord,cls).__new__(cls,name,op,id,flags,length)
    
    
    ###
    # Get properties
    ###
    def is_noparse(self):
        return "noparse" in self.flags
        
    def is_run_f(self):
        return (
            "run_f" in self.flags
            or "forget" in self.flags
            or self.op in ("duplex","duplex_r")
        )
        
    def is_nondir(self):
        return "implicit" in self.flags
        
    def is_forget(self):
        return "forget" in self.flags
        
    def is_implicit(self):
        return "implicit" in self.flags or "implicit_dir" in self.flags
    
    def send_bytes(self):
        out = []
        if "no_send_tag" not in self.flags: out += [1]
        if "no_send_len" not in self.flags: out += [2,3]
        return out
    
    ###
    # Adjust properties
    ###
    def make_explicit(self):
        return self.__class__(self.name,self.op,self.id,self.flags
            - frozenset("implicit","implict_dir"))
            
    def make_implicit_dir(self): return self.__class__(self.name,self.op,self.id,self.flags
        + frozenset("implicit_dir"))
    
    def toBytes(self,length,am_client=False,receive=False,force_run_f=False):
        if length < 0 or length >= 1<<16:
            raise StrobeliteError("Bad length: " + str(length))
        
        if self.is_nondir():
            c2s = 0
        elif receive:
            c2s = int(not(bool(am_client)))
        else:
            c2s = int(bool(am_client))

        flagfield = c2s | int(not self.is_implicit())<<1 | ControlWord.knownops[self.op]<<2
        theBytes = [flagfield, self.id & 0xFF, length&0xFF, length>>8]
        
        # Padding byte
        if self.is_run_f() or force_run_f: pad_byte = len(theBytes) | 3<<6
        else: pad_byte = None
        
        return bytearray(theBytes), pad_byte
    
    def __str__(self):
        l = [self.op] + list(self.flags)
        if self.length: l += "length=%d" % self.length
        return "0x%02x (%s): %s" % (self.id,self.name,",".join(l))
    
    @classmethod
    def register(cls,id,op,name,flags=(),**kwargs):
        name = name.upper()
        return cls(id,op,name,flags,**kwargs)
    
    @classmethod
    def duplex(cls,id,name,*flags,**kwargs):
        return cls.register(id,"duplex",name,flags,**kwargs)
    
    @classmethod
    def duplex_r(cls,id,name,*flags,**kwargs):
        return cls.register(id,"duplex_r",name,flags,**kwargs)
    
    @classmethod
    def squeeze(cls,id,name,*flags,**kwargs):
        return cls.register(id,"duplex",name,("implicit","input_zero")+tuple(flags),**kwargs)
    
    @classmethod
    def plaintext(cls,id,name,*flags,**kwargs):
        return cls.register(id,"absorb",name,flags,**kwargs)
        
    @classmethod
    def absorb(cls,id,name,*flags,**kwargs):
        return cls.register(id,"absorb",name,("implicit",)+tuple(flags),**kwargs)
        
    @classmethod
    def absorb_r(cls,id,name,*flags,**kwargs):
        return cls.register(id,"absorb_r",name,("implicit",)+tuple(flags),**kwargs)

################################################################################
# Example control words.
#
# The STROBE lite framework is not tied to any of these definitions except INIT.
# These are just some examples / recommendations of what you can use.
#
# These code words span the gamut from offline encrypted and/or signed messages,
# to full TLS-like protocols.
#
# ***
# The assumption is that most protocols will use a VERY SMALL SUBSET of these tags.
# They are comprehensive just to demonstrate that you could replace TLS with a
# protocol like this.
# ***
################################################################################

################################################################################
# Initialization
#
# INIT: The initialization string for the sponge.
#     XXX TODO: make INIT compatible with NIST domain separation, if they make it
#     a prefix and not a suffix (if it's a suffix, can't do this).
#
# VERSION: always 2-byte, major and then minor.
#     Intended use is for forward-compatible protocols.  Client sends version;
#     if it's too high, server responds to first flight with a lower version
#     and client continues.  Client's messages in first flight are still hashed
#     into the protocol log.
#
#     XXX TODO: of course, in forward-compatible protocols, you will need to
#     more rigorously nail down which tags have implicit lengths and which ones
#     use which duplex modes, or else the two parties states will not match up
#     anyway.
#
# HELLO: other sorts of first-flight handshake data.
#
# CIPHERSUITE:
#     When sent by initiator, offered cipher suite.
#     When sent by responder, selected cipher suite.
#
# EXTENSION:
#     Any sort of extension data which is safe to ignore.
#     (TODO: a separate type for mandatory extensions?)
#
# ENCRYPTED_EXTENSION:
#     Same, but encrypted with any data that's been sent so far.
#
# CERTIFICATE:
#     A party's encrypted certificate (though the length will leak...)
#
# HEADER_PLAINTEXT:
#     Any kind of header plaintext not defined above.
#
# HEADER_PLAINTEXT:
#     Any kind of header ciphertext not defined above.
#
# OVER: In forward-compatible protocols, mark the end of a flight where the other
#     party might not be able to figure that out.
#
#     It is reasonable to use this moment to COMPRESS / FORGET the state as well.
################################################################################

INIT                = ControlWord.absorb   (0x00,"INIT")
VERSION             = ControlWord.plaintext(0x01,"VERSION","no_send_len",length=2) # 2 bytes
HELLO               = ControlWord.plaintext(0x02,"HELLO")
CIPHERSUITE         = ControlWord.plaintext(0x03,"CIPHERSUITE")
EXTENSION           = ControlWord.plaintext(0x04,"EXTENSION")
ENCRYPTED_EXTENSION = ControlWord.duplex   (0x05,"ENCRYPTED_EXTENSION")
CERTIFICATE         = ControlWord.duplex   (0x06,"CERTIFICATE")
HEADER_PLAINTEXT    = ControlWord.plaintext(0x0D,"HEADER_PLAINTEXT")
HEADER_CIPHERTEXT   = ControlWord.duplex   (0x0E,"HEADER_CIPHERTEXT")
OVER                = ControlWord.absorb_r (0x0F,"OVER","no_send_len","forget",length=0) # TODO: compress, run_f?

################################################################################
# Keys.
#
# FIXED_KEY: a preshared secret or similar.
#
# DH_EPH: an ephemeral Diffie-Hellman public key.
#
# DH_KEY: the shared secret.
#
# PRNG: extract a pseudorandom value.
#
# SESSION_HASH: like PRNG, but extract a value with the intention of eg signing
# the session.
################################################################################
FIXED_KEY    = ControlWord.absorb   (0x10,"FIXED_KEY")
DH_EPH       = ControlWord.plaintext(0x11,"DH_EPH")
DH_KEY       = ControlWord.absorb   (0x12,"DH_KEY")
PRNG         = ControlWord.squeeze  (0x18,"PRNG")
SESSION_HASH = ControlWord.squeeze  (0x19,"SESSION_HASH")

################################################################################
# Signatures.  This design uses a Schnorr-like scheme built into STROBE lite.
#
# SIG_SCHEME: a signature scheme description, in some to-be-defined form
#
# SIG_PK: The public key used to sign, if that isn't already clear.
#
# SIG_EPH: a Schnorr ephemeral g^k
#
# SIG_CHAL: the implicit challenge
#
# SIG_RESP: the response, the final part of the signature.
################################################################################
SIG_SCHEME   = ControlWord.absorb   (0x20,"SIG_SCHEME")
SIG_PK       = ControlWord.absorb   (0x21,"SIG_PK")
SIG_EPH      = ControlWord.plaintext(0x22,"SIG_EPH")
SIG_CHAL     = ControlWord.squeeze  (0x23,"SIG_CHAL")
SIG_RESP     = ControlWord.duplex   (0x24,"SIG_RESP")

################################################################################
# Payloads and encryption.
#
# PAYLOAD_PLAINTEXT: any sort of message that the application wants to send in
#     plaintext for some reason (eg, because this is an authentication protocol,
#     not an encryption protocol).
#
# PAYLOAD_CIPHERTEXT: An encrypted message.
#
# MAC: A MAC of fixed 96-bit length.  This is also special-cased by the MAC
#     function to erase most of the state so that the call will not be
#     invertible.  (XXX TODO: should we really do this?)
#
# AD_EXPLICIT: Explicit authenticated data, sent down the wire.
# AD_IMPLICIT: Implicit authenticated data which both sides know.
#
# NONCE_EXPLICIT: An explicit packet nonce.
# NONCE_IMPLICIT: A nonce which both sides know, eg a counter.
################################################################################
PAYLOAD_PLAINTEXT  = ControlWord.plaintext(0x30,"PAYLOAD_PLAINTEXT")
PAYLOAD_CIPHERTEXT = ControlWord.duplex   (0x31,"PAYLOAD_CIPHERTEXT")
MAC                = ControlWord.duplex_r (0x32,"MAC",
    "no_send_len","input_zero","forget",length=12)
AD_EXPLICIT        = ControlWord.plaintext(0x34,"AD_EXPLICIT")
AD_IMPLICIT        = ControlWord.absorb   (0x35,"AD_IMPLICIT")
NONCE_EXPLICIT     = ControlWord.plaintext(0x36,"NONCE_EXPLICIT")
NONCE_IMPLICIT     = ControlWord.absorb   (0x37,"NONCE_IMPLICIT")

################################################################################
# Change of spec, flow control, etc.
#
# COMPRESS: Erase all of the state except for the capacity-key.  This is useful
#     for memory reduction on deeply embedded systems, and for rollback
#     protection.
#
# RESPEC_INFO: For protocols which need very high speed, it may be useful to
#     change ciphers or reduce the number of rounds.  This call sets the info,
#     and then RESPEC runs F, forgets state, and sets the new parameters.
# RESPEC: finalize a respec.
#
# FORK: Prepare to make multiple copies of the state.  For example, the ordinary
#     STROBE lite modes are half-duplex.  To make them full-duplex, fork them.
#
# INSTANCE: Following FORK, specify the data for this fork of the stream.
#     Forgets state to prevent a compromise from recovering the other streams.
#
# ACKNOWLEDGE: In asynchronous protocols, acknowledge receipt of some message
#     sent by the partner.
################################################################################
COMPRESS     = ControlWord.absorb_r (0x40,"COMPRESS","forget","implicit",length=0)
RESPEC_INFO  = ControlWord.absorb   (0x41,"RESPEC_INFO")
RESPEC       = ControlWord.absorb_r (0x42,"RESPEC","implicit","forget",length=0)
FORK         = ControlWord.absorb_r (0x43,"FORK","implicit","forget",length=0)
INSTANCE     = ControlWord.absorb_r (0x44,"INSTANCE","implicit","forget")
ACKNOWLEDGE  = ControlWord.plaintext(0x45,"ACKNOWLEDGE")