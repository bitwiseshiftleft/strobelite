import Keccak
from ControlWord import *
import base64
import threading

class KeccakF(Keccak.Keccak):
    """
    Wrapper for Keccak-F which acts as a function and has a cute __repr__.
    
    This library uses the official Keccak-F implementation, even though
    we do not use need of the Keccak source code (padding, debug modes, etc).
    A practical implementation would probably reimplement Keccak-F only.
    """
    def __init__(self,bits=1600): Keccak.Keccak.__init__(self,bits)
    def __repr__(self): return "%s(%d)" % (self.__class__.__name__, self.b)
    def __str__(self): return repr(self)
    def nbytes(self): return self.b // 8
    
    def __call__(self, bytes):
        """
        Run Keccak-F itself on a byte sequence.  This wraps the library's
        implementation, which takes a 5x5 array of words.
        """
        wl = self.nbytes() // 25
        a = [ [ sum(( bytes[(i*5+j)*wl+o]<<(8*o)
                      for o in xrange(wl)))
                for i in xrange(5)]
              for j in xrange(5)]
        a = self.KeccakF(a)
        b = bytearray(( a[j][i]>>(8*o) & 0xFF
                        for i in xrange(5)
                        for j in xrange(5)
                        for o in xrange(wl) ))
        return b


class Strobelite(object):
    """
    STROBE lite protocol framework
    """
    version = "v0.1"
    EXCEEDED_RATE = 2
    
    def __init__(self,proto,am_client=False,F=None,rate=None,raise_if_fail=True,copyFrom=None):
        if copyFrom is not None:
            self.F = copyFrom.F
            self.rate = copyFrom.rate
            self.proto = copyFrom.proto
            self.off = copyFrom.off
            self.noparse = copyFrom.noparse # EXT
            self.am_client = copyFrom.am_client
            self.st = bytearray(copyFrom.st)
            self.raise_if_fail = copyFrom.raise_if_fail
        
        else:
            if F is None: F = KeccakF(800)
            if rate is None: rate = F.nbytes() - 32
            self.F = F
            self.rate = rate
            self.proto = proto
            self.off = 0
            self.noparse = False
            self.am_client = am_client
            self.init(proto)
            self.raise_if_fail = raise_if_fail
    
    def copy(self):
        return Strobelite(proto=self.proto,copyFrom=self)

    def init(self,proto):
        """
        The initialization routine sets up the state in a way that is
        unique to this Strobelite protocol.  Unlike SHA-3, the protocol
        and rate are distinguished up front in the first call to the
        F-function.
        """
        self.st = bytearray("\x00" * self.F.nbytes())
        
        # Distinguish the version
        aString = "STROBE lite " + self.__class__.version
        self.st[-len(aString):] = aString
        
        # Distinguish the rate up front
        self.st[self.rate+1] = "\x01"
        
        # Distinguish the protocol
        self.operate(INIT,proto)
    
    def _runF(self,pad):
        """
        Absorb a pad byte and run F.
        """
        self.st[self.off] ^= pad
        self.st = self.F(self.st)
        self.off = 0
    
    def _duplex(self,op,data):
        """
        Duplexing sponge construction.
        """
        out = []
        for byte in bytearray(data):
            if self.off == self.rate:
                self._runF(Strobelite.EXCEEDED_RATE)
            
            if op in ("duplex","duplex_r"): out.append(self.st[self.off] ^ byte)
            elif op in ("absorb","absorb_r"): out.append(byte)
            
            if op in ("duplex_r","absorb_r"): self.st[self.off] = byte
            else: self.st[self.off] ^= byte
            
            self.off += 1
            
        return bytearray(out)

    def fail(self,why,your_fault=False):
        """
        Fail by returning None or by throwing an exception.
        If your_fault, it is the application's fault (eg for
        trying to send a control word which is marked as
        implicit) and an exception will be thrown regardless
        of raise_if_fail.
        """
        if self.raise_if_fail or your_fault:
            raise StrobeliteError(why)
        else: return None
        
    def operate(self,cw,data=None,receive=False):
        """
        Main operation.  Apply the control word cw, input the given data,
        and return the result.  If receive, then reverse the operation.
        """
        if data is None:
            if cw.length is not None and "input_zero" in cw.flags:
                data = cw.length
            else:
                return self.fail("Need to call send() with data")
        
        if "input_zero" in cw.flags and not receive:
            # input is a length
            data = bytearray("\x00"*data)
            
        # serialize the control word
        cwb,pad = cw.toBytes(len(data),self.am_client,receive=receive,force_run_f=self.noparse)
        
        # extension: possibly force the next operation to run f
        self.noparse = cw.is_noparse()
            
        # reverse-absorb the control word
        self._duplex("absorb_r",cwb)
        
        # run F if necessary
        if pad: self._runF(pad)
        
        # apply the duplex operation
        op = cw.op
        if receive:
            if op == "duplex": op = "duplex_r"
            elif op == "duplex_r": op = "duplex"
        ret = self._duplex(op,data)
        
        if "input_zero" in cw.flags and receive:
            orr = 0
            for byte in ret: orr |= ret[0]
            if orr: return self.fail("input_zero failed")
        
        # erase state to forget data
        if "forget" in cw.flags:
            assert self.rate - 4 - self.off >= 32
            self._duplex("absorb_r",b'\x00'*(self.rate - 4 - self.off))
            
        return cwb,ret

class StrobeliteProtocol(Strobelite):
    """
    A handler which uses STROBE lite to operate on an i/o stream.
    The stream must implement send and recv.
    """
    def __init__(self,io,*args,**kwargs):
        super(StrobeliteProtocol,self).__init__(*args,**kwargs)
        self.io = io

    def send(self,cw,data=None):
        """
        Operate on some data, and send the result to the other party.
        """
        if cw.is_implicit():
            raise StrobeliteError("Trying to send implicit data")
            
        frame,data = self.operate(cw,data)
        frame = bytearray((frame[b] for b in cw.send_bytes()))
        self.io.send(frame+data)
        return True
        
    def _check_frame(self,cw,frame,exact_length=None,min_length=None,max_length=None):
        """
        Check a frame against the given tag.  The idea is that you could expand this
        function to deal with peeking in the case that the protocol defines several
        possible next frames; but as written, it only handles one frame.
        """
        if cw.is_implicit():
            return self.fail("Trying to recv implicit data",True)
        
        # Length checks
        if exact_length is None and cw.length is not None:
            exact_length = cw.length
        if exact_length is not None:
            min_length = max_length = exact_length
        
        if len(frame) != len(cw.send_bytes()):
            return self.fail("Wrong frame length: expected %d, got %d" % (len(cw.send_bytes()),len(frame)))

        if "no_send_tag" not in cw.flags:
            cwb,_ = cw.toBytes(0,self.am_client,receive=True)
            if cwb[1] != frame[0]:
                return self.fail("Received wrong frame type (expected %s ~ %02x, got %02x)"
                    % (str(cw),cwb[1],frame[0]))
            frame = frame[1:]
        
        if "no_send_len" in cw.flags:
            if exact_length is None:
                return self.fail("No exact_length on no_send_len tag")
            return exact_length
        
        length = frame[0] | (frame[1]<<8)
        if (  min_length is not None and length < min_length
           or max_length is not None and length > max_length ):
            return self.fail("Received wrong frame length (got %d instead of %s..%s) for frame %s"
                    % (length,str(min_length),str(max_length),str(cw)))
        
        return length
    
    def implicit(self,cw,data=None):
        """
        Do an implicit operation, i.e. one in which the data is not sent to the other side.
        """
        if not cw.is_implicit():
            raise StrobeliteError("Called implicit, but control word is not implicit")
        return self.operate(cw,data)[1]
    
    def recv(self,cw,frame=None,**kwargs):
        """
        Receive and check the frame header, then receive data.
        Can take min_length,max_length or exact_length kwargs.
        """
        if frame is None: frame = self.io.recv(len(cw.send_bytes()))
        length = self._check_frame(cw,frame,**kwargs)
        data = self.io.recv(length)
        return self.operate(cw,data,receive=True)[1]
    
    def recv_decrypt(self,**kwargs):
        """
        As recv, but decrypt PAYLOAD_CIPHERTEXT and then check a MAC.
        """
        data = self.recv(PAYLOAD_CIPHERTEXT,**kwargs)
        if not self.recv(MAC): return None
        return data
    
    def encrypt_send(self,data):
        """
        As send, but encrypt PAYLOAD_CIPHERTEXT and then send a MAC.
        """
        self.send(PAYLOAD_CIPHERTEXT,data)
        return self.send(MAC)
    
    def ecdhe(self,EC,i_go_first):
        """
        Toy ECDH ephemeral exchange.
        Real protocols will probably take these steps in their header,
        but might send other items such as OVER.
        """
        pub,sec = EC.keygen()
        
        if i_go_first: self.send(DH_EPH,pub)
        
        their_pub = self.recv(DH_EPH,exact_length=len(pub))
        
        if not i_go_first: self.send(DH_EPH,pub)
        
        ret = EC.ecdh(their_pub,sec)
        if ret is None: return self.fail("ECDH failed")

    def sign(self,EC,secret,scheme_data=None,stir_pk=None):
        """
        Signature scheme.  Realistic, except that the bundled
        Toy25519 is nonstandard.
        """
        if scheme_data is not None:
            self.implicit(SIG_SCHEME,scheme_data)
            # TODO: a way to make this explicit maybe?
            
        if stir_pk is not None: self.implicit(SIG_PK, stir_pk)
            
        eph,esec = EC.keygen()
        self.send(SIG_EPH,eph)
        challenge = self.implicit(SIG_CHAL,EC.challenge_bytes)
        response = EC.sig_response(secret,esec,challenge)
        return self.send(SIG_RESP,response)
    
    def verify_sig(self,EC,public,scheme_data=None,stir_pk=False):
        """
        Signature verification.  Realistic, except that the bundled
        Toy25519 is nonstandard.
        """
        if scheme_data is not None:
            self.implicit(SIG_SCHEME,scheme_data)
            
        if stir_pk: self.implicit(SIG_PK, public)
            
        eph = self.recv(SIG_EPH)
        challenge = self.implicit(SIG_CHAL,EC.challenge_bytes)
        response = self.recv(SIG_RESP)
        ok = EC.sig_verify(public,eph,challenge,response)
        if not ok: return self.fail("Signature verify failed")
        return True
