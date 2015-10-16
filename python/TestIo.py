"""
Toy IO handlers for testing code.
"""
import sys
import socket

class EOF(Exception):
    """
    Exception: we're all out of file.
    """
    def __init__(self, value): self.value = value
    def __str__(self): return repr(self.value)

class BytesIo(object):
    """
    "I/O" from a fixed byte string.
    """
    def __init__(self, input = b""):
        self.output = bytearray()
        self.input = bytearray(input)
    def add_input(self,x): self.input.extend(x)
    def send(self,x): self.output.extend(x)
    def recv(self,n):
        if len(self.input) < n: raise EOF("EOF in BytesIo recv")
        out = self.input[0:n]
        self.input = self.input[n:]
        return out

class FileIo(object):
    """
    I/O from an input and output file.
    """
    def __init__(self,input=sys.stdin,output=sys.stdout):
        self.input = input
        self.output = output
    def send(self,x): self.output.write(x)
    def recv(self,n): return bytearray(self.input.read(n))

class SockIo(object):
    """
    I/O from a socket, with classmethods to make a listening socket.
    
    Includes a verbose flag for debugging purposes.
    """
    def __init__(self,socket,verbose=None):
        self.socket = socket
        self.verbose = verbose
    
    def send(self,x):
        """
        Send bytes down the socket.
        """
        if self.verbose is not None:
            print "%s -->" % self.verbose, " ".join(["%02x"%b for b in x])
        self.socket.send(x)
        
    def recv(self,n):
        """
        Receive exactly n bytes, blocking.
        """
        ret = bytearray(self.socket.recv(n,socket.MSG_WAITALL))
        if self.verbose is not None:
            print "%s <--" % self.verbose, " ".join(["%02x"%b for b in ret])
        return ret
        
    def close(self):
        """
        Close the socket.
        """
        if self.verbose:
            print "%s: close" % self.verbose
        self.socket.close()
        
    @classmethod
    def pair(cls,va=None,vb=None):
        """
        A socket pair for local communication.
        """
        a,b = socket.socketpair()
        return cls(a,va),cls(b,vb)
        
    @classmethod
    def listen(cls,port,verbose=None):
        """
        A single server socket.
        """
        lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        lsock.bind(("127.0.0.1", port))
        lsock.listen(1)
        (csock, address) = lsock.accept()
        return SockIo(csock,verbose)