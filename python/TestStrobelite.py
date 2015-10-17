from Strobelite.Strobelite import StrobeliteProtocol
from Strobelite.ControlWord import *

import threading
from Toy25519 import Toy25519

from TestIo import *

if 0:
    """
    This is for interacting with a C version I wrote, which doesn't
    have the same EC code linked to it so it can't interoperate there.
    """
    sock = SockIo.listen(4444,"Server")
    ctx = StrobeliteProtocol(sock,"toy python",am_client=False)

    v = ctx.recv(VERSION)
    if tuple((x for x in v)) != (0,1):
        raise Exception("Version wasn't 0,1")


    key = b"my key"
    ctx.transact(FIXED_KEY,key)
    
    while 1:
        x = ctx.recv_decrypt()
        print x
        ctx.encrypt_send("I got your message! It was: " + x)
    

if 1:
    c,s = SockIo.pair("Client")

    client = StrobeliteProtocol(c,"toy",am_client=True)
    server = StrobeliteProtocol(s,"toy",am_client=False)

    key = b"my key"
    pt1 = b"Hello world!"
    pt2 = b"And hello to you too!"


    pk,sk = Toy25519.keygen()
    pk2,sk2 = Toy25519.keygen()

    def clientThread(ctx):
        ctx.send(VERSION,[0,1])
        ctx.transact(FIXED_KEY,key)
        ctx.ecdhe(Toy25519,True)
        ctx.sign(Toy25519,sk)
        ctx.verify_sig(Toy25519,pk2)
        ctx.encrypt_send(pt1)
        print ctx.recv_decrypt()
    
    def serverThread(ctx):
        v = ctx.recv(VERSION)
        if tuple((x for x in v)) != (0,1):
            ctx.io.close()
            return None
        ctx.transact(FIXED_KEY,key)
        ctx.ecdhe(Toy25519,False)
        ctx.verify_sig(Toy25519,pk)
        ctx.sign(Toy25519,sk2)
        print ctx.recv_decrypt()
        ctx.encrypt_send(pt2)
    
    cthread = threading.Thread(None,clientThread,None,args=[client])
    sthread = threading.Thread(None,serverThread,None,args=[server])

    cthread.start()
    sthread.start()
    cthread.join(5)
    sthread.join(5)
