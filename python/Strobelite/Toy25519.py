# Toy25519.py - Toy Ed25519 arithmetic library with Strobelite interface.
# This version of the Ed25519 library has the Edwards arithmetic, but no
# hashing implemented for the signatures -- the hashing is done by Strobe lite.
#
# Written in 2011? by Daniel J. Bernstein <djb@cr.yp.to>
#            2013 by Donald Stufft <donald@stufft.io>
#            2013 by Alex Gaynor <alex.gaynor@gmail.com>
#            2013 by Greg Price <price@mit.edu>
#            2015 by Mike Hamburg <mike@shiftleft.org>
#
# To the extent possible under law, the author(s) have dedicated all copyright
# and related and neighboring rights to this software to the public domain
# worldwide. This software is distributed without any warranty.
#
# You should have received a copy of the CC0 Public Domain Dedication along
# with this software. If not, see
# <http://creativecommons.org/publicdomain/zero/1.0/>.

"""
NB: This code is not safe for use with secret keys or secret data.
The only safe use of this code is for verifying signatures on public messages.

Functions for computing the public key of a secret key and for signing
a message are included, namely publickey_unsafe and signature_unsafe,
for testing purposes only.

The root of the problem is that Python's long-integer arithmetic is
not designed for use in cryptography.  Specifically, it may take more
or less time to execute an operation depending on the values of the
inputs, and its memory access patterns may also depend on the inputs.
This opens it to timing and cache side-channel attacks which can
disclose data to an attacker.  We rely on Python's long-integer
arithmetic, so we cannot handle secrets without risking their disclosure.
"""

import hashlib
import operator
import sys
import os


__version__ = "1.0.dev0"


# Useful for very coarse version differentiation.
PY3 = sys.version_info[0] == 3

b = 256
q = 2 ** 255 - 19
l = 2 ** 252 + 27742317777372353535851937790883648493

def inv(z):
    """$= z^{-1} \mod q$, for z != 0"""
    return pow(z,q-2,q)
    

d = -121665 * inv(121666) % q
I = pow(2, (q - 1) // 4, q)

def xrecover(y):
    xx = (y * y - 1) * inv(d * y * y + 1)
    x = pow(xx, (q + 3) // 8, q)

    if (x * x - xx) % q != 0:
        x = (x * I) % q

    if (x * x - xx) % q != 0:
        # It ain't square!
        return None
        
    if x % 2 != 0:
        x = q-x

    return x

def decodeint(s):
    s = bytearray(s)
    return sum(b<<(8*i) for i,b in enumerate(s))

def encodeint(y,bytes=32):
    if y >= 1<<(8*bytes): return None
    return bytearray([
        (y>>(8*i)) & 0xFF
        for i in xrange(bytes)
    ])
    
def decodepoint(s):
    ss = bytearray(s)
    xlo = ss[-1]>>7
    ss[-1] &= 0x7F
    
    y = decodeint(ss)
    if y >= q: return None
    
    x = xrecover(y)
    if x is None: return None
    
    if x & 1 != xlo: x = q - x
    
    P = (x, y, 1, (x*y) % q)
    return P

def encodepoint(P):
    (x, y, z, t) = P
    zi = inv(z)
    x = (x * zi) % q
    y = (y * zi) % q
    ss = encodeint(y)
    ss[-1] ^= 0x80 * (x&1)
    return ss

B = decodepoint(encodeint((4*inv(5)) % q))
ident = (0, 1, 1, 0)

def edwards_neg((x,y,z,t)):
    return (q-x)%q,y,z,(q-t)%q
    
def edwards_add(P, Q):
    # This is formula sequence 'addition-add-2008-hwcd-3' from
    # http://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html
    (x1, y1, z1, t1) = P
    (x2, y2, z2, t2) = Q

    a = (y1-x1)*(y2-x2) % q
    b = (y1+x1)*(y2+x2) % q
    c = t1*2*d*t2 % q
    dd = z1*2*z2 % q
    e = b - a
    f = dd - c
    g = dd + c
    h = b + a
    x3 = e*f
    y3 = g*h
    t3 = e*h
    z3 = f*g

    return (x3 % q, y3 % q, z3 % q, t3 % q)

def edwards_double(P):
    # MH: optimization not worth it.
    return edwards_add(P,P)

def scalarmult(P, e):
    if e == 0:
        return ident
    Q = scalarmult(P, e // 2)
    Q = edwards_double(Q)
    if e & 1:
        Q = edwards_add(Q, P)
    return Q
    
def scalarmult_B(e):
    # MH: optimization not worth it
    return scalarmult(B, e)

class Toy25519:
    challenge_bytes = 32

    @staticmethod
    def get_pubkey(sk):
        return encodepoint(scalarmult_B(decodeint(sk)))

    @staticmethod
    def keygen():
        sk = bytearray(os.urandom((b+7)//8))
        return Toy25519.get_pubkey(sk),sk

    @staticmethod
    def ecdh(pk,sk):
        P = decodepoint(pk)
        if P is None: return None
        return encodepoint(scalarmult(P,8*decodeint(sk)))

    @staticmethod
    def sig_response(secret,esec,challenge):
        sl = decodeint(secret)
        el = decodeint(esec)
        cl = decodeint(challenge)
        response = (sl * cl + el) % l
        return encodeint(response)
    
    @staticmethod
    def sig_verify(pk,eph,challenge,response):
        P = decodepoint(pk)
        if P is None: return False
        MPC = scalarmult(edwards_neg(P),decodeint(challenge))
        BR = scalarmult_B(decodeint(response))
        EE = edwards_add(MPC,BR)
        return encodepoint(EE) == eph

