# -*- coding: utf-8 -*-
# The Keccak sponge function, designed by Guido Bertoni, Joan Daemen,
# Michaël Peeters and Gilles Van Assche. For more information, feedback or
# questions, please refer to our website: http://keccak.noekeon.org/
# 
# Implementation by Renaud Bauvin,
# hereby denoted as "the implementer".
# 
# To the extent possible under law, the implementer has waived all copyright
# and related or neighboring rights to the source code in this file.
# http://creativecommons.org/publicdomain/zero/1.0/

import math

class KeccakError(Exception):
    """Class of error used in the Keccak implementation

    Use: raise KeccakError.KeccakError("Text to be displayed")"""

    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)


class Keccak:
    """
    Class implementing the Keccak sponge function
    """
    def __init__(self, b=1600):
        """Constructor:

        b: parameter b, must be 25, 50, 100, 200, 400, 800 or 1600 (default value)"""
        self.setB(b)

    def setB(self,b):
        """Set the value of the parameter b (and thus w,l and nr)

        b: parameter b, must be choosen among [25, 50, 100, 200, 400, 800, 1600]
        """

        if b not in [25, 50, 100, 200, 400, 800, 1600]:
            raise KeccakError.KeccakError('b value not supported - use 25, 50, 100, 200, 400, 800 or 1600')

        # Update all the parameters based on the used value of b
        self.b=b
        self.w=b//25
        self.l=int(math.log(self.w,2))
        self.nr=12+2*self.l

    # Constants

    ## Round constants
    RC=[0x0000000000000001,
        0x0000000000008082,
        0x800000000000808A,
        0x8000000080008000,
        0x000000000000808B,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008A,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000A,
        0x000000008000808B,
        0x800000000000008B,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800A,
        0x800000008000000A,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008]

    ## Rotation offsets
    r=[[0,    36,     3,    41,    18]    ,
       [1,    44,    10,    45,     2]    ,
       [62,    6,    43,    15,    61]    ,
       [28,   55,    25,    21,    56]    ,
       [27,   20,    39,     8,    14]    ]

    ## Generic utility functions

    def rot(self,x,n):
        """Bitwise rotation (to the left) of n bits considering the \
        string of bits is w bits long"""

        n = n%self.w
        return ((x>>(self.w-n))+(x<<n))%(1<<self.w)

    def fromHexStringToLane(self, string):
        """Convert a string of bytes written in hexadecimal to a lane value"""

        #Check that the string has an even number of characters i.e. whole number of bytes
        if len(string)%2!=0:
            raise KeccakError.KeccakError("The provided string does not end with a full byte")

        #Perform the modification
        temp=''
        nrBytes=len(string)//2
        for i in range(nrBytes):
            offset=(nrBytes-i-1)*2
            temp+=string[offset:offset+2]
        return int(temp, 16)

    def fromLaneToHexString(self, lane):
        """Convert a lane value to a string of bytes written in hexadecimal"""

        laneHexBE = (("%%0%dX" % (self.w//4)) % lane)
        #Perform the modification
        temp=''
        nrBytes=len(laneHexBE)//2
        for i in range(nrBytes):
            offset=(nrBytes-i-1)*2
            temp+=laneHexBE[offset:offset+2]
        return temp.upper()

    def printState(self, state, info):
        """Print on screen the state of the sponge function preceded by \
        string info

        state: state of the sponge function
        info: a string of characters used as identifier"""

        print("Current value of state: %s" % (info))
        for y in range(5):
            line=[]
            for x in range(5):
                 line.append(hex(state[x][y]))
            print('\t%s' % line)

    ### Conversion functions String <-> Table (and vice-versa)

    def convertStrToTable(self,string):
        """Convert a string of bytes to its 5×5 matrix representation

        string: string of bytes of hex-coded bytes (e.g. '9A2C...')"""

        #Check that input paramaters
        if self.w%8!= 0:
            raise KeccakError("w is not a multiple of 8")
        if len(string)!=2*(self.b)//8:
            raise KeccakError.KeccakError("string can't be divided in 25 blocks of w bits\
            i.e. string must have exactly b bits")

        #Convert
        output=[[0,0,0,0,0],
                [0,0,0,0,0],
                [0,0,0,0,0],
                [0,0,0,0,0],
                [0,0,0,0,0]]
        for x in range(5):
            for y in range(5):
                offset=2*((5*y+x)*self.w)//8
                output[x][y]=self.fromHexStringToLane(string[offset:offset+(2*self.w//8)])
        return output

    def convertTableToStr(self,table):
        """Convert a 5×5 matrix representation to its string representation"""

        #Check input format
        if self.w%8!= 0:
            raise KeccakError.KeccakError("w is not a multiple of 8")
        if (len(table)!=5) or (False in [len(row)==5 for row in table]):
            raise KeccakError.KeccakError("table must be 5×5")

        #Convert
        output=['']*25
        for x in range(5):
            for y in range(5):
                output[5*y+x]=self.fromLaneToHexString(table[x][y])
        output =''.join(output).upper()
        return output

    def Round(self,A,RCfixed):
        """Perform one round of computation as defined in the Keccak-f permutation

        A: current state (5×5 matrix)
        RCfixed: value of round constant to use (integer)
        """

        #Initialisation of temporary variables
        B=[[0,0,0,0,0],
           [0,0,0,0,0],
           [0,0,0,0,0],
           [0,0,0,0,0],
           [0,0,0,0,0]]
        C= [0,0,0,0,0]
        D= [0,0,0,0,0]

        #Theta step
        for x in range(5):
            C[x] = A[x][0]^A[x][1]^A[x][2]^A[x][3]^A[x][4]

        for x in range(5):
            D[x] = C[(x-1)%5]^self.rot(C[(x+1)%5],1)

        for x in range(5):
            for y in range(5):
                A[x][y] = A[x][y]^D[x]

        #Rho and Pi steps
        for x in range(5):
          for y in range(5):
                B[y][(2*x+3*y)%5] = self.rot(A[x][y], self.r[x][y])

        #Chi step
        for x in range(5):
            for y in range(5):
                A[x][y] = B[x][y]^((~B[(x+1)%5][y]) & B[(x+2)%5][y])

        #Iota step
        A[0][0] = A[0][0]^RCfixed

        return A

    def KeccakF(self,A, verbose=False):
        """Perform Keccak-f function on the state A

        A: 5×5 matrix containing the state
        verbose: a boolean flag activating the printing of intermediate computations
        """

        if verbose:
            self.printState(A,"Before first round")

        for i in range(self.nr):
            #NB: result is truncated to lane size
            A = self.Round(A,self.RC[i]%(1<<self.w))

            if verbose:
                  self.printState(A,"Satus end of round #%d/%d" % (i+1,self.nr))

        return A

    def appendBit(self, M, bit):
        """Append a bit to M

        M: message pair (length in bits, string of hex characters ('9AFC...'))
        bit: 0 or 1
        Example: appendBit([7, '30'],1) returns [8,'B0']
        Example: appendBit([8, '30'],1) returns [9,'3001']
        """
        [my_string_length, my_string]=M
        if my_string_length>(len(my_string)//2*8):
            raise KeccakError.KeccakError("the string is too short to contain the number of bits announced")
        if ((my_string_length%8) == 0):
            my_string = my_string[0:my_string_length//8*2] + "%02X" % bit
            my_string_length = my_string_length + 1
        else:
            nr_bytes_filled = my_string_length//8
            nbr_bits_filled = my_string_length%8
            my_byte = int(my_string[nr_bytes_filled*2:nr_bytes_filled*2+2],16)
            my_byte = my_byte + bit*(2**(nbr_bits_filled))
            my_byte = "%02X" % my_byte
            my_string = my_string[0:nr_bytes_filled*2] + my_byte
            my_string_length = my_string_length + 1
        return [my_string_length, my_string]

    def appendDelimitedSuffix(self, M, suffix):
        """Append a delimited suffix to M

        M: message pair (length in bits, string of hex characters ('9AFC...'))
        suffix: integer coding a string of 0 to 7 bits, from LSB to MSB, delimited by a bit 1 at MSB
        Example: appendDelimitedSuffix([3, '00'], 0x06) returns [5, '10']
        Example: appendDelimitedSuffix([3, '00'], 0x1F) returns [7, '78']
        Example: appendDelimitedSuffix([8, '00'], 0x06) returns [10, '0002']
        Example: appendDelimitedSuffix([8, '00'], 0x1F) returns [12, '000F']
        """
        if (suffix == 0):
            raise KeccakError.KeccakError("the delimited suffix must not be zero")
        while(suffix != 1):
            M = self.appendBit(M, suffix%2)
            suffix = suffix//2
        return M

    def delimitedSuffixInBinary(self, delimitedSuffix):
        binary = ''
        while(delimitedSuffix != 1):
            binary = binary + ('%d' % (delimitedSuffix%2))
            delimitedSuffix = delimitedSuffix//2
        return binary

    ### Padding rule

    def pad10star1(self, M, n):
        """Pad M with the pad10*1 padding rule to reach a length multiple of r bits

        M: message pair (length in bits, string of hex characters ('9AFC...')
        n: length in bits (must be a multiple of 8)
        Example: pad10star1([60, 'BA594E0FB9EBBD03'],8) returns 'BA594E0FB9EBBD93'
        """

        [my_string_length, my_string]=M

        # Check the parameter n
        if n%8!=0:
            raise KeccakError.KeccakError("n must be a multiple of 8")

        # Check the length of the provided string
        if len(my_string)%2!=0:
            raise KeccakError.KeccakError("there must be an even number of digits")
        if my_string_length>(len(my_string)//2*8):
            raise KeccakError.KeccakError("the string is too short to contain the number of bits announced")

        nr_bytes_filled=my_string_length//8
        nbr_bits_filled=my_string_length%8
        l = my_string_length % n
        if ((n-8) <= l <= (n-2)):
            if (nbr_bits_filled == 0):
                my_byte = 0
            else:
                my_byte=int(my_string[nr_bytes_filled*2:nr_bytes_filled*2+2],16)
            my_byte=my_byte+2**(nbr_bits_filled)+2**7
            my_byte="%02X" % my_byte
            my_string=my_string[0:nr_bytes_filled*2]+my_byte
        else:
            if (nbr_bits_filled == 0):
                my_byte = 0
            else:
                my_byte=int(my_string[nr_bytes_filled*2:nr_bytes_filled*2+2],16)
            my_byte=my_byte+2**(nbr_bits_filled)
            my_byte="%02X" % my_byte
            my_string=my_string[0:nr_bytes_filled*2]+my_byte
            while((8*len(my_string)//2)%n < (n-8)):
                my_string=my_string+'00'
            my_string = my_string+'80'

        return my_string

    def Keccak(self,M,r=1024,c=576,suffix=0x01,n=1024,verbose=False):
        """Compute the Keccak[r,c,d] sponge function on message M

        M: message pair (length in bits, string of hex characters ('9AFC...')
        r: bitrate in bits (defautl: 1024)
        c: capacity in bits (default: 576)
        suffix: the delimited suffix to append to all inputs (0x01 means none, 0x06 for SHA3-* and 0x1F for SHAKE*)
        n: length of output in bits (default: 1024),
        verbose: print the details of computations(default:False)
        """

        #Check the inputs
        if (r<0) or (r%8!=0):
            raise KeccakError.KeccakError('r must be a multiple of 8 in this implementation')
        if (n%8!=0):
            raise KeccakError.KeccakError('outputLength must be a multiple of 8')
        self.setB(r+c)

        if verbose:
            print("Create a Keccak[r=%d, c=%d] function with '%s' suffix" % (r,c,self.delimitedSuffixInBinary(suffix)))

        #Compute lane length (in bits)
        w=(r+c)//25

        # Initialisation of state
        S=[[0,0,0,0,0],
           [0,0,0,0,0],
           [0,0,0,0,0],
           [0,0,0,0,0],
           [0,0,0,0,0]]

        # Appending the suffix
        M = self.appendDelimitedSuffix(M, suffix)
        if verbose:
            print("After appending the suffix: ", M)

        #Padding of messages
        P = self.pad10star1(M, r)

        if verbose:
            print("String ready to be absorbed: %s (will be completed by %d x '00')" % (P, c//8))

        #Absorbing phase
        for i in range((len(P)*8//2)//r):
            Pi=self.convertStrToTable(P[i*(2*r//8):(i+1)*(2*r//8)]+'00'*(c//8))

            for y in range(5):
              for x in range(5):
                  S[x][y] = S[x][y]^Pi[x][y]
            S = self.KeccakF(S, verbose)

        if verbose:
            print("Value after absorption : %s" % (self.convertTableToStr(S)))

        #Squeezing phase
        Z = ''
        outputLength = n
        while outputLength>0:
            string=self.convertTableToStr(S)
            Z = Z + string[:r*2//8]
            outputLength -= r
            if outputLength>0:
                S = self.KeccakF(S, verbose)

            # NB: done by block of length r, could have to be cut if outputLength
            #     is not a multiple of r

        if verbose:
            print("Value after squeezing : %s" % (self.convertTableToStr(S)))

        return Z[:2*n//8]
