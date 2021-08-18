from math import ceil, log2
from hashlib import sha512

# Montgomery: X25519
# Twisted Edwards : ED25519

# Definitions of the constants
B = convertMont(5) # Base point on the twisted Edwards curve
p = pow(2,448) - pow(2,224) - 1 # Field prime
q = pow(2,446) - 13818066809895115352007386748515426880336692474882178609894547503885 # Order of base point (prime; q < p; qB = I) with I identity point
d = (39082 / 39081) % p # Twisted Edwards curve constant
ceilLog2P = 448 # |p| = ceil(log2(p))
ceilLog2Q = 446 # |q| = ceil(log2(q))
b = 456 # 8 * ( ceil((|p| + 1)/8) ) (= bitlength for encoded point or integer)

class TwistedEdwardPoint(object):
    def __init__(self, y, s):
        self.y = y # y coordinate
        self.s = s # sign bit

    def __mul__(self, other):
        if isinstance(other, int) or isinstance(other, float):
            result = other*(y+s)
            return TwistedEdwardPoint(result[:-1], result[-1:])

    def __rmul__(self, other):
        return self.__mul__(other)

    def getCoordinates(self):
        x = 'temp' # TODO: find x from b-bits string: https://eprint.iacr.org/2015/677.pdf fin de page 2
        return [x, self.y]

# Applies a curve-specific birational map to convert the u-coordinate of a point
# on the Montgomery curve to the y-coordinate of the equivalent point on the
# twisted Edwards curve
def uToY(u):
    return (1 + u) * pow(1 - u,-1) % p

# Converts a Montgomery u-coordinate to a twisted Edwards point P
def convertMont(u):
    umasked = u % pow(2,ceilLog2P)
    P = TwistedEdwardPoint(uToY(umasked), 0)
    return P

# Converts a Montgomery private key k to a twisted Edwards public key and private key (A, a)
# A: Edwards public key
# a: Edwards private key
def calculateKeyPair(k):
    E = k*B
    A = TwistedEdwardPoint(E.y, 0)
    if E.s == 1:
        a = -k % q
    else:
        a = k % q
    return A, a

def hashi(X, i):
    return sha512(pow(2,b)-1-i + X)

# k: Montgomery private key (integer mod q)
# M: Message to sign (byte sequence)
# Z: 64 bytes secure random data (byte sequence)
# R||s: byte sequence of length 2b bits, where R encodes a point and s encodes an integer modulo q
def xeddsaSign(k, M, Z):
    A, a = calculateKeyPair(k)
    r = hashi(a + M + Z, i) % q
    R = r*B
    h = sha512(R + A + M) % q
    s = r + h*a % q
    return R, s

# The onCurve(P) function returns true if a purported point P satisfies the curve equation.
def onCurve(P):
    x, y = P.getCoordinates()
    xSquared = x**2
    ySquared = y**2
    return xSquared + ySquared == 1 + d*xSquared*ySquared

# u: Montgomery public key (byte sequence of b bits)
# M: Message to verify (byte sequence)
# R||s: Signature to verify (byte sequence of 2b bits)
def xeddsaVerify(u, M, R, s):
    if u >= p or R.y >= pow(2,ceilLog2P) or s >= pow(2,ceilLog2Q):
        return false
    A = convertMont(u)
    if not onCurve(A):
        return false
    h = sha512(R + A + M) % q
    Rcheck = s*B - h*A
    if R == Rcheck:
        return true
    return false
