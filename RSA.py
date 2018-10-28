from Crypto.Util import number
from os import urandom
from sys import getrecursionlimit, setrecursionlimit

def mod_exp(x, y, N):
    # This function implements an algorithm to solve modular exponentiation problems more efficiently than simply evaluating the entire exponetial statement and then modding it, since this method does not scale well. Instead, we will first check if power == 0. If yes, we return 1.
    if y == 0:
        return 1

    # Otherwise, we recursively call this function but pass in half the value of power (integer division aka floor division). This results in a stack of recursive calls until power reaches zero, at which point the function returns 1 and begins to unwind.
    z = mod_exp(x, y // 2, N)

    # Each function call then takes the value returned from the recursive layer under it and puts it into a new variable Z. The function then checks if power in the current context is even.
    if y % 2 == 0:
        # If it is, the function returns Z^2 % mod.
        return z ** 2 % N
    else:
        # If it isn't, then the function returns number * z^2 % mod.
        return (x * z ** 2) % N

    # The final layer will return the completed answer, having kept the size of the numbers involved down to a reasonable level by modding the results of every step, rather than just at the end.

def gcd(a, b):
    if a > b:
        oldR = a
        r = b
    else:
        oldR = b
        r = a

    while r != 0:
        quotient = oldR//r
        oldR, r = r, (oldR - quotient * r)

    return oldR

def modular_inverse(a, n):
    x = 0
    newX = 1
    r = n
    newR = a
    while newR != 0:
        quotient = r//newR
        x, newX = newX, (x - quotient * newX)
        r, newR = newR, (r - quotient * newR)
    if r > 1:
        x = None
    if x < 0:
        x = x+n
    return x


e = 65537
primeBitLength = 512
print("e = ", e, " and primes are ", primeBitLength, " bits long")

print("Generating primes...")
primes = []
coprime = False
n = None

while not coprime:
    for i in range(2):
        while True:
            p = number.getPrime(primeBitLength, urandom)
            if (p ^ 0x80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000) < p:
                break

        print("prime ", i, ": ", p)
        primes.append(p)

    coprime = (gcd(e, (primes[0]-1) * (primes[1]-1)) == 1)

n = primes[0]*primes[1]
print("n: ", n)

phiN = (primes[0]-1) * (primes[1]-1)
print("phiN: ", phiN)

d = modular_inverse(e, phiN)
print("d: ", d)

m = 123

#for passing off. Remove to use newly generated primes or original message.
#n = 152669946975312876157480541946922209711638455558698991477678161037415280617875873456678828546970599500327376131320212724765644888095251063428667179866680316636933758489323199235207811366769079942692794611083309433585721742709730236764737165726639400139620882752025270734953410296983534519536493649481276545787
#d = 29424204651497275413051203523682414984935308789873307617903670477189868463377788999058703989758237976847202159310093640638339572783788030916390667087233757530090535937557500818937432057518318923230844567105818744049078457327112686889217486285695805420936640759959269994966014111237265634682662796143284303241
#m = 13945293450201704814553226581615391364450294031656145321247051595402407195776124062089668593622373390496593648357111962503436238929179078384473190096718407
print("m: ", m)
c = mod_exp(m, e, n)
print("c: ", c)

#for passing off. Remove to use newly generated ciphertext. Remove message variable and everything using it below to restore test.
#c = 5631401778148228886497702560490890401589128795337233506670086692469854904819929834575557655174985865368707295882918616611886194676408842616948691849730568856983569325721266505539955580470977072536967946738513208044527388920063892972428944575688226017089130170989487762401326659706740672549156868253129791757
#message = None

determined = False

oldRecursionLimit = getrecursionlimit()


try:
    valid = (mod_exp(c, d, n) == m)
    #message = mod_exp(c, d, n)
except RecursionError:
    print("WARNING: Custom mod_exp function exceeded default recursion limit of ", getrecursionlimit(), " during decryption. Doubling recursion limit and trying again...")
    setrecursionlimit(oldRecursionLimit*2)
    try:
        valid = (mod_exp(c, d, n) == m)
        #message = mod_exp(c, d, n)
    except RecursionError:
        print("WARNING: Custom mod_exp function exceeded double recursion limit of ", getrecursionlimit(), " during decryption. Tripling recursion limit and trying again...")
        setrecursionlimit(oldRecursionLimit*3)
        #message = mod_exp(c, d, n)
        try:
            valid = (mod_exp(c, d, n) == m)
        except RecursionError:
            print("WARNING: Custom mod_exp function has exceeded triple recursion limit of ", getrecursionlimit(), " during decryption. Deeper recursion is too dangerous. Switching to native pow() function for final attempt...")
            valid = (pow(c, d, n) == m)
            #message = pow(c, d, n)

print("Encryption and Decryption Successful: ", valid)
#print("Message: ", message)

if getrecursionlimit() != oldRecursionLimit:
    print("Recursion limit has been reset.")
    setrecursionlimit(oldRecursionLimit)
