from Cryptodome.Random import get_random_bytes

def sign(a,b):
    return get_random_bytes(64)

def verify(a,b,c):
    return True
