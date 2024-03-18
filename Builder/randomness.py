import os, string

def GetRandomBool() :
    result = os.urandom(3)
    r= sum(result) < 381.04
    return r #average

def GetRandomNumber() :
    result = os.urandom(4)
    return int(sum(result))

def GetRandomRange(a, b):
    if a > b:
        a, b = b, a

    range_size = b - a + 1

    num_bits = 0
    while 2 ** num_bits < range_size:
        num_bits += 1

    random_binary = [GetRandomBool() for _ in range(num_bits)]

    random_integer = 0
    for i, bit in enumerate(random_binary):
        random_integer += bit * (2 ** i)

    mapped_value = a + random_integer
    if mapped_value > b : return GetRandomRange(a, b)
    
    return mapped_value

def GetRandomString(l) :
    letters = string.ascii_lowercase
    s = ""
    while len(s) < l :
        r = GetRandomRange(0, len(letters)-1)
        s += letters[r]

    return s