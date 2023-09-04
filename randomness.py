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
        a, b = b, a  # Swap a and b if a is greater than b

    range_size = b - a + 1  # Calculate the size of the range

    # Calculate the number of bits required to represent all values in the range
    num_bits = 0
    while 2 ** num_bits < range_size:
        num_bits += 1

    # Generate a random number in binary representation using GetRandomBool()
    random_binary = [GetRandomBool() for _ in range(num_bits)]

    # Convert the binary representation to an integer within the specified range
    random_integer = 0
    for i, bit in enumerate(random_binary):
        random_integer += bit * (2 ** i)

    # Map the generated integer to the desired range [a, b]
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