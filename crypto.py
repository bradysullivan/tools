import sys
import os

import base64
import itertools

def main():
#    step1()
#    step2()
#    step3()
#    step4()
#    step5()
    step6()
#    cryptic()

def step6():
    f = open("repeatingXOR.txt", "r")
    buf = ""
    for line in f:
        line = line.strip("\n")
        buf += line
    buf = b642bytes(buf)
    ks_range = range(2, 41)
    s1 = "this is a test"
    s2 = "wokka wokka!!!"
    s1bits = tobits(s1)
    s2bits = tobits(s2)
    print hamming(s1bits, s2bits)
    smallest = []
    for ks in ks_range:
        b1 = buf[:ks]
        b2 = buf[ks:ks*2]
        h = hamming(tobits(b1), tobits(b2))
        nh = h / float(ks)
        smallest.append((ks, nh))
    smallest.sort(key=lambda tup:tup[1])
    print smallest[0]
    key_size = smallest[0][0]
    buf_chunks = chunks(buf, key_size)
    diff = len(buf_chunks[0]) - len(buf_chunks[-1])
    buf_chunks[-1] += "a" * diff
    print bytes2hex(buf_chunks[0])
    print bytes2hex(buf_chunks[key_size-1])
    key = ""
    blocks = []
    for i in range(0, key_size):
        blocks.append("")
        print i
        print blocks[i]
        for c in buf_chunks:
            print bytes2hex(c)
            blocks[i] += c[i]
        print bytes2hex(blocks[i])
        key += bestSingleCharXOR(blocks[i])
        print key
    print key
    print XOR(buf, key)
        

def chunks(l, n):
    return [l[i:i+n] for i in range(0, len(l), n)]

def hamming(s1, s2):
    assert(len(s1) == len(s2))
    total = 0
    for i in range(0, len(s1)):
        if s1[i] != s2[i]:
            total += 1
    return total

def bestSingleCharXOR(string):
    strings = singleCharXOR(string)
    results = []
    for s in strings:
        results.append((s[0], scorePlaintext(s[1])))
    results.sort(key=lambda tup:tup[1])
    return results[0][0]

def singleCharXOR(string):
    results = []
    ascii_range = range(32,126)
    for i in ascii_range:
        skip = 0
        res = XOR(string, chr(i))
        for j in res:
            a = ord(j)
            if a < 9 or (a > 13 and a < 32) or a > 127:  
                skip = 1
            if not skip:
                results.append((chr(i), res))
            else:
                skip = 0
    return results

def scorePlaintext(string):
    score = 0
    for c in string:
        if ord(c) < 65 or ord(c) > 91:
            if ord(c) < 97 or ord(c) > 122:
                if ord(c) < 47 or ord(c) > 57:
                    if ord(c) != 32:
                        score += 1
    return score

def XOR(string, key):
    res = ""
    for i in range(0, len(string)):
        res += chr(ord(string[i]) ^ ord(key[i % len(key)]))
    return res

def tobits(s):
    result = []
    for c in s:
        bits = bin(ord(c))[2:]
        bits = '00000000'[len(bits):] + bits
        result.extend([int(b) for b in bits])
    return result

def frombits(bits):
    chars = []
    for b in range(len(bits) / 8):
        byte = bits[b*8:(b+1)*8]
        chars.append(chr(int(''.join([str(bit) for bit in byte]), 2)))
    return ''.join(chars)

def hex2bytes(bytestring):
    return string.decode('hex')

def bytes2hex(bytestring):
    return bytestring.encode('hex')

def bytes2b64(bytestring):
    return base64.b64encode(bytestring)

def b642bytes(base64string):
    return base64.b64decode(base64string)


def step1():
    orig_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    print "Original hex string: \t\t" + orig_string
    byte_buf = hex2bytes(orig_string)
    print "Bytes as ascii: \t\t" + byte_buf
    b64 = bytes2b64(byte_buf)
    print "Base64 encoded string: \t\t" + b64
    bytes2 = b642bytes(b64)
    print "Bytes from Base64 string: \t" + bytes2
    final_string = bytes2hex(bytes2)
    print "Hex from bytes: \t\t" + final_string

def step2():
    s1 = "1c0111001f010100061a024b53535009181c"
    s2 = "686974207468652062756c6c277320657965"
    res = "746865206b696420646f6e277420706c6179"
    print s1
    print s2
    print res
    new_res = fixedXOR(hex2bytes(s1), hex2bytes(s2))
    print new_res
    print bytes2hex(new_res)

def step3():
    s = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    bs = hex2bytes(s)
    results = singleCharXOR(bs)
    for ret in returnPlausible(results):
        print ret

def step4():
    f = open("60hex.txt", "r")
    i = 0
    for line in f:
        line = line.strip('\n')
        s = hex2bytes(line)
        res = returnPlausible(singleCharXOR(s))
        if res:
            print "Line " + str(i) + ": " + line
            for plaus in res:
                print "\t" + plaus
        i+= 1

def step5():
    s = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    c = XOR(s, "ICE")
    print bytes2hex(c)
    print "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

if __name__ == "__main__":
    main()


