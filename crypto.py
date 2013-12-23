import sys
import os

import base64
import itertools

def main():

#	step1()
#	step2()
#	step3()
#	step4()
#	step5()
#	step6()
    cryptic()

def step6():
	f = open("repeatingXOR.txt", "r")
	buf = ""
	
	for line in f:
		line = line.strip("\n")
		buf += line
	keysize_range = range(2, 40)
	s1 = "this is a test"
	s2 = "wokka wokka!!!"
	print hamming(s1, s2)
	print hamming1(s1, s2)
	print hamdist(s1, s2)
	#for keysize in keysize_range:


def hamdist(str1, str2):
	"""Count the # of differences between equal length strings str1 and str2"""

	diffs = 0
	for ch1, ch2 in zip(str1, str2):
		if ch1 != ch2:
			diffs += 1
	return diffs


def hamming(s1, s2):
	assert(len(s1) == len(s2))
	total = 0
	for i in range(0, len(s1)):
		diff = ord(s1[i]) - ord(s2[i])
		if diff < 0:
			diff = -diff
		total += diff
	return total


def hamming1(str1, str2):
	return sum(itertools.imap(str.__ne__, str1, str2))


def step5():
	s = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	c = XOR(s, "ICE")
	print bytes2hex(c)
	print "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"


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
			results.append(res)
		else:
			skip = 0
	return results



def step3():
	s = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	bs = hex2bytes(s)
	results = singleCharXOR(bs)
	for ret in returnPlausible(results):
		print ret

def cryptic():
    s = "sfpns prquc ejdax cgbmn uoicw llhze abqdw tkcqm iarvj nymrj gutmz"
    results = singleCharXOR(s)
    for ret in results: #returnPlausible(s):
        print ret

def returnPlausible(strings):
	results = []
	for string in strings:
		score = 0
		for c in string:
			if ord(c) < 65 or ord(c) > 91:
				if ord(c) < 97 or ord(c) > 122:
					if ord(c) < 47 or ord(c) > 57:
						if ord(c) != 32:
							score += 1
		if score < (.15 * len(string)):
			 results.append(string)
	return results


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


def XOR(string, key):
	res = ""
	for i in range(0, len(string)):
		res += chr(ord(string[i]) ^ ord(key[i % len(key)]))
	return res

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


def hex2bytes(string):
	return string.decode('hex')

def bytes2hex(bytestring):
	return bytestring.encode('hex')

def bytes2b64(bytestring):
	return base64.b64encode(bytestring)

def b642bytes(base64string):
	return base64.b64decode(base64string)



if __name__ == "__main__":
	main()


