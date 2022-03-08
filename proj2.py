#Hannah Heath
#Project 2 - CRYPTOSYSTEM

import random 
import numpy 


#Function to get q
def getRand_Q(bitsize):
	while True:
		num = random.randint(2**(bitsize-1), 2**(bitsize))
		if millerRabin(num) and q_mod_12_5(num):
			return num

#Function to get p
def getRand_P(bitsize, q):
	#call function to check that possible prime is larger that 2^32 and if not "+ 0x10000000000000000000000000000000" - needed since randint range?
	num = 2 * q + 1
#	if num < 42949967296 :
#		num = num + 0x10000000000000000000000000000000

	if millerRabin(num):
		return num
	else:
		return 0


#Function to check q for 2 to be the generator
def q_mod_12_5(q):
	if q % 12 == 5:
		return True
	else:
		return False


#Functions for Miller-Rabin Primality Test
#Sourced from: https://jeremykun.com/2013/06/16/miller-rabin-primality-test/
def decompose(n):
   exponentOfTwo = 0
 
   while n % 2 == 0:
      n = n/2
      exponentOfTwo += 1
 
   return exponentOfTwo, n
 
def isWitness(possibleWitness, n, exponent, remainder):
   possibleWitness = pow(possibleWitness, remainder, n)
 
   if possibleWitness == 1 or possibleWitness == n - 1:
      return False
 
   for _ in range(exponent):
      possibleWitness = pow(possibleWitness, 2, n)
 
      if possibleWitness == n - 1:
         return False
 
   return True
 
def millerRabin(n, accuracy=16):
   if n == 2 or n == 3: return True
   if n < 2: return False
 
   exponent, remainder = decompose(n - 1)
   remainder = int(remainder)

   for _ in range(accuracy):
      possibleWitness = random.randint(2, n - 2)
      if isWitness(possibleWitness, n, exponent, remainder):
         return False
 
   return True


#Function to write public key to file
def writePubkey(p, g, e2):
	f = open("pubkey.txt", "w")
	f.write(str(p))
	f.write(" ")
	f.write(str(g))
	f.write(" ")
	f.write(str(e2))
	f.close()



#Function to write private key to file
def writePrikey(p, g, d):
	f = open("prikey.txt", "w")
	f.write(str(p))
	f.write(" ")
	f.write(str(g))
	f.write(" ")
	f.write(str(d))
	f.close()



#Main function for key generation
def keyGeneration():
	p = 0

	while p == 0 :
		q = getRand_Q(32)
		p = getRand_P(33, q)

	d = random.randint(1, p - 2)
	g = 2

	e2 = pow(g, d, p)

	print("Public key : ", p, g, e2)
	print("Private key: ", p, g, d)
	writePubkey(p, g, e2)
	writePrikey(p, g, d)
	return p, g, e2, d	

	

#Function to read public key
def readPubkey():
	f = open("pubkey.txt", "r")
	t1 = f.readline()
	t2 = t1.split(" ")	
	t3 = [int(v) for v in t2]
	p, g, e2 = t3
	f.close()
	print("Public key: ", p, g, e2)
	return p, g, e2



#Function to read in plaintext from ptext.txt 
def readPtxt():
	f = open("ptext.txt", "r")
	M = f.read()
	f.close()
	M.strip('\n')	
	return M
	


#Function to divide M to m
def divideM(M):
	i = 0
	length = len(M) 
	size = length/4
	num_dec = str(size-int(size))[1:]
	size = int(size)
	if num_dec != '.0' and num_dec != '.25':
		size += 1	
		length -= 1
	else:
		size += 0
	m = []
	j, u, v, w = 0, 1, 2, 3
	
	for i in range(size):

		if j == length - 1:
			m.append(str(M[j]))
			return m, length
		if u == length - 1:
			m.append(str(M[j]) + str(M[u]))
			return m, length
		if v == length - 1:
			m.append(str(M[j]) + str(M[u])+ str(M[v]))
			return m, length

		m.append(str(M[j]) + str(M[u]) + str(M[v]) + str(M[w]))
		j += 4
		u += 4
		v += 4
		w += 4

	return m, length
			


#Function to convert ascii to hex
def convertHex(m, length):
	newM = []
	newEle = ""
	size = len(m)
	x = 0

	for i in range(size): 
		j = 0
		while j < 4 and x < length: 
			ele = m[i]
			ele2 = ele[j]
			int1 = ord(ele2)
			temp = hex(int1).lstrip("0x").rstrip("L")
			newEle += temp
			j += 1
			x += 1
			if j == 4 or x == length:
				newM.append(newEle)
				newEle = ""
	return newM



#Function to convert hex to base 10
def convertInt(m):   
	size = len(m)

	for i in range(size):
		temp = int(m[i], 16)
		m[i] = temp
	
	return m


#Function for C1 and C2
def C1C2(g, mi, e2, p):
	if mi < p :
		k = random.randint(1, p-1)
		C1 = pow(g, k, p)
		C2 = pow(e2, k, p)
		temp = mi % p
		C2 = (C2 * temp) % p
		return C1, C2


#Function to output 1st ciphertext to overwrite and start ctext.txt
def writeCipher1(C1, C2):
	f = open("ctext.txt", "w")
	f.write(str(C1))
	f.write(" ")
	f.write(str(C2))
	f.write(" ")
	f.close()


#Function to append ciphertext to ctext.txt file
def writeCipher2(C1, C2):
	f = open("ctext.txt", "a")
	f.write(str(C1))
	f.write(" ")
	f.write(str(C2))
	f.write(" ")
	f.close()



#Main function for encryption
def Encryption(): 
	p, g, e2 = readPubkey()
	M = readPtxt()
	m, length = divideM(M)
	m = convertHex(m, length)
	m = convertInt(m)
	size = len(m)

	for i in range(size):
		C1, C2 = C1C2(g, m[i], e2, p)
		if i == 0:
			writeCipher1(C1, C2)
		else:
			writeCipher2(C1, C2)



#Function to read in private key from pritext.txt
def readPrikey():
	f = open("prikey.txt", "r")
	t1 = f.readline()
	t2 = t1.split(" ")	
	t3 = [int(v) for v in t2]
	p, g, d = t3
	f.close()
	return p, g, d 



#Function to read in ciphertext from ctext.txt
def readCipher():
	f = open("ctext.txt", "r")
	c = f.read()
	f.close()
	return c



#Function to divide the cipher read in and convert to int
def divideCipher(c):
	c = c.split()

	for i in range(len(c)):
		c[i] = int(c[i])
	return c



#Function to calculate decryption
def decryptCalc(c, p, d):
	size = len(c)
	size = size/2
	size = int(size)
	message = []
	j = 0
 		
	for i in range(size):
		t1 = p - 1 - d
		t2 = pow(c[j], t1, p)
		j += 1
		t3 = c[j] % p
		m = (t2 * t3) % p 
		j += 1
		message.append(m)

	return message



#Function to convert int to hex
def intHex(m):
	size = len(m)

	for i in range(size):
		m[i] = hex(m[i]).lstrip("0x")

	return m




#Function to convert hex to ascii
#Sourced from: https://www.kite.com/python/answers/how-to-convert-a-string-from-hex-to-ascii-in-python
def hexAscii(m):
	size = len(m)

	for i in range(size):
		bytes_object = bytes.fromhex(m[i])
		m[i] = bytes_object.decode("ASCII")
	return m



#Function to write decrypted message to dtext.txt
def writeDecrypt(m):
	size = len(m)
	f = open("dtext.txt", "w")

	for i in range(size):
		m[i] = str(m[i])
		f.write(m[i])

	f.close()



#Main function for decryption
def Decryption():
	p, g, d = readPrikey()
	print("Private key: ", p, g, d)
	c = readCipher()
	c = divideCipher(c)
	m = decryptCalc(c, p, d)
	m = intHex(m)
	m = hexAscii(m)
	writeDecrypt(m)

	decrypted = ""
	print("Decryption: ", decrypted.join(m))


#Main menu to start process
while True:
	print("\n 1. Key Generation", "\n", "2. Encryption", "\n", "3. Decryption", "\n", "4. Exit\n")
	val = input("Pick an option: ")

	if val == "1":
		print("\n")
		p, g, e2, d = keyGeneration()
	elif val == "2":
		print("\n")
		Encryption()
		ctext = readCipher()
		print("Ciphertext: ", ctext)
		print("\n")
	elif val == "3":
		print("\n")
		Decryption()
		print("\n")
	else:
		break




