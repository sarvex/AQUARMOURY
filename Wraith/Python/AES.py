# Red Team Operator course code template
# payload encryption with AES
# 
# author: reenz0h (twitter: @sektor7net)
# modified by: slaeryan (twitter: @slaeryan)


from Crypto.Cipher import AES
from Crypto import Random
import hashlib
import binascii
import sys
import re


# Add padding to the plaintext
def pad(s):
	return (s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size))


# AES encrypt a plaintext with a key obtained from the passphrase
# Return the ciphertext as a hex string
# Uses default static IV(\x00)
def aes_encrypt(plaintext, key):
	k = hashlib.sha256(key.encode('utf-8')).digest()
	#iv = 16 * '\x00'
	#iv = iv.encode('utf-8')
	iv = Random.new().read(AES.block_size)
	plaintext = pad(plaintext)
	cipher = AES.new(k, AES.MODE_CBC, iv)
	ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
	return binascii.hexlify(ciphertext).decode('utf-8'), binascii.hexlify(iv).decode('utf-8')


if __name__ == "__main__":
	if len(sys.argv) < 2:
		print("Missing file path")
		print("Usage: python AES.py <input file path>")
		sys.exit(0)

	AESKEY = "Passw0rd!" # Change me please!

	try:
		data = binascii.b2a_hex(open(sys.argv[1], "rb").read()).decode()
	except:
		print("Error reading %s" % sys.argv[1])
		sys.exit(0)
		
	plaintext_hex = "".join(re.findall("..", data))

	ciphertext_hex, iv_hex = aes_encrypt(plaintext_hex, AESKEY)

	print("Ciphertext: " + ciphertext_hex + "\n")
	print("Random IV: " + iv_hex + "\n")
	print("Encrypted Payload: " + ciphertext_hex + iv_hex)