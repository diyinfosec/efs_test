from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import struct
from binascii import unhexlify

#- Ref: https://cryptography.io/en/latest/_modules/
'''
Initially got the error:
AttributeError: 'NoneType' object has no attribute 'load_key_and_certificates_from_pkcs12'
pip uninstall cryptography (cryptography-2.9.2)
pip install cryptography (cryptography-3.1.1)
Ref: https://github.com/conda/conda/issues/6404
'''

from efsGen import efsGen

class efsCryptDecrypt:

	def __init__(self):
		self.gen_obj=efsGen()
		
		
	def encrypt_file(self,inp_file_name_path):
		c=f"cipher /e {inp_file_name_path}"
		r=self.gen_obj.exec_cmd(c)
		return r

	def export_efs_cert_as_pfx(self):
		c=f"PowerShell -NoProfile -ExecutionPolicy Bypass ./cert.ps1"
		print(c)
		h=self.gen_obj.exec_cmd(c)
		print(h)


	#===============================================================
	#- Read the PFX and get the private key 
	#===============================================================
	def read_private_key_from_pfx(self,inp_pfx_name_path,inp_pfx_passwd='.'):
		#- Ref:https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/#pkcs12
		pfx_data=open(inp_pfx_name_path, 'rb').read()

		#- Output will be a Tuple of (private_key, certificate, additional_certificates)
		x=pkcs12.load_key_and_certificates(pfx_data, inp_pfx_passwd, backend=None)

		private_key=x[0]
		certificate=x[1]

		#print(x[0])
		return private_key

	#===============================================================
	#- Use the private key to decrypt the EFEK
	#===============================================================
	def decrypt_efek(self,inp_private_key, inp_efek):
		#efek= b'\xc1\xe4\xe7\xb7\x06\x10d\x97g\x93)\x05n\x0bB\x1bu\xd2\x03F\xda\xdc\xee\x89\x023\x8f\xa3s\x8e\xc4\xaa\x88S\xef\x16\xfb\xcb\x8b\x05\xf5\x90k\xc0\xf2\xe3,F-\xbc!\xdf\xbf\xf0\xfaF\xb2\x11\xf3\x85\xa2~\xe8\xd0\x87\x16\xcea\n\xb1\xeb\xa0\xf4\xe2\xa9X\xf3\xac\xf1gJY\xa3v*\x93]\'\x1a\x89\x01\xf5\x93\x948\xfa"\x8f\x17\xf2\xe8J\x94\xe8\\\xe7Rc\xcbi\xce&\xb1\xf3Y\xa9\x04\x0c\xea%\xf2\xc4Gg*G<g\x80\x1b\x81\x03\x8b\x8e\xe9V\xf8\xf8%\xbe\xda\xaa\xcd\nvn\x02\x1e\x97\x1e"\xfaAzp\xf0_h3\x9a\xb5\xa4\x1f\xe0]*iv\xc9\x89\xcd\xf2\xbd\x1c\xd03@J*\xd9^\x928W\xbd\xc3\x11\xa1\x8eu\xb0h\xc8\x93\xc3/\xb8p\x01\xf8\xb6\xbb\xdc\xfc\x0b\x02\xc4\xc7\x14\x01\xb5:$}e\xfd\xe3\x7f\xcbi\x99pET\xed\xff\xdd\xd6T\'\xb5s\xb3p\x04k\xe0#y\x80\xa6\xe325N\xf0\xact\x8cJ\x96\xe3^K\xce\xc2'
		#- Reverse the EFEK as it will be in little-endian
		efek_reversed=inp_efek[::-1]
		print(efek_reversed)
		print(type(efek_reversed))
		print(len(efek_reversed))

		#- Ref: https://github.com/pyca/cryptography/blob/master/docs/hazmat/primitives/asymmetric/rsa.rst
		#- rsautl module of openssl uses PKCS#1 v1.5 as the default padding scheme. Ref: https://linux.die.net/man/1/rsautl
		efek_decrypted=inp_private_key.decrypt(efek_reversed,padding.PKCS1v15())
		print(efek_decrypted.hex())
		
		#- The decrypted EFEK is the FEK. 
		#- Parse the FEK struct to get the symmetric key
		d={}
		start=0
		d['key_length']=int.from_bytes(efek_decrypted[start:start+4],byteorder='little')
		d['key_entropy']=int.from_bytes(efek_decrypted[start+4:start+8],byteorder='little')
		d['key_algo_id']=int.from_bytes(efek_decrypted[start+8:start+12],byteorder='little')
		if(d['key_algo_id']==0x6610):
			d['key_algo_name']='CALG_AES_256'
		elif(d['key_algo_id']==0x6603):
			d['key_algo_name']='CALG_3DES'
		d['reserved']=int.from_bytes(efek_decrypted[start+12:start+16],byteorder='little')
		d['fek']=efek_decrypted[start+16:start+16+d['key_length']]
		print(d['fek'].hex())

		return d



'''
	# Function to get the Initialization Vector (IV) used by EFS for AES encrypted files. 
	def get_iv_for_block(inp_block_num):
	#{

		block_offset=512*(inp_block_num-1);

		#- NTFS EFS uses a hard-coded IV. 
		#- Ref: https://github.com/nats/ntfsprogs/blob/master/ntfsprogs/ntfsdecrypt.c#L1315
		iv_part1=0x5816657be9161312 + int(block_offset); 
		iv_part2=0x1989adbe44918961 + int(block_offset);

		#- To swap endianness in Python it's easy to use the struct module. 
		#- First you "pack" the IV as a set of little-endian bytes. 
		#- Second, you "unpack" the bytes in the IV as big-endian. So effectively you have converted the endianness!
		le_iv_part1=hex(struct.unpack('>Q',struct.pack("<Q", iv_part1))[0])
		le_iv_part2=hex(struct.unpack('>Q',struct.pack("<Q", iv_part2))[0])


		s=(le_iv_part1 + le_iv_part2).replace('0x','').replace('L','');
		print(s)
		return s
		#int(s,16).to_bytes(16,byteorder='big')

	#}

	#===============================================================================
	#- Use the symmetric key to decrypt the data
	#===============================================================================
	data_file='enc.txt-DATA-128-3.bin'
	iv=b'0000000000000000'

	with open(data_file,'rb') as f:
		encrypted_content=f.read()
		encrypted_content_size=len(encrypted_content)
		num_blocks=encrypted_content_size/512
		print("Iterations needed ", num_blocks)
		
		curr_block=1
		while(curr_block<num_blocks):
			iv=unhexlify(get_iv_for_block(curr_block))
			print(f"IV for block {curr_block} is {iv}")
			cipher = Cipher(algorithms.AES(d['fek']), modes.CBC(iv))
			decryptor = cipher.decryptor()
			print(decryptor.update(encrypted_content) + decryptor.finalize())
			curr_block=curr_block+1
'''
	

	