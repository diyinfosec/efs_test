import time
from efsUsnLog import efsUsnLog
from efsStructs import efsStructs
from efsSleuthKit import efsSleuthKit
from efsCryptDecrypt import efsCryptDecrypt

#-----------------------
#- Initial Settings
#-----------------------
drive_letter='c'
working_dir="C:\\Users\\test\\Documents\\"
output_dir="N:\\"
file_name='enc.txt'
file_name_path=working_dir+file_name

usn_obj=efsUsnLog()
efs_obj=efsStructs()
tsk_obj=efsSleuthKit()
crypto_obj=efsCryptDecrypt()

#-----------------------
#- Create a file
#-----------------------
with open(file_name_path,"w") as f:
	#-27 chars
	file_content='This is an encrypted file.\n'*100
	f.write(file_content)
	
print(f"Created file {file_name_path}")

#-----------------------------
#- Get it's MFT record number
#-----------------------------
mft_record_num=usn_obj.get_mft_num_from_usn(file_name_path)
print(f"MFT record number of {file_name_path} is {mft_record_num}")

#-------------------------------------------
#- Get file attributes (before encryption)
#-------------------------------------------
attr_l=tsk_obj.get_file_attributes(drive_letter,mft_record_num)
print("Printing attributeds of file {file_name_path}")
print(attr_l)

#-----------------------
#- Get the next usn
#-----------------------
next_usn=usn_obj.get_next_usn_record_id(drive_letter)
print(f"Record ID of the next USN entry is {next_usn}")

#-----------------------
#- Encrypt the file
#-----------------------
r=crypto_obj.encrypt_file(file_name_path)
print(f"Attempting to encrypt file {file_name_path}")
print("Result of file encryption: ",r)

#-------------------------------------------
#- Get file attributes (after encryption)
#-------------------------------------------
attr_l=tsk_obj.get_file_attributes(drive_letter,mft_record_num)
print("Attributes of the file")
print(attr_l)

#- 'DATA', 'LOGGED_UTILITY_STREAM'
attr_dump_prefix=f"{file_name}"
attr_dump_suffix=".bin"
efs_attr_dump_file=""
for attr in attr_l:
	if attr.startswith('DATA') or attr.startswith('LOGGED_UTILITY_STREAM'):
		#icat \\.\c: 86335-256-5
		x=attr.split(' ')
		attr_id=x[1]
		attr_name=x[0]

		#- enc.txt-LOGGED_UTILITY_STREAM-256-5.bin
		attr_dump_file=f"{attr_dump_prefix}-{attr_name}-{attr_id}{attr_dump_suffix}"
		print(attr_dump_file)
		
		if attr_name=='LOGGED_UTILITY_STREAM':
			efs_attr_dump_file=attr_dump_file

		attr_data=tsk_obj.dump_file_attribute(drive_letter,  f"{mft_record_num}-{attr_id}")

		with open(attr_dump_file,'wb') as f:
			f.write(attr_data)


#---------------------------
#- Get Usn Journal changes
#---------------------------
print("Sleep for 10 seconds, for full list of changes")
#time.sleep(10)
usn_obj.usn_to_csv(drive_letter,next_usn)

#- Enrich the USN output
usn_obj.enrich_usn_csv('c','usn.csv','out.csv')



#-------------------------------
#- Export the certificate/PFX
#-------------------------------
#- TODO: For now this is efs.pfx
crypto_obj.export_efs_cert_as_pfx()


#-------------------------------
#- Get EFS private key
#-------------------------------
pfx_passwd=b'.'
pfx_path=working_dir+'efs.pfx'
private_key_obj=crypto_obj.read_private_key_from_pfx(pfx_path,pfx_passwd)
print(private_key_obj)


'''
TODO:
Extract private and public key from pfx
Parse logged utility stream and get EFEK
Obtain EFS log and tmp files
Decrypt EFEK using private key
Get the FEK
Decrypt with FEK
File create with ADS
Directory encryption
Keys in memory
'''


#-------------------------------
#- Process the $EFS attribute
#-------------------------------		

if efs_attr_dump_file!="":
	with open(efs_attr_dump_file,'rb') as f:
		efs_attr_bin=f.read()
	
	#- Parse logged utility stream
	efs_attr_d=efs_obj.parse_efs_attribute(efs_attr_bin)
	print(efs_attr_d)
	
	#-TODO: Check this, currently handling only the first DDF key 
	efek=efs_attr_d['ddf_records'][0]['efek']
	print(efek.hex())

	#- Get the FEK
	fek_d=crypto_obj.decrypt_efek(private_key_obj, efek)
	print(fek_d)

