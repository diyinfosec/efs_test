import re

#- Name of the file/drive letter to scan
#- Input file can be a file (VHD/disk image) or a drive (e.g. input_file_name=r"\\.\e:")
input_file_name="c:\\100MB.vhd"

#- Name of the output file to place the extracted EFS.LOG records
output_file_name="C:\\Users\\test\\Documents\efs.log_output.bin"

#- Open the input file
with open(input_file_name, "rb") as f:
	#- Signature to match G.U.J.R. (in hex)
	match_str=b'\x47\x00\x55\x00\x4A\x00\x52\x00'

	#- Match regex on input file
	matches=re.finditer(match_str,f.read())
	
	#- List to store extracted records
	efs_log_recs=[]
	
	#- Iterate through the matches
	for m in matches:
		#print(m)
		#- Get the start offset
		start_offset=m.start()

		#- Get the length of the EFS log record
		f.seek(start_offset+16)
		record_len=int.from_bytes(f.read(4),byteorder='little')
		#print("Record length is ", hex(record_len))
		
		#- Record length validation. 
		#- 4096 should be reasonable. 
		if record_len>4096:
			continue;
		
		#- Seek to the start of match
		f.seek(start_offset)

		#- Read the EFS log record
		efs_log=f.read(record_len)
		
		#- Append record to output list
		efs_log_recs.append(efs_log)
		

	#print(efs_log_recs)
	
#- Open the output file and write to it
with open(output_file_name,"bw") as f:
	for x in efs_log_recs:
		f.write(x)
