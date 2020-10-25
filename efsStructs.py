class efsStructs:

	def parse_efs_attribute(self, inp_efs_attr):
		#- TODO: Min length should be length of header. 
		#- Max length should be length of the body
		
		efs_attr_len=len(inp_efs_attr)
		d={}
		start=0
		d['attr_len']=int.from_bytes(inp_efs_attr[start:start+4],byteorder='little')
		
		#- Validating length of EFS attribute
		if(efs_attr_len < 75):
			print("$EFS attribute should be at least 75 bytes")
			exit()
		if(efs_attr_len != d['attr_len']):
			print("Length mismatch between header [{d['attr_len']}] and actual EFS body [{inp_efs_attr_len}]")
			exit()
		d['uk_state']=int.from_bytes(inp_efs_attr[start+4:start+8],byteorder='little')
		d['efs_version']=int.from_bytes(inp_efs_attr[start+8:start+12],byteorder='little')
		d['crypto_api_version']=int.from_bytes(inp_efs_attr[start+12:start+16],byteorder='little')
		d['uk_fek_md5']=inp_efs_attr[start+16:start+32].hex()
		d['uk_ddf_md5']=inp_efs_attr[start+32:start+48].hex()
		d['uk_drf_md5']=inp_efs_attr[start+48:start+64].hex()

		d['offset_to_ddf']=(int.from_bytes(inp_efs_attr[start+64:start+68],byteorder='little'))
		d['offset_to_drf']=(int.from_bytes(inp_efs_attr[start+68:start+72],byteorder='little'))
		d['reserved']=(int.from_bytes(inp_efs_attr[start+72:start+76],byteorder='little'))

		print(d)
		#- Process DDF records if they exist
		if(d['offset_to_ddf']!=0):
			d['ddf_records']=self.parse_df_records('DDF',d['offset_to_ddf'], inp_efs_attr)
		#- Process DRF records if they exist
		if(d['offset_to_drf']!=0):
			d['drf_records']=self.parse_df_records('DRF',d['offset_to_drf'], inp_efs_attr)
			
		return d

	def parse_df_records(self,inp_rec_type, inp_offset, inp_efs_attr):
		start=inp_offset
		print("Parsing ", inp_rec_type)
		num_recs=int.from_bytes(inp_efs_attr[start:start+4],byteorder='little')
		print(f"Number of {inp_rec_type} records is {num_recs}")
		
		df_recs=[]
		record_begin=start+4
		
		loop_counter=0
		
		while(num_recs>0):
			df_record={}
			
			loop_counter=loop_counter+1
			#print('loop counter is ', loop_counter)
			
			df_record['length']=int.from_bytes(inp_efs_attr[record_begin:record_begin+4],byteorder='little')
			#print('Length of df_record is ', df_record['length'])
			
			df_record['public_key_offset']=int.from_bytes(inp_efs_attr[record_begin+4:record_begin+8],byteorder='little')
			df_record['efek_size']=int.from_bytes(inp_efs_attr[record_begin+8:record_begin+12],byteorder='little')
			df_record['efek_offset']=int.from_bytes(inp_efs_attr[record_begin+12:record_begin+16],byteorder='little')
			df_record['uk_df1']=int.from_bytes(inp_efs_attr[record_begin+16:record_begin+20],byteorder='little')
			df_record['public_key_details_size']=int.from_bytes(inp_efs_attr[record_begin+20:record_begin+24],byteorder='little')
			df_record['sid_offset']=int.from_bytes(inp_efs_attr[record_begin+24:record_begin+28],byteorder='little')
			df_record['credential_type']=int.from_bytes(inp_efs_attr[record_begin+28:record_begin+32],byteorder='little')
			
			efek_begin=record_begin+df_record['efek_offset']
			efek_end=efek_begin+df_record['efek_size']
			#print('EFEK begins at ',efek_begin)
			df_record['efek']=inp_efs_attr[efek_begin:efek_end]
			#print('EFEK length is ',len(df_record['efek']))
			

			df_record['uk_df2']=int.from_bytes(inp_efs_attr[efek_end: efek_end+2],byteorder='little')
			
			#print(df_record)
			df_recs.append(df_record)
			
			#- Offset to beginning of next DF record, if it exists
			record_begin=record_begin+df_record['length']
			
			#- Decrement number of records
			num_recs=num_recs-1
			
		return(df_recs)
			
	'''
	uint32 df_length <name="Record Length (bytes)", comment="Length of the DDF/DRF record">;
	uint32 publickey_header_offset <name="Offset to Publickey Details (bytes)">; 
	uint32 fek_size <name="Size of Encrypted FEK (bytes)", comment="FEK = File Encryption Key">;
	uint32 fek_offset <name="Offset to Encrypted FEK (bytes)">;
    uint32 unknown1 <hidden=true>;

    // Go to the location of the Public Key Header
    FSeek(startof(this)+publickey_header_offset);
    // Declare the Credential Header variable
    EFS_DF_PUBLICKEY_DETAILS e4 <name="Public Key Details">;

    // Go to the location of the Encrypted FEK
    FSeek(startof(this)+fek_offset);
    // Declare the Encrypted FEK variable
    dynamicField fek(fek_size) <name="Encrypted FEK">;
	'''



'''

file_name='enc.txt-LOGGED_UTILITY_STREAM-256-5.bin'			
#file_name='01-logged_utility_stream.bin'
with open(file_name,'rb') as f:

	s=efsStructs()
	efs_attr_bin=f.read()
	efs_attr_d=s.parse_efs_attribute(efs_attr_bin)
	print(efs_attr_d)
'''