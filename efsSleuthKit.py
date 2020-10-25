from efsGen import efsGen

class efsSleuthKit:

	def __init__(self):
		self.gen_obj=efsGen()
		
		
	def get_file_attributes(self, inp_drive_letter, inp_mft_record_num):
		out_attr_l=[]
		c=f"istat \\\\.\\{inp_drive_letter}: {inp_mft_record_num}" 
		r=self.gen_obj.exec_cmd(c)

		for line in r:
			if line.startswith('Type:'):
				attr_str=line.split(':')[1].replace(' Name','').strip().replace('$','').replace('(','').replace(')','') #- Should give STANDARD_INFORMATION 16-0
				out_attr_l.append(attr_str)

		return out_attr_l
		
		
			
	def dump_file_attribute(self,inp_drive_letter, inp_attr_str):
		out_attr_l=[]
		c=f"icat \\\\.\\{inp_drive_letter}: {inp_attr_str}" 
		r=self.gen_obj.exec_cmd(c,decode_output='N')

		return r