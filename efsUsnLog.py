from efsGen import efsGen
import csv

class efsUsnLog:

	def __init__(self):
		self.gen_obj=efsGen()

	def get_next_usn_record_id(self,inp_drive_letter):
		nextusn=''
		h=self.gen_obj.exec_cmd(f'fsutil usn queryjournal {inp_drive_letter}:')


		for x in h:
			if(x.startswith('Next Usn')):
				nextusn=x.split(':')[1].strip()
				break
		
		return(nextusn)
			#print(type(line.rstrip()))


	def get_mft_num_from_usn(self,inp_file_name_path):
		#working_dir+file_name
		#- fsutil file queryfileid c:\users\test\documents\sid.bt
		#- File ID is 0x0000000000000000000b00000001c566
		c=f"fsutil file queryfileid {inp_file_name_path}"
		#print(c)

		r=self.gen_obj.exec_cmd(c)[0]
		mft_record_num=int(r.split(' ')[3][-8:],16)
		#print(f'MFT record number of {file_name_path} is {mft_record_num}')
		return mft_record_num
		
	def usn_to_csv(self,inp_drive_letter, inp_start_usn='0', out_csv_file='usn.csv'):
		c=f'fsutil usn readjournal {inp_drive_letter}: startusn={inp_start_usn} csv'
		print(c)
		h=self.gen_obj.exec_cmd(c)
		#print(h)
		counter=0
		
		with open(out_csv_file,"w") as f:
			for x in h:
				counter=counter+1
				if(counter<8):
					continue

				f.write(x+"\n")


	def enrich_usn_csv(self,inp_drive_letter,inp_csv_file, out_csv_file):
		#- General csv ref: https://docs.python.org/3/library/csv.html
		#- Reason for adding "newline" when opening file: https://stackoverflow.com/questions/3191528/csv-in-python-adding-an-extra-carriage-return-on-windows
		with open(inp_csv_file,"r") as r, open(out_csv_file,"w",newline='') as w:
			reader = csv.DictReader(r, delimiter=',')
			runonce=0
			field_names=[]
			writer=None
			#- {'Usn': '25882167944', 'File name': 'AppList', 'File name length': '14', 'Reason #': '0x80000100', 'Reason': 'File create | Close', 'Time stamp': '22-Oct-20 19:07:49', 'File attributes #': '0x00000010', 'File attributes': 'Directory', 'File ID': '000000000000000000120000000cc0d6', 'Parent file ID': '000000000000000000120000000cc0d5', 'Source info #': '0x00000000', 'Source info': '*NONE*', 'Security ID': '0', 'Major version': '3', 'Minor version': '0', 'Record length': '96', 'Number of extents': None, 'Remaining extents': None, 'Extent': None, 'Offset': None, 'Length': None}
			for row in reader:
				if(runonce==0):
					field_names= [x for x in row]
					field_names.insert(1,'Parent Dir')
					field_names.insert(3,'MFT#')
					writer = csv.DictWriter(w,delimiter=',',fieldnames=field_names)
					writer.writeheader()
					runonce=1

				file_id=row['File ID']
				mft_record_num=int(file_id[-8:],16)
				parent_file_id=row['Parent file ID']
				#- Ref: https://fleexlab.blogspot.com/2018/07/finding-path-to-file-mentioned-in-usn.html
				#- fsutil file queryFileNameById C:\ 0x0000000000000000001200000019ab0e
				#- If the file has been deleted then this command returns an "Error"
				cmd=f"fsutil file queryFileNameById {inp_drive_letter}:\\ 0x{parent_file_id}"
				r=self.gen_obj.exec_cmd(cmd,blocking_error='N')[0]
				#print(r)
				if r.startswith('Error'):
					parent_dir_name='<DIR_NAME_UNKNOWN>'
				else:
					parent_dir_name='"'+r.split('?')[1].lstrip('\\')+'"'
				
				row['Parent Dir']=parent_dir_name
				row['MFT#']=mft_record_num

				print(row)
				writer.writerow(row)
				#print(parent_dir_name)
				#exit()
				
				
