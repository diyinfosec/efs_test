import subprocess
class efsGen:
	def exec_cmd(self,inp_cmd, blocking_error='Y',decode_output='Y'):
		try:
			#print("value of the input command is ", inp_cmd)
			proc=subprocess.run(inp_cmd,  check=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		except subprocess.CalledProcessError as e:
			if(blocking_error=='Y'):
				print(f'Execution of "{e.cmd}" resulted in error. The exit code is {e.returncode}.')
				print(e.output)
				exit()
			else:
				return([e.output.decode('utf-8')])

		#- proc.stdout will be <class 'str'> if universal_newlines=True
		if(decode_output=='Y'):
			out_l=([x.decode('utf-8') for x in proc.stdout.splitlines()])
		else:
			return(proc.stdout)

		return(out_l)