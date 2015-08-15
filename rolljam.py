# **********************************************************************************
# Wes Calvert, 2015
# **********************************************************************************
# License
# **********************************************************************************
# This program is free software; you can redistribute it 
# and/or modify it under the terms of the GNU General    
# Public License as published by the Free Software       
# Foundation; either version 2 of the License, or        
# (at your option) any later version.                    
#                                                        
# This program is distributed in the hope that it will   
# be useful, but WITHOUT ANY WARRANTY; without even the  
# implied warranty of MERCHANTABILITY or FITNESS FOR A   
# PARTICULAR PURPOSE.  See the GNU General Public        
# License for more details.                              
#                                                        
# You should have received a copy of the GNU General    
# Public License along with this program; if not, write 
# to the Free Software Foundation, Inc.,                
# 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
#                                                        
# Licence can be viewed at                               
# http:#www.fsf.org/licenses/gpl.txt                    
#
# Please maintain this license information along with authorship
# and copyright notices in any redistribution of this code
# **********************************************************************************

import socket
from Crypto.Cipher import AES
from Crypto import Random
import thread
import time
from multiprocessing import Process
from hashlib import sha1

def OTP(salt, n=0, digits=8):
    while True:
        hash = sha1(str(salt) + repr(n)).hexdigest()
        yield hash[-digits:]
        n += 1

class Server(object):

	key = "123456789ABCDEFG" #None
	mode = AES.MODE_CFB
	clients = []

	def __init__(self, address, port):
		self.address = address
		self.port = port
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.socket.bind((self.address, self.port))
		self.socket.listen(500)

	def serve(self):
		while True:
			clientsock, address = self.socket.accept()
			thread.start_new_thread(self.handler, (clientsock, address))

	def handler(self, clientsock, address):
		while True:
			temp = clientsock.recv(100)
			if self.key is not None:
				iv = temp[:16]
				data = temp[16:]
				try:
					decryptor = AES.new(self.key, self.mode, IV=iv)
				except ValueError:
					# After the tests are finished running, I'm getting "IV must be 16 bytes".
					# There should not be any more data received though, so I don't know what is going on.
					return
				self.data = decryptor.decrypt(data)
			else:
				self.data = temp

			# Remove extra spaces and break message into chunks.
			self.data = self.data.strip()
			received_uid = self.data[:7]
			received_code = self.data[7:-4]
			message = self.data[-4:]
			known_client = False
			for client in self.clients:
				if client.uid == received_uid:
					known_client = True
					if received_code == client.last_code:
						print "Code Replayed! Client: {0} with received code: {1}".format(client.uid, client.last_code)
						break
					if received_code in client.invalid_codes:
						print "Possible Rolljam! Rejecting message from client {0} with code {1}".format(client.uid, client.last_code)
						break
					loops = 0
					client.next_code = client.generator.next()
					while received_code != client.next_code:
						loops += 1
						client.invalid_codes.append(client.next_code)
						client.next_code = client.generator.next()
					client.last_code = client.next_code
					print "Code accepted after {0} retries. Messsage: '{1}' from client '{2}' with received code: {3}, generated code: {4}".format(
							loops, message, received_uid, received_code, client.last_code)
			if not known_client:
				print "Unknown UID detected: {0}".format(received_uid)

	def SetEncryptionKey(self, key):
		if len(key) != 16:
			raise Exception("Key must be exactly 16 bytes!")
		self.key = key

class Client(object):

	key = "123456789ABCDEFG" #None
	mode = AES.MODE_CFB

	def __init__(self, address, port, uid, seed):
		self.address = address
		self.port = port
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.socket.connect((self.address, self.port))
		self.uid = uid
		self.seed = seed
		self.generator = OTP(salt=seed)
		self.last_code = None
		self.next_code = self.generator.next()
		# List of invalid codes is located in the client object for simulation purposes only.
		# In the real world, the server device would maintain this list for each client.
		self.invalid_codes = []

	def send(self, buffer_in, transmit=True):	
		buffer = "{}{}{}".format(self.uid, self.generator.next(), buffer_in)
		clear_text = buffer
		if self.key is not None:
			while (len(buffer)+16) % 16 != 0:
				buffer += " "
			iv = Random.new().read(16)
			encryptor = AES.new(self.key, self.mode, IV=iv)
			buffer = iv + encryptor.encrypt(buffer)
		if transmit:
			self.socket.sendall(buffer)
		return buffer, clear_text # return the encrypted and clear text data for use in tests

# This is a helper method to run the server object in another process.
def run_server(server):
	for i in range(0,10):
		uid = "device%d" % i
		c = Client("localhost",10000,uid,1234)
		server.clients.append(c)
	try:
		server.serve()
	except KeyboardInterrupt:
		print "Shutting down..."

# Simulate a few messages which were not received by the server.
# The server should increment the rolling code twice when it receives the last message.
def basic_test():
	print "Beginning basic test..."
	c = Client("localhost",10000,"device0","1234")
	c.send("LOCK")
	c.send("UNLK", transmit=False)
	c.send("UNLK", transmit=False)
	c.send("UNLK")
	time.sleep(1)
	print "Basic test finished.\n"

# "Naive" replay attack - just send the same encrypted data again.
def naive_replay():
	print "Beginning naive replay..."
	victim = Client("localhost",10000,"device1","1234")
	attacker = Client("localhost",10000,None,None)
	encrypted, clear = victim.send("UNLK")
	attacker.socket.sendall(encrypted)
	time.sleep(1)
	print "Naive replay finished.\n\n"

# Rolljam attack - steal key and attempt to use it later.
def rolljam():
	print "Beginning rolljam..."
	victim = Client("localhost",10000,"device2","1234")
	attacker = Client("localhost",10000,None,None)
	victim.send("LOCK")
	encrypted, clear = victim.send("UNLK", transmit=False)
	victim.send("UNLK")
	attacker.socket.sendall(encrypted)
	time.sleep(1)
	print "Rolljam finished.\n\n"

def main():
	s = Server("localhost",10000)
	p = Process(target=run_server, args=(s,))
	p.start()
	print "Server started, waiting a bit..."
	time.sleep(1)
	basic_test()
	naive_replay()
	rolljam()
	try:
		p.join()
	except KeyboardInterrupt:
		pass

if __name__ == "__main__":
	main()