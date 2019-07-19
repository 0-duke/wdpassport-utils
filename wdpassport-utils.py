#!/usr/bin/env python3
import sys
import os
import struct
import getpass
from hashlib import sha256
from random import randint
import argparse
import subprocess

try:
	import py_sg
except ImportError as e:
	print("You need to install the \"py_sg\" module.")
	sys.exit(1)

BLOCK_SIZE = 512
HANDSTORESECURITYBLOCK = 1
dev = None

## Print fail message with red leading characters
def fail(str):
	return "\033[91m" + "[!]" + "\033[0m" + " " + str

## Print fail message with green leading characters
def success(str):
	return "\033[92m" + "[*]" + "\033[0m" + " " + str

## Print fail message with blue leading characters
def question(str):
	return "\033[94m" + "[+]" + "\033[0m" + " " + str

def title(str):
	return "\033[93m" + str + "\033[0m"

## Convert an integer to his human-readable secure status
def sec_status_to_str(security_status):
	if security_status == 0x00:
		return "No lock"
	elif security_status == 0x01:
		return "Locked";
	elif security_status == 0x02:
		return "Unlocked";
	elif security_status == 0x06:
		return "Locked, unlock blocked";
	elif security_status == 0x07:
		return "No keys";
	else:
		return "unknown";

## Convert an integer to his human-readable cipher algorithm
def cipher_id_to_str(cipher_id):
	if cipher_id == 0x10:
		return "AES_128_ECB";
	elif cipher_id == 0x12:
		return "AES_128_CBC";
	elif cipher_id == 0x18:
		return "AES_128_XTS";
	elif cipher_id == 0x20:
		return "AES_256_ECB";
	elif cipher_id == 0x22:
		return "AES_256_CBC";
	elif cipher_id == 0x28:
		return "AES_256_XTS";
	elif cipher_id == 0x30:
		return "Full Disk Encryption";
	else:
		return "unknown";

## Transform "cdb" in char[]
def _scsi_pack_cdb(cdb):
	return struct.pack('{0}B'.format(len(cdb)), *cdb)

## Convert int from host byte order to network byte order
def htonl(num):
    return struct.pack('!I', num)

## Convert int from  host byte order to network byte order
def htons(num):
    return struct.pack('!H', num)

## Call the device and get the selected block of Handy Store.
def read_handy_store(page):
	cdb = [0xD8,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x01,0x00]
	i = 2
	for c in htonl(page):
		cdb[i] = c
		i+=1
	data = py_sg.read_as_bin_str(dev, _scsi_pack_cdb(cdb), BLOCK_SIZE)
	return data

## Calculate checksum on the returned data
def hsb_checksum(data):
	c = 0
	for i in range(510):
		c = c + data[i]
	c = c + data[0]  ## Some WD Utils count data[0] twice, some other not ...
	r = (c * -1) & 0xFF
	return hex(r)

## Call the device and get the encryption status.
## The function returns three values:
##
## SecurityStatus: 
##		0x00 => No lock
##		0x01 => Locked
##		0x02 => Unlocked
##		0x06 => Locked, unlock blocked
##		0x07 => No keys
## CurrentChiperID
##		0x10 =>	AES_128_ECB
##		0x12 =>	AES_128_CBC
##		0x18 =>	AES_128_XTS
##		0x20 =>	AES_256_ECB
##		0x22 =>	AES_256_CBC
##		0x28 =>	AES_256_XTS
##		0x30 =>	Full Disk Encryption
## KeyResetEnabler (4 bytes that change every time)
##
def get_encryption_status():
	cdb = [0xC0, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00]
	data = py_sg.read_as_bin_str(dev, _scsi_pack_cdb(cdb), BLOCK_SIZE)
	if data[0] != 0x45:
		print(fail("Wrong encryption status signature %s" % hex(data[0])))
		sys.exit(1)
	##  SecurityStatus, CurrentChiperID, KeyResetEnabler
	return (data[3], data[4], data[8:12])

## Call the device and get the first block of Handy Store.
## The function returns three values:
## 
## Iteration - number of iteration (hashing) in password generation
## Salt - salt used in password generation
## Hint - hint of the password if used. TODO.
def read_handy_store_block1():
	signature = [0x00, 0x01, 0x44, 0x57]
	sector_data = read_handy_store(1)
	## Check if retrieved Checksum is correct
	if hsb_checksum(sector_data) != hex(sector_data[511]):
		print(fail("Wrong HSB1 checksum"))
		sys.exit(1)
	## Check if retrieved Signature is correct
	for i in range(0,4):
		if signature[i] != sector_data[i]:
			print(fail("Wrong HSB1 signature."))
			sys.exit(1);

	iteration = struct.unpack_from("<I",sector_data[8:])
	salt = sector_data[12:20] + bytes([0x00, 0x00])
	hint = sector_data[24:226] + bytes([0x00, 0x00])
	return (iteration[0],salt,hint)

## Perform password hashing with requirements obtained from the device
def mk_password_block(passwd, iteration, salt):
	clean_salt = ""
	for i in range(int(len(salt)/2)):
		if salt[2 * i] == 0x00 and salt[2 * i + 1] == 0x00:
			break
		clean_salt = clean_salt + chr(salt[2 * i])

	password = clean_salt + passwd
	password = password.encode("utf-16")[2:]

	for i in range(iteration):
		password = sha256(password).digest()

	return password

## Unlock the device
def unlock():
	cdb = [0xC1,0xE1,0x00,0x00,0x00,0x00,0x00,0x00,0x28,0x00]
	sec_status, cipher_id, key_reset = get_encryption_status()
	## Device should be in the correct state 
	if (sec_status == 0x00 or sec_status == 0x02):
		print(fail("Your device is already unlocked!"))
		return
	elif (sec_status != 0x01):
		print(fail("Wrong device status!"))
		sys.exit(1)
	if cipher_id == 0x10 or cipher_id == 0x12 or cipher_id == 0x18:
		pwblen = 16;
	elif cipher_id == 0x20 or cipher_id == 0x22 or cipher_id == 0x28:
		pwblen = 32;
	elif cipher_id == 0x30:
		pwblen = 32;
	else:
		print(fail("Unsupported cipher %s" % cipher_id))
		sys.exit(1)
	
	## Get password from user
	print(question("Insert password to Unlock the device"))
	passwd = getpass.getpass()
	
	iteration,salt,hint = read_handy_store_block1()
	
	pwd_hashed = mk_password_block(passwd, iteration, salt)
	pw_block = [0x45,0x00,0x00,0x00,0x00,0x00]
	for c in htons(pwblen):
		pw_block.append(c)

	pwblen = pwblen + 8
	cdb[8] = pwblen

	try:
		## If there aren't exceptions the unlock operation is OK.
		py_sg.write(dev, _scsi_pack_cdb(cdb), _scsi_pack_cdb(pw_block) + pwd_hashed)
		print(success("Device unlocked."))
	except:
		## Wrong password or something bad is happened.
		print(fail("Wrong password."))
		pass

## Change device password
## If the new password is empty the device state change and become "0x00 - No lock" meaning encryption is no more used.
## If the device is unencrypted a user can choose a password and make the whole device encrypted.
## 
## DEVICE HAS TO BE UNLOCKED TO PERFORM THIS OPERATION
##
def change_password():
	cdb = [0xC1, 0xE2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x00]
	sec_status, cipher_id, key_reset = get_encryption_status()
	if (sec_status != 0x02 and sec_status != 0x00):
		print(fail("Device has to be unlocked or without encryption to perform this operation"))
		sys.exit(1)
	if cipher_id == 0x10 or cipher_id == 0x12 or cipher_id == 0x18:
		pwblen = 16;
	elif cipher_id == 0x20 or cipher_id == 0x22 or cipher_id == 0x28:
		pwblen = 32;
	elif cipher_id == 0x30:
		pwblen = 32;
	else:
		print(fail("Unsupported cipher %s" % cipher_id))
		sys.exit(1)

	print(question("Insert the OLD password"))
	old_passwd = getpass.getpass()
	print(question("Insert the NEW password"))
	new_passwd = getpass.getpass()
	print(question("Confirm the NEW password"))
	new_passwd2 = getpass.getpass()
	if new_passwd != new_passwd2:
		print(fail("Password confirmation doesn't match the given password"))
		sys.exit(1)

	## Both passwords shouldn't be empty
	if (len(old_passwd) <= 0 and len(new_passwd) <= 0):
		print(fail("Both passwords shouldn't be empty"))
		sys.exit(1)

	iteration,salt,hint = read_handy_store_block1()
	pw_block = [0x45,0x00,0x00,0x00,0x00,0x00]
	for c in htons(pwblen):
		pw_block.append(ord(c))

	if (len(old_passwd) > 0):
		old_passwd_hashed = mk_password_block(old_passwd, iteration, salt)
		pw_block[3] = pw_block[3] | 0x10
	else:
		old_passwd_hashed = ""
		for i in range(32):
			old_passwd_hashed = old_passwd_hashed + chr(0x00)

	if (len(new_passwd) > 0):
		new_passwd_hashed = mk_password_block(new_passwd, iteration, salt)
		pw_block[3] = pw_block[3] | 0x01
	else:
		new_passwd_hashed = ""
		for i in range(32):
			new_passwd_hashed = new_passwd_hashed + chr(0x00)

	if pw_block[3] & 0x11 == 0x11:
		pw_block[3] = pw_block[3] & 0xEE

	pwblen = 8 + 2 * pwblen
	cdb[8] = pwblen
	try:
		## If exception isn't raised the unlock operation gone ok.
		py_sg.write(dev, _scsi_pack_cdb(cdb), _scsi_pack_cdb(pw_block) + old_passwd_hashed + new_passwd_hashed)
		print(success("Password changed."))
	except:
		## Wrong password or something bad is happened.
		print(fail("Error changing password"))
		pass

## Change the internal key used for encryption, every data on the device would be permanently unaccessible.
## Device forgets even the partition table so you have to make a new one.
def secure_erase(cipher_id = 0):
	cdb = [0xC1, 0xE3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00]
	status, current_cipher_id, key_reset = get_encryption_status()

	if cipher_id == 0:
		cipher_id = current_cipher_id

	pw_block = [0x45,0x00,0x00,0x00,0x30,0x00,0x00,0x00]

	if cipher_id == 0x10 or cipher_id == 0x12 or cipher_id == 0x18:
		pwblen = 16;
		pw_block[3] = 0x01
	elif cipher_id == 0x20 or cipher_id == 0x22 or cipher_id == 0x28:
		pwblen = 32;
		pw_block[3] = 0x01
	elif cipher_id == 0x30:
		pwblen = 32;
	#	pw_block[3] = 0x00
	else:
		print(fail("Unsupported cipher %s" % cipher_id))
		sys.exit(1)

	## Set the actual lenght of pw_block (8 bytes + pwblen pseudorandom data)
	cdb[8] = pwblen + 8
	## Fill pw_block with random data
	for rand_byte in os.urandom(pwblen):
		pw_block.append(ord(rand_byte))

	## key_reset needs to be retrieved immidiatly before the reset request
	#status, current_cipher_id, key_reset = get_encryption_status()
	key_reset = get_encryption_status()[2]
	i = 2
	for c in key_reset:
		cdb[i] = ord(c)
		i += 1

	try:
		py_sg.write(dev, _scsi_pack_cdb(cdb), _scsi_pack_cdb(pw_block))
		print(success("Device erased. You need to create a new partition on the device (Hint: fdisk and mkfs)"))
	except:
		## Something bad is happened.
		print(fail("Something wrong."))
		pass

## Get device info through "lsscsi" command
def get_device_info(device = None):
	if device == None: grep_string = "Passport"
	else: grep_string = device

	## Ex. from the following string 
	## "[23:0:0:0]   disk    WD       My Passport 0820 1012  /dev/sdb"
	## We extract 
	p = subprocess.Popen("lsscsi | grep " + grep_string + " | grep -oP \"\/([a-zA-Z]+)\/([a-zA-Z0-9]+)\"",shell=True,stdout=subprocess.PIPE)
	## /dev/sdb
	complete_path = p.stdout.read().rstrip()
	p = subprocess.Popen("lsscsi | grep " + grep_string + " | grep -oP \"\/([a-zA-Z]+)\/([a-zA-Z0-9]+)\" | cut -d '/' -f 3",shell=True,stdout=subprocess.PIPE)
	## sdb
	relative_path = p.stdout.read().rstrip()
	p = subprocess.Popen("lsscsi -d|grep " + grep_string + "|cut -d ':' -f 1|cut -d '[' -f 2",shell=True,stdout=subprocess.PIPE)
	## 23
	host_number = p.stdout.read().rstrip()
	return (complete_path, relative_path, host_number)

## Enable mount operations 
## Tells the system to scan the "new" (unlocked) device
def enable_mount(device):
	sec_status, cipher_id, key_reset = get_encryption_status()
	## Device should be in the correct state 
	if (sec_status == 0x00 or sec_status == 0x02):
		rp,hn = get_device_info(device)[1:]
		p = subprocess.Popen("echo 1 > /sys/block/" + rp + "/device/delete",shell=True)
		p = subprocess.Popen("echo \"- - -\" > /sys/class/scsi_host/host" + hn + "/scan",shell=True)
		print(success("Now depending on your system you can mount your device or it will be automagically mounted."))
	else:
		print(fail("Device needs to be unlocked in order to mount it."))


## Main function, get parameters and manage operations
def main(argv): 
	global dev
	print(title("WD Passport Ultra linux utility v0.1 by duke"))
	parser = argparse.ArgumentParser()
	parser.add_argument("-s", "--status", required=False, action="store_true", help="Check device status and encryption type")
	parser.add_argument("-u", "--unlock", required=False, action="store_true", help="Unlock")
	parser.add_argument("-m", "--mount", required=False, action="store_true", help="Enable mount point for an unlocked device")
	parser.add_argument("-c", "--change_passwd", required=False, action="store_true", help="Change (or disable) password")
	parser.add_argument("-e", "--erase", required=False, action="store_true", help="Secure erase device")
	parser.add_argument("-d", "--device", dest="device", required=False, help="Force device path (ex. /dev/sdb). Usually you don't need this option.")

	args = parser.parse_args()
	
	if len(sys.argv) == 1:
		args.status = True
	
	if args.device:
		DEVICE = args.device
	else:
		## Get occurrences of "Passport" devices
		p = subprocess.Popen("lsscsi | grep Passport | wc -l",shell=True,stdout=subprocess.PIPE)
		if int(p.stdout.read().rstrip()) > 1:
			print(fail("Multiple occurences of \"My Passport\" detected. You should specify a device manually (with -d option)."))
			sys.exit(1)
		DEVICE = get_device_info()[0]

	try:
		dev = open(DEVICE,"r+b")
	except:
		print(fail("Something wrong opening device \"%s\"" % (DEVICE)))
		sys.exit(1)

	if args.status:
		status, cipher_id, key_reset = get_encryption_status()
		print(success("Device state"))
		print("\tSecurity status: %s" % sec_status_to_str(status))
		print("\tEncryption type: %s" % cipher_id_to_str(cipher_id))
	if args.unlock:
		unlock()
	if args.change_passwd:
		change_password()

	if args.erase:
		print(question("Any data on the device will be lost. Are you sure you want to continue? [y/N]"))
		r = sys.stdin.read(1)
		if r.lower() == 'y':
			secure_erase(0)
		else:
			print(success("Ok. Bye."))

	if args.mount:
		enable_mount(DEVICE)

if __name__ == "__main__":
	main(sys.argv[1:])
