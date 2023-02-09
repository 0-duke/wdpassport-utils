#!/usr/bin/env python3
import sys
import os
import struct
import getpass
import random
import string
from hashlib import sha256
from random import randint
import argparse
import pyudev

try:
	import py3_sg as py_sg
except ImportError as e:
	print("You need to install the \"py_sg\" module. Try 'pip3 install --user git+https://github.com/crypto-universe/py_sg'.")
	sys.exit(1)

BLOCK_SIZE = 512
HANDSTORESECURITYBLOCK = 1
dev = None
device_name = None

## Print fail message with red leading characters
def fail(str):
	return "\033[91m" + "[!]" + "\033[0m" + " " + str

## Print fail message with green leading characters
def success(str):
	return "\033[92m" + "[*]" + "\033[0m" + " " + str

## Print fail message with blue leading characters
def question(str):
	return "\033[94m" + "[+]" + "\033[0m" + " " + str

## Convert an integer to his human-readable secure status
def sec_status_to_str(security_status):
	if security_status == 0x00:
		return "No lock"
	elif security_status == 0x01:
		return "Locked"
	elif security_status == 0x02:
		return "Unlocked"
	elif security_status == 0x06:
		return "Locked, unlock blocked"
	elif security_status == 0x07:
		return "No keys"
	else:
		return "unknown"

## Convert an integer to his human-readable cipher algorithm
def cipher_id_to_str(cipher_id):
	if cipher_id == 0x10:
		return "AES_128_ECB"
	elif cipher_id == 0x12:
		return "AES_128_CBC"
	elif cipher_id == 0x18:
		return "AES_128_XTS"
	elif cipher_id == 0x20:
		return "AES_256_ECB"
	elif cipher_id == 0x22:
		return "AES_256_CBC"
	elif cipher_id == 0x28:
		return "AES_256_XTS"
	elif cipher_id == 0x30:
		return "Full Disk Encryption"
	else:
		return "Unknown ({})".format(hex(cipher_id))

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

## Call the device and set the selected block of Handy Store.
def write_handy_store(page, data):
	cdb = [0xDA,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x01,0x00]
	i = 2
	for c in htonl(page):
		cdb[i] = c
		i+=1
	py_sg.write(dev, _scsi_pack_cdb(cdb), data)

## Calculate checksum on the returned data
def hsb_checksum(data):
	c = 0
	for i in range(510):
		c = c + data[i]
	c = c + data[0]  ## Some WD Utils count data[0] twice, some other not ...
	r = (c * -1) & 0xFF
	return r

## Call the device and get the encryption status.
## The function returns three values:
##
## SecurityStatus: 
##		0x00 => No lock
##		0x01 => Locked
##		0x02 => Unlocked
##		0x06 => Locked, unlock blocked
##		0x07 => No keys
## CurrentCipherID
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
		print(fail("Wrong encryption status signature: %s." % hex(data[0])))
		sys.exit(1)
	return {
		"Locked": data[3],
		"Cipher": data[4],
		"PasswordLength": struct.unpack('!H', data[6:8])[0],
		"KeyResetEnabler": data[8:12],
	}

## Call the device and get the first block of Handy Store.
## The function returns three values:
## 
## Iteration - number of iteration (hashing) in password generation
## Salt - salt used in password generation
## Hint - hint of the password if used.
def read_handy_store_block1():
	signature = [0x00, 0x01, 0x44, 0x57] # "01WD"
	sector_data = read_handy_store(1)
	## Check if retrieved Checksum is correct
	if hsb_checksum(sector_data) != sector_data[511]:
		print(fail("Wrong HSB1 checksum."))
		sys.exit(1)
	## Check if retrieved Signature is correct. If not,
	# there is no hashing parameter data set.
	for i in range(0,4):
		if signature[i] != sector_data[i]:
			return None

	iteration = struct.unpack_from("<I",sector_data[8:])
	salt = sector_data[12:20]
	hint = sector_data[24:226]
	return (iteration[0], salt, hint)

def write_handy_store_block1(iteration, salt, hint):
	sector_data = [0x00, 0x01, 0x44, 0x57] # "01WD" signature
	sector_data += [0, 0, 0, 0] # reserved
	sector_data += struct.pack("<I", iteration)
	sector_data += salt[0:8]
	sector_data += [0, 0, 0, 0] # reserved
	sector_data += hint[0:202]
	sector_data += [0] * 285
	sector_data += [hsb_checksum(bytes(sector_data))]
	print(sector_data)
	assert len(sector_data) == BLOCK_SIZE
	write_handy_store(1, bytes(sector_data))

## Perform password hashing with requirements obtained from the device
def mk_password_block(passwd, iteration, salt):
	clean_salt = ""
	salt += bytes([0x00, 0x00])
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
	global device_name

	## Device should be in the correct state 
	status = get_encryption_status()
	if (status["Locked"] in (0x00, 0x02)):
		print(fail("Your device is already unlocked!"))
		return
	elif (status["Locked"] != 0x01):
		print(fail("Wrong device status!"))
		sys.exit(1)
	
	## Get password from user
	passwd = getpass.getpass("[wdpassport] password for {}: ".format(device_name))
	
	hash_parameters = read_handy_store_block1()
	if not hash_parameters:
		print(fail("Key hash parameters are not valid."))
		sys.exit(1)
	iteration, salt, hint = hash_parameters
	
	pwd_hashed = mk_password_block(passwd, iteration, salt)
	pw_block = [0x45,0x00,0x00,0x00,0x00,0x00]
	pwblen = status["PasswordLength"]
	for c in htons(pwblen):
		pw_block.append(c)

	pwblen = pwblen + 8
	cdb = [0xC1,0xE1,0x00,0x00,0x00,0x00,0x00,0x00,0x28,0x00]
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
	# Check drive's current status.
	status = get_encryption_status()
	if (status["Locked"] not in (0x00, 0x02)):
		print(fail("Device has to be unlocked or without encryption to perform this operation."))
		sys.exit(1)

	# Get and confirm the current and new password.
	if status["Locked"] == 0x00:
		# The device doesn't have a password.
		old_passwd = ""
	else:
		old_passwd = getpass.getpass("Current password: ")
	new_passwd = getpass.getpass("New password: ")
	new_passwd2 = getpass.getpass("New password (again): ")
	if new_passwd != new_passwd2:
		print(fail("Password didn't match."))
		sys.exit(1)

	## Both passwords shouldn't be empty
	if (len(old_passwd) <= 0 and len(new_passwd) <= 0):
		print(fail("Password can't be empty. The device doesn't yet have a password."))
		sys.exit(1)

	# Construct the command.
	pw_block = [0x45,0x00,0x00,0x00,0x00,0x00]

	# Get the length in bytes of the key for the drive's current cipher
	# and put that length into the command.
	pwblen = status["PasswordLength"]
	pw_block += list(htons(pwblen))

	# For compatibility with the WD encryption tool, use the same
	# hashing mechanism and parameters to turn the user's password
	# input into a key. The parameters are stored in unencrypted data.
	hash_parameters = read_handy_store_block1()
	if hash_parameters is None:
		# No password hashing parameters are stored on the device.
		# Make some up and write them to the device.
		hash_parameters = (
			1000,
			''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(8)).encode("ascii"), # eight-byte salt
			b'wdpassport-utils'.ljust(202)
		)
		write_handy_store_block1(*hash_parameters)
		assert read_handy_store_block1() == hash_parameters
	iteration, salt, hint = hash_parameters

	if (len(old_passwd) > 0):
		old_passwd_hashed = mk_password_block(old_passwd, iteration, salt)
		pw_block[3] = pw_block[3] | 0x10
	else:
		old_passwd_hashed = bytes([0x00]*32)

	if (len(new_passwd) > 0):
		new_passwd_hashed = mk_password_block(new_passwd, iteration, salt)
		pw_block[3] = pw_block[3] | 0x01
	else:
		new_passwd_hashed = bytes([0x00]*32)

	if pw_block[3] & 0x11 == 0x11:
		pw_block[3] = pw_block[3] & 0xEE

	cdb = [0xC1, 0xE2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x00]
	pwblen = 8 + 2 * pwblen
	cdb[8] = pwblen
	try:
		## If exception isn't raised the unlock operation gone ok.
		py_sg.write(dev, _scsi_pack_cdb(cdb), _scsi_pack_cdb(pw_block) + old_passwd_hashed + new_passwd_hashed)
		print(success("Password changed."))
	except:
		## Wrong password or something bad is happened.
		print(fail("Error changing password."))
		pass

## Change the internal key used for encryption, every data on the device would be permanently unaccessible.
## Device forgets even the partition table so you have to make a new one.
def secure_erase():
	cdb = [0xC1, 0xE3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00]
	status = get_encryption_status()

	cipher_id = status["Cipher"]

	pw_block = [0x45,0x00,0x00,0x00,cipher_id,0x00,0x00,0x00]

	# For old ciphers, this code used to set the "combine" flag.
	# pw_block[3] = 0x01

	## Set the actual lenght of pw_block (8 bytes + pwblen pseudorandom data)
	pwblen = status["PasswordLength"]
	cdb[8] = pwblen + 8
	## Fill pw_block with random data
	for rand_byte in os.urandom(pwblen):
		pw_block.append(rand_byte)

	## key_reset needs to be retrieved immidiatly before the reset request
	#status, current_cipher_id, key_reset = get_encryption_status()
	key_reset = status["KeyResetEnabler"]
	i = 2
	for c in key_reset:
		cdb[i] = c
		i += 1

	try:
		py_sg.write(dev, _scsi_pack_cdb(cdb), _scsi_pack_cdb(pw_block))
		print(success("Device erased. You need to create a new partition on the device (Hint: fdisk and mkfs)"))
	except:
		## Something bad is happened.
		print(fail("Something went wrong."))
		pass

## Enable mount operations 
## Tells the system to scan the "new" (unlocked) device
def enable_mount(device):
	status = get_encryption_status()
	## Device should be in the correct state 
	if status["Locked"] not in (0x00, 0x02):
		print(fail("Device needs to be unlocked in order to mount it."))
		return

	scsi_host = device.find_parent(subsystem="scsi", device_type="scsi_host").sys_name

	# Detach(?) the device.
	with open("/sys/block/{}/device/delete".format(device.sys_name), "w") as f:
		f.write("1\n")

	# Scan for devices.
	with open("/sys/class/scsi_host/{}/scan".format(scsi_host), "w") as f:
		f.write("- - -\n")
	print(success("Device re-scanned."))


## Main function, get parameters and manage operations
def main(argv): 
	global dev
	global device_name

	parser = argparse.ArgumentParser()
	parser.add_argument("-u", "--unlock", required=False, action="store_true", help="Unlock")
	parser.add_argument("-m", "--mount", required=False, action="store_true", help="Enable mount point for an unlocked device")
	parser.add_argument("-c", "--change_passwd", required=False, action="store_true", help="Change (or disable) password")
	parser.add_argument("-e", "--erase", required=False, action="store_true", help="Secure erase device")
	parser.add_argument("-d", "--device", dest="device", required=False, help="Force device path (ex. /dev/sdb). Usually you don't need this option.")

	args = parser.parse_args()
	
	if len(sys.argv) == 1:
		args.status = True
	
	## Get occurrences of "Passport" devices. Iterate over each disk block device
	## and go up to its parents to find a "WD Passport" device.
	passport_devices = []
	context = pyudev.Context()
	for disk_device in context.list_devices(subsystem='block', DEVTYPE='disk'):
		# If -d is used, filter devices.
		if args.device and disk_device.device_node != args.device:
			continue

		# Scan parent for device name.
		device = disk_device
		while device is not None:
			if "ID_SERIAL" in device:
				if device.properties["ID_SERIAL"].startswith("Western_Digital_My_"):
					passport_devices.append(disk_device)
			device = device.parent

	if len(passport_devices) == 0:
		print(fail("No Western Digital Passport device found."))
		sys.exit(1)
	elif len(passport_devices) > 1:
		print(fail("Multiple Western Digital Passport devices found. Use --device /dev/___ to choose."))
		sys.exit(1)

	device = passport_devices[0]
	device_name = device.device_node

	## Open the device.
	try:
		dev = open(device.device_node, "r+b")
	except PermissionError:
		print(fail("Could not open {}. Try running as root as 'sudo {}'.".format(
			device_name,
			sys.argv[0])))
		sys.exit(1)
	except:
		print(fail("Something wrong opening {}".format(device_name)))
		sys.exit(1)

	## Report device state if no specific command is given.
	if not args.unlock and not args.change_passwd and not args.erase and not args.mount:
		status = get_encryption_status()
		print("Device: %s" % device_name)
		print("Security status: %s" % sec_status_to_str(status["Locked"]))
		print("Encryption type: %s" % cipher_id_to_str(status["Cipher"]))

	## Perform actions.
	if args.unlock:
		unlock()
	if args.change_passwd:
		print("Changing password for {}...".format(device_name))
		change_password()
	if args.erase:
		print(question("All data on {} will be lost. Are you sure you want to continue? [y/N]".format(
			device_name
		)))
		r = sys.stdin.read(1)
		if r.lower() == 'y':
			secure_erase()
		else:
			print(success("Ok, nevermind."))
	if args.mount:
		enable_mount(device)

if __name__ == "__main__":
	main(sys.argv[1:])
