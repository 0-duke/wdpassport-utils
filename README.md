
# WD My Passport Drive Hardware Encryption Utility for Linux

A Linux command-line utility to lock, unlock, and manage the hardware encryption functionality of Western Digital My Passport external drives. Written in Python 3.

WD My Passport drives support hardware encryption. New drives arrive in a passwordless state --- they can be used without locking or unlocking. After a password is set, drives become locked when they are unplugged and must be unlocked when they are plugged in to mount the volume and see its content.

This utlity can:

* Show drive status.
* Set and change the drive's password.
* Unlock an encrypted drive, given the password.
* Reset the drive in case of a lost password.

Passwords given on the command line are converted into binary password data in a mechanism intended to be compatible with WD's unlock software that is used in Microsoft Windows.

This tool was originally written by [0-duke](https://github.com/0-duke/wdpassport-utils) in 2015 based on reverse engineering research by [DanLukes](https://github.com/DanLukes) and an implementation by DanLukes and [KenMacD](https://github.com/KenMacD/wdpassport-utils). [crypto-universe](https://github.com/crypto-universe/wdpassport-utils) converted this project and the underlying SCSI interface library py_sg to Python 3. [JoshData](https://github.com/JoshData/wdpassport-utils) updated the library to work with the latest WD My Passport device.

## Installing

You'll need the Python 3 development headers to install this tool. On Ubuntu 22.04 LTS run:

```
sudo apt install python3 python3-dev python3-pip git
```

On other Linux distributions you may need a different command.


You *must* use sudo in this command.  Usually that's a bad idea when running pip but we need to be root to access the devices.
Then use pip to install the source code in this repository:
```
sudo pip install git+https://github.com/0-duke/wdpassport-utils
```

## Usage

Run script as root or as a user that has permission to manage the device.

When used without any arguments, the status of the drive is shown:
```
$ sudo wdpassport-utils.py 
[sudo] password for user: 
Device: /dev/sdc
Security status: Unlocked
Encryption type: Unknown (0x31)
```

There are few options:

```
-u, --unlock          Unlock
```
Unlock a locked drive. You will be asked to enter the unlock password. If everything is fine device will be unlocked. (To lock a drive, unplug it.)

```
-m, --mount           Enable mount point for an unlocked device
```
After unlock, your operating system may still think that your device is a strange thing attached to its USB port and doesn't know how to manage it. This option forces the operating system to rescan the device and handle it as a normal external USB harddrive. This flag can be combined with `-u`.

```
-c, --change_passwd   Set, change, or remove password protection
```
Set a password on a new drive, change the password, or remove the password (so that it does not need to be unlocked to use). To remove a password, leave the new password empty.

```
-e, --erase           Erase/reset device
```
Erase (reset) the drive. This will remove the internal key associated to you password and all your data will be unaccessible. You will also lose your partition table and you will need to create a new one (you can use fdisk and mkfs or other utilities to prepare and format the drive).

```
-d DEVICE, --device DEVICE  Device path (ex. /dev/sdb). Optional.
```
This tool will try to auto-detect the device path of your WD My Passport device. If you have more than one device, or if auto-detection fails, you can manually specify the device path, e.g. as `/dev/sdb`.

```
-h, --help            show this help message and exit
```
Lists all possible arguments.

<h1>Disclaimer</h1>

Use the tool and any of the information contained in this repository at your own risk. The tool was developed without any official documenation from Western Digital on how to manage the drive using its raw SCSI interface. We accept no responsibility.
