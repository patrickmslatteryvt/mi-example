# $LastChangedBy:$
# $Revision:$
# $LastChangedDate:$
# $HeadURL:$
#
# Kickstart file for use as a minimal (~366 packages) CentOS/RHEL v7.x base VM
# Expects the following hardware:
# 512+MB RAM (4+GB listed as required if using the GUI installer)
# Hard disk 1 = 6+GB	OS
# Hard disk 2 = 4+GB	metadata
# Hard disk 3 = 4+GB	depotdata
# Hard disk 4 = 4+GB	logs
# Updated for CentOS v7.0
#
# NOTE: Edit network and timezone as necessary
# See:
# http://fedoraproject.org/wiki/Anaconda/Kickstart
# &
# https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Installation_Guide/s1-kickstart2-options.html
# for latest documentation of kickstart options

# platform=x86, AMD64, or Intel EM64T
# version=1.0

# Install OS instead of upgrade
install

# Use network installation (slow)
# url --url="http://mirror.centos.org/centos/7/os/x86_64/"
#
# Install from CD/ISO (fast)
# Use the full DVD ISO image if installing anything more than the minimal set of packages
cdrom

# System language
# Using en_US.UTF-8 over en_US as it gives us correct ncurses UI display in the console.
lang en_US.UTF-8

# System keyboard
keyboard us

# Use non-interactive command line mode instead of ncurses mode for the install. Any prompts for interaction will halt the install.
# cmdline
#
# Use text mode (ncurses) install
text

# Install logging level
logging --level=info

# Enable firewall, open ports for ssh, HTTP and HTTPS (TCP 22, 80 and 443)
# The ssh option is enabled by default, regardless of the presence of the --ssh flag. See: http://fedoraproject.org/wiki/Anaconda/Kickstart#firewall
firewall --enabled --ssh --http --port=443:tcp

# Use SHA-512 encrypted password instead of the usual UNIX crypt or md5
authconfig --enableshadow --passalgo=sha512

# Root password (generate the password with the "grub-crypt" command)
rootpw --iscrypted $6$B5wo6mj1yshzwORO$RP1QyFLoXpYnqGfS5p5Oo2dcLwFgC1ExXSs7UXnX2BeNEVZKwR1DWHTB8d/ZiCy1fi9kSTdpZ3xDX4f624K290
# rootpw MyWebGrocer2013

# SELinux configuration
selinux --permissive

# Edit the network settings as required
# If you need to manually specify network settings during an otherwise-automated kickstart installation, do not use network.
# Instead, boot the system with the "asknetwork" option (refer to Section 32.10, "Starting a Kickstart Installation"), which will prompt
## https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Installation_Guide/s1-kickstart2-startinginstall.html
# anaconda to ask you for network settings rather than use the default settings. anaconda will ask this before fetching the kickstart file.
# Once the network connection is established, you can only reconfigure network settings with those specified in your kickstart file.
# UNDERSTANDING THE PREDICTABLE NETWORK INTERFACE DEVICE NAMES
# https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/Networking_Guide/ch-Consistent_Network_Device_Naming.html
# DEVDMZ test instance - DHCP boot for network installs
network --device=ens192 --onboot=yes --noipv6 --bootproto=dhcp

# Do not configure the X Window System
skipx

# Reboot after the installation is complete and eject the install DVD. Normally, kickstart displays a message and waits for the user to press a key before rebooting.
# default is halt
reboot --eject

# System timezone - Edit as required
# Option --utc - If present, the system assumes the hardware clock is set to UTC (Greenwich Mean) time.
timezone --utc America/New_York # Eastern
# timezone --utc America/Chicago # Central
# timezone --utc America/Boise # Mountain
# timezone --utc America/Phoenix # Mountain - No DST observed in AZ except in the Navajo Nation
# timezone --utc America/Los_Angeles # Pacific


# System bootloader configuration
bootloader --location=mbr --driveorder=sda,sdb,sdc,sdd --append="crashkernel=auto rhgb quiet"

# If zerombr is specified any invalid partition tables found on disks are initialized. This destroys all of the contents of disks with invalid partition tables.
zerombr

# Disk partitioning information
clearpart --all --initlabel
part /boot --fstype="xfs" --size=384 --ondisk=sda
part swap --fstype="swap" --size=1024 --ondisk=sda
part / --fstype="xfs" --grow --size=1 --ondisk=sda
part /metadata --fstype="xfs" --grow --size=1 --ondisk=sdb
part /depotdata --fstype="xfs" --grow --size=1 --ondisk=sdc
part /logs --fstype="xfs" --grow --size=1 --ondisk=sdd


##############################################################################
#
# packages part of the KickStart configuration file
#
##############################################################################
# following is MINIMAL https://partner-bugzilla.redhat.com/show_bug.cgi?id=593309
# Minimal + the packages listed below = 366 packages
%packages --nobase
@core
@network-file-system-client
nano
ntp
perl
nfs-utils
wget
unzip
rsync
man
logwatch
parted
pciutils
lsof
patch
bind-utils # provides nslookup and dig
deltarpm
mlocate
# Don't install these packages, no need for firmware patches on a VM, gets us down to 366 packages
-aic94xx-firmware.noarch
-alsa-firmware.noarch
-alsa-lib.x86_64
-alsa-tools-firmware.x86_64
-ivtv-firmware.noarch
-iwl100-firmware.noarch
-iwl1000-firmware.noarch
-iwl105-firmware.noarch
-iwl135-firmware.noarch
-iwl2000-firmware.noarch
-iwl2030-firmware.noarch
-iwl3160-firmware.noarch
-iwl3945-firmware.noarch
-iwl4965-firmware.noarch
-iwl5000-firmware.noarch
-iwl5150-firmware.noarch
-iwl6000-firmware.noarch
-iwl6000g2a-firmware.noarch
-iwl6000g2b-firmware.noarch
-iwl6050-firmware.noarch
-iwl7260-firmware.noarch
-libertas-sd8686-firmware.noarch
-libertas-sd8787-firmware.noarch
-libertas-usb8388-firmware.noarch
%end
