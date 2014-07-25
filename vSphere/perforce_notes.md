# Set hostname
hostnamectl set-hostname perforce.devdmz.mywebgrocer.com

# Updating base packages...
yum update -y

# reboot to let latest kernel take effect
reboot
# 3.10.0-123.4.2.el7
# Linux perforce.devdmz.mywebgrocer.com 3.10.0-123.el7.x86_64 #1 SMP Mon Jun 30 12:09:22 UTC 2014 x86_64 x86_64 x86_64 GNU/Linux
# Linux perforce.devdmz.mywebgrocer.com 3.10.0-123.4.2.el7.x86_64 #1 SMP Mon Jun 30 16:09:14 UTC 2014 x86_64 x86_64 x86_64 GNU/Linux

# jq is a lightweight and flexible command-line JSON processor.
curl http://stedolan.github.io/jq/download/linux64/jq -o /usr/local/sbin/jq
chmod -c +x /usr/local/sbin/jq

systemctl -t service
[root@dlp ~]# systemctl stop postfix 
[root@dlp ~]# systemctl disable postfix 

