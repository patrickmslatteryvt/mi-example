#!/bin/bash

# ================================================================================

function pause(){
	read -t15 -n1 -r -p "Press any key to continue..."
	printf "\n"
}

# ================================================================================

export_vars() {
  echo ''
  echo 'Perforce - Export all the environment variables we will use later on in the script...'

  # Define our Java version
  # 7u51-b13
  JAVA_RELEASE=7
  JAVA_UPDATE=u51
  JAVA_BUILD=b13
  JAVA_VERSION="jre-"
  JAVA_VERSION+=$JAVA_RELEASE$JAVA_UPDATE
  JAVA_DIR="jdk1.7.0_51"
  JAVA_x64_URL=http://download.oracle.com/otn-pub/java/jdk/$JAVA_RELEASE$JAVA_UPDATE-$JAVA_BUILD/server-jre-$JAVA_RELEASE$JAVA_UPDATE-linux-x64.tar.gz
  JAVA_x64_MD5=c5a034f4222bac326101799bcb20509c
  
  # Define the version we are going to use and where we'll get it from.
  # P4BIN_DOWNLOAD=http://perforce.mywebgrocer.com/3rdparty/Perforce
  P4BIN_DOWNLOAD=ftp://ftp.perforce.com/perforce
  P4BIN_VERSION=r13.3
  P4BIN_PLATFORM=bin.linux26x86_64
  P4SCRIPTS_DOWNLOAD=https://raw.github.com/patrickmslatteryvt/mi-perforce/master
  WGETGLOBALS="--no-check-certificate --no-directories --no-cache"
  P4BIN_DIR=/depotdata/p4/common/bin

  IP_ADDRESS=$(ifconfig eth0 | sed -En 's/127.0.0.1//;s/.*inet (addr:)?(([0-9]*\.){3}[0-9]*).*/\2/p')

  # Who will email be sent to? If not defined send to the default
  if [ -z ${PERFORCE_ADMINS} ]; then
    PERFORCE_ADMINS=pslattery+perforce@mywebgrocer.com
  fi

  # CNAME=sourcecode.mywebgrocer.com
  # CNAME=perforce.mywebgrocer.com
  if [ -z ${CNAME} ]; then
    echo 'A valid CNAME is required!'
    exit 1
  fi

  # Make sure we have an OAuth key defined
  # if [ -z ${GITHUB_OAUTH_KEY} ]; then
    # echo 'A valid 40 char OAuth key for GitHub downloads is required!'
    # exit 1
  # else
    # # Make sure it's 40 chars long
    # STRLENGTH=$(echo ${GITHUB_OAUTH_KEY} | awk '{print length}')
    # if [ ${STRLENGTH} -ne 40 ]; then
      # echo 'A valid 40 char OAuth key for GitHub downloads is required!'
      # exit 1
    # fi
  # fi  
}

# ================================================================================

install_base() {
  # Update package library and install the necessary packages
  # these may already be installed via kickstart but we'll call them
  # again here just in case as the script will fail without them
  echo ''
  echo 'Perforce - Installing base packages...'
  yum update -y && yum install -y nano wget lsof patch
  # jq is a lightweight and flexible command-line JSON processor.
  curl http://stedolan.github.io/jq/download/linux64/jq -o /usr/local/sbin/jq
  chmod -c +x /usr/local/sbin/jq
}

# ================================================================================

install_nginx() {
  echo ''
  echo 'Perforce - Installing nginx...'
  # http://nginx.org/packages/keys/nginx_signing.key
  echo "[nginx]">/etc/yum.repos.d/nginx.repo
  echo "name=nginx repo">>/etc/yum.repos.d/nginx.repo
  echo "baseurl=http://nginx.org/packages/centos/6/x86_64/">>/etc/yum.repos.d/nginx.repo
  echo "enabled=1">>/etc/yum.repos.d/nginx.repo
  echo "gpgcheck=0">>/etc/yum.repos.d/nginx.repo
  # Verify we can download from the repo
  yum list | grep nginx
    # check we got a return there
  # Install nginx
  yum install -y nginx
    # Check the packages were installed
}

# ================================================================================

install_htop() {
  echo ''
  echo 'Perforce - Installing htop...'
  rpm -Uhv http://pkgs.repoforge.org/htop/htop-1.0.2-1.el6.rf.x86_64.rpm
}

# ================================================================================

install_vmtools() {
  echo ''
  echo 'Install the latest VMware Tools...'
  rpm --import http://packages.vmware.com/tools/keys/VMWARE-PACKAGING-GPG-DSA-KEY.pub
  rpm --import http://packages.vmware.com/tools/keys/VMWARE-PACKAGING-GPG-RSA-KEY.pub
  echo "[vmware-tools]">/etc/yum.repos.d/vmware-tools.repo
  echo "name=VMware Tools">>/etc/yum.repos.d/vmware-tools.repo
  echo "baseurl=http://packages.vmware.com/tools/esx/latest/rhel6/x86_64">>/etc/yum.repos.d/vmware-tools.repo
  echo "enabled=1">>/etc/yum.repos.d/vmware-tools.repo
  echo "gpgcheck=1">>/etc/yum.repos.d/vmware-tools.repo
  # Install VMware Tools
  yum install vmware-tools-esx-kmods.x86_64 vmware-tools-esx-nox.x86_64 -y
  
#  curl http://packages.vmware.com/tools/esx/5.5p01/repos/vmware-tools-repo-RHEL6-9.4.0-1.el6.x86_64.rpm -o /tmp/vmware-tools-repo-RHEL6-9.4.0-1.el6.x86_64.rpm
#  rpm -Uhv /tmp/vmware-tools-repo-RHEL6-9.4.0-1.el6.x86_64.rpm
  
  # Verify the VMware Tools were installed
}

# ================================================================================

create_users() {
  # Add the admin user to the sudoers list
  # echo 'admin ALL=(ALL) ALL'>>/etc/sudoers
  echo ''
  echo 'Perforce - Create the users to run Perforce under...'
  # NOTE: 8 char max for user and group names
  # <username>,<password>,<GID>,<groupname>,<User detail>,<shell>
  echo 'uperforce,MyWebGrocer2013#_perforce,500,gp4admin,Account for running the Perforce services under,/sbin/nologin'>~/users.txt
  # Would be be better security to run each service under its own user? Getting access to a edge access user such as the broker should not lead to access on the main p4d user in such a case. Worth looking into...
  #echo 'up4broker,MyWebGrocer2013#_p4broker,500,gp4admin,Account for running the Perforce Broker under,/sbin/nologin'>~/users.txt
  #echo 'up4d,MyWebGrocer2013#_p4d,500,gp4admin,Account for running the Perforce depots under,/sbin/nologin'>>~/users.txt
  #echo 'up4web,MyWebGrocer2013#_p4web,500,gp4admin,Account for running the Perforce web server under,/sbin/nologin'>>~/users.txt
  #echo 'up4git,MyWebGrocer2013#_p4git,500,gp4admin,Account for running the Perforce GitFusion instance under,/sbin/nologin'>>~/users.txt
  #echo 'up4commons,MyWebGrocer2013#_p4commons,500,gp4admin,Account for running the Perforce Commons processes under,/sbin/nologin'>>~/users.txt

  curl -L -u ${GITHUB_PRIV_OAUTH_KEY}:x-oauth-basic https://raw.github.com/patrickmslatteryvt/shell/master/bash/create_users.sh -o ~/create_users.sh
  echo
  chmod -c +x ~/create_users.sh
  echo
  ~/create_users.sh<~/users.txt
}

# ================================================================================

install_java() {
  echo ''
  echo 'Perforce - Installing Java...'

  if [ -f "/tmp/server-${JAVA_VERSION}-linux-x64.tar.gz" ]
  then
    echo "File is already on disk, no need to download it again"
  else
    # JAVA install tar.gz not found, download it
  wget --read-timeout=60 --tries=3 --no-cookies --no-check-certificate --header "Cookie: gpw_e24=http%3A%2F%2Fwww.oracle.com%2F" ${JAVA_x64_URL} \
  --output-document=/tmp/server-${JAVA_VERSION}-linux-x64.tar.gz
  fi

  # Verify the downloaded files
  echo "${JAVA_x64_MD5}  server-${JAVA_VERSION}-linux-x64.tar.gz">/tmp/java.md5

  cd /tmp
  md5sum -c /tmp/java.md5
  exit_status=$?
  if test $exit_status -eq 0
  then
    echo "Files match precomputed MD5 hashes"
  else
    echo "Files DO NOT match precomputed MD5 hashes. Exiting."
    exit 1
  fi
  cd ->nul

  # Make an installation directory for Java, the specific versions will in subdirectories thereof
  mkdir -p /opt/java

  echo ''
  echo 'Perforce - Extracting Java binaries...'
  # Extract the Java binaries from the gz file to the installation directory
  # Will extract as owned by uucp:143 if --no-same-owner is not used by the root user
  tar --no-same-owner -xvzf /tmp/server-${JAVA_VERSION}-linux-x64.tar.gz -C /opt/java 1>/dev/null

  # Delete the Java source files, we don't have any need of them and it just wastes 20MB of disk space (each).
  find /opt/java -name src.zip -exec rm -f {} \;
}

# ================================================================================

config_nginx() {
  echo ''
  echo 'Perforce - Configure Nginx reverse proxy...'
  # The nginx service is disabled by default, it needs a valid conf file setup for it first before we enable it
  curl -L -u ${GITHUB_OAUTH_KEY}:x-oauth-basic https://raw.github.com/patrickmslatteryvt/mi-perforce/master/nginx/nginx.conf -o /etc/nginx/nginx.conf
  grep -i --color "Hello future GitHubber" /etc/nginx/nginx.conf

  # Replace the hostname stub with the CNAME that we are using (This could be the hostname, either way define the CNAME variable)
  sed -i "s/HOSTNAME/${CNAME}/g" /etc/nginx/nginx.conf
  grep -i --color ${CNAME} /etc/nginx/nginx.conf
  # Replace the external facing IP address stub with the actual IP address of interface eth0
  # This is used to make sure that nginx only listens on the external interface.
  sed -i "s/IP_ADDRESS/${IP_ADDRESS}/g" /etc/nginx/nginx.conf
  grep -i --color ${IP_ADDRESS} /etc/nginx/nginx.conf
  # Fix the /etc locations in the conf file (the conf file was written for SmartOS), log locations are the same in Linux and CentOS 6.x
#  sed -i "s@/opt/local/etc@/etc@g" /etc/nginx/nginx.conf
  # Fix the user name in the conf file (www in SmartOS, nginx in CentOS 6.x)
  sed -i "s@www www;@nginx nginx;@g" /etc/nginx/nginx.conf
  # Download the IP blocking conf file
  curl -L -u ${GITHUB_OAUTH_KEY}:x-oauth-basic https://raw.github.com/patrickmslatteryvt/mi-perforce/master/nginx/blockips.conf -o /etc/nginx/blockips.conf

  # Create a directory for nginx status and error pages.
  mkdir -p /srv/www/MWG_images
  cp /usr/share/nginx/html/* /srv/www/
  # 404 background image
  curl -L -u ${GITHUB_OAUTH_KEY}:x-oauth-basic https://raw.github.com/patrickmslatteryvt/mi-perforce/master/images/maint_background.gif -o /srv/www/MWG_images/maint_background.gif

  # download the static error pages
  mkdir -p /srv/www/error
  mv /srv/www/50x.html /srv/www/error/50x.html
  curl -L -u ${GITHUB_OAUTH_KEY}:x-oauth-basic https://raw.github.com/patrickmslatteryvt/mi-perforce/master/nginx/403.html -o /srv/www/error/403.html
  curl -L -u ${GITHUB_OAUTH_KEY}:x-oauth-basic https://raw.github.com/patrickmslatteryvt/mi-perforce/master/nginx/502.html -o /srv/www/error/502.html
  curl -L -u ${GITHUB_OAUTH_KEY}:x-oauth-basic https://raw.github.com/patrickmslatteryvt/mi-perforce/master/nginx/503.html -o /srv/www/error/503.html

  # Create self signed SSL Cert for HTTPS
  curl -L -u ${GITHUB_PRIV_OAUTH_KEY}:x-oauth-basic https://raw.github.com/patrickmslatteryvt/shell/master/bash/generateSSLSelfSignCert.sh -o ~/generateSSLSelfSignCert.sh
  chmod -c +x ~/generateSSLSelfSignCert.sh
  ~/generateSSLSelfSignCert.sh
  # If the CNAME is not the same as the hostname then rename the self signed keys or else nginx won't start
  if [ "${HOSTNAME}" != "${CNAME}" ]
  then
    mv /etc/ssl/private_keys/${HOSTNAME}.key /etc/ssl/private_keys/${CNAME}.key
    mv /etc/ssl/certs/${HOSTNAME}.crt /etc/ssl/certs/${CNAME}.crt
  fi

  # Set security on the keys so that only the root user can read them (but even root cannot write to them)
  chown -c -R root:root /etc/ssl/
  chmod -c 400 /etc/ssl/certs/*.crt
  chmod -c 400 /etc/ssl/private_keys/*.key

  # Enable nginx
  chkconfig --level 345 nginx on
  service nginx start
}

# ================================================================================

config_network() {
  echo ''
  echo 'Perforce - Configure network settings...'
  # Disable applications from using IPv6 without actually disabling IPv6 totally
  # See: How do I disable IPv6? - http://wiki.centos.org/FAQ/CentOS6#head-d47139912868bcb9d754441ecb6a8a10d41781df
  # These commands will disable IPv6 usage on the running system
  sysctl -w net.ipv6.conf.all.disable_ipv6=1
  sysctl -w net.ipv6.conf.default.disable_ipv6=1

  # To make the change permanent we need to to the following:
  echo 'net.ipv6.conf.all.disable_ipv6 = 1'>>/etc/sysctl.conf
  echo 'net.ipv6.conf.default.disable_ipv6 = 1'>>/etc/sysctl.conf
}

# ================================================================================

config_firewall() {
  # Initial firewall
  # Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
  # num   pkts bytes target     prot opt in     out     source               destination
  # 1      145 13065 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0           state RELATED,ESTABLISHED
  # 2        3   354 ACCEPT     icmp --  *      *       0.0.0.0/0            0.0.0.0/0
  # 3        0     0 ACCEPT     all  --  lo     *       0.0.0.0/0            0.0.0.0/0
  # 4       18   976 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0           state NEW tcp dpt:22
  # 5        3   164 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0           state NEW tcp dpt:80
  # 6       10   440 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0           state NEW tcp dpt:443
  # 7     2396  124K REJECT     all  --  *      *       0.0.0.0/0            0.0.0.0/0           reject-with icmp-host-prohibited
  #
  # Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
  # num   pkts bytes target     prot opt in     out     source               destination
  # 1        0     0 REJECT     all  --  *      *       0.0.0.0/0            0.0.0.0/0           reject-with icmp-host-prohibited
  #
  # Chain OUTPUT (policy ACCEPT 174 packets, 22407 bytes)
  # num   pkts bytes target     prot opt in     out     source               destination

  echo ''
  echo 'Perforce - Configure firewall...'
  echo -e "\tDelete all existing iptables rules"
  iptables -F
  echo -e "\tSet default chain policies, drop all packets by default."
  iptables -P INPUT DROP
  #iptables -P FORWARD DROP
  #iptables -P OUTPUT DROP
  echo -e "\tAllow incoming SSH"
  iptables -A INPUT -i eth0 -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT -m recent --set --name SSH
  iptables -A OUTPUT -o eth0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT -m recent --set --name SSH
  # Allow only 4 ssh connections within 2 minutes, tarpits dictionary attacks
  # iptables -I INPUT -i eth0 -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 120 --hitcount 10 --rttl --name SSH -j DROP
  # Testcase ssh from desktop
  echo -e "\tAllow outgoing HTTP (for yum updates)"
  iptables -A OUTPUT -o eth0 -p tcp --dport 80 -m tcp -m state --state NEW -j ACCEPT
  echo -e "\tAllow ESTABLISHED,RELATED connections"
  iptables -A INPUT -i eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT
  iptables -A OUTPUT -o eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT
  echo -e "\tAllow HTTP data on port 80"
  iptables -A INPUT -i eth0 -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT -m recent --set --name HTTP
  iptables -A OUTPUT -o eth0 -p tcp --sport 80 -m state --state RELATED,ESTABLISHED -j ACCEPT -m recent --set --name HTTP
  echo -e "\tAllow HTTPS data on port 443"
  iptables -A INPUT -i eth0 -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT -m recent --set --name HTTPS
  iptables -A OUTPUT -o eth0 -p tcp --sport 443 -m state --state RELATED,ESTABLISHED -j ACCEPT -m recent --set --name HTTPS
  echo -e "\tAllow Perforce data on port 1666"
  iptables -A INPUT -i eth0 -p tcp --dport 1666 -m state --state NEW,ESTABLISHED -j ACCEPT -m recent --set --name P4
  iptables -A OUTPUT -o eth0 -p tcp --sport 1666 -m state --state RELATED,ESTABLISHED -j ACCEPT -m recent --set --name P4
  echo -e "\tBut block any attempts by users to get directly to the Perforce processes on ports 1667, 1668, or 1669"
  iptables -A INPUT -i eth0 -p tcp --dport 1667 -j DROP # P4D_depots
  iptables -A INPUT -i eth0 -p tcp --dport 1668 -j DROP # P4D_sideload
  iptables -A INPUT -i eth0 -p tcp --dport 1669 -j DROP # ???
  echo -e "\tAllow allow outside users to be able to ping the server"
  iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
  iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT
  # Testcase ping $IP
  echo -e "\tAllow ping from inside to outside"
  iptables -A OUTPUT -o eth0 -p icmp --icmp-type echo-request -j ACCEPT
  iptables -A INPUT -i eth0 -p icmp --icmp-type echo-reply -j ACCEPT
  # Testcase ping wvt2012r2stdco.devdmz.mywebgrocer.com
  echo -e "\tAllow local loopback access"
  iptables -A INPUT -i lo -j ACCEPT
  iptables -A OUTPUT -o lo -j ACCEPT
  echo -e "\tAllow outbound DNS"
  iptables -A OUTPUT -p udp -o eth0 --dport 53 -j ACCEPT
  iptables -A INPUT -p udp -i eth0 --sport 53 -j ACCEPT
  # Testcase ping wvt2012r2stdco.devdmz.mywebgrocer.com
  echo -e "\tAllow Sendmail or Postfix Traffic"
  # iptables -A INPUT -i eth0 -p tcp --dport 25 -m state --state NEW,ESTABLISHED -j ACCEPT
  iptables -A INPUT -i eth0 -p tcp --dport 25 -m state --state ESTABLISHED -j ACCEPT
  iptables -A OUTPUT -o eth0 -p tcp --sport 25 -m state --state ESTABLISHED -j ACCEPT
  # Testcase
  echo Save the iptables settings
  service iptables save
  # list the active rules
  iptables -L -n -v --line-numbers
}

# ================================================================================

config_etc-services() {
# Fix the services file so that various network utils will show the right service running
sed -i "s@netview-aix-6   1666/tcp                # netview-aix-6@p4broker        1666/tcp                # Perforce Broker@g" /etc/services
sed -i "s@netview-aix-7   1667/tcp                # netview-aix-7@p4d             1667/tcp                # Perforce depots instance@g" /etc/services
sed -i "s@netview-aix-8   1668/tcp                # netview-aix-8@p4d-sideload    1668/tcp                # Perforce sideload instance@g" /etc/services
}

# ================================================================================

create_p4_dirs() {
# REQUIRES USERS TO EXIST FIRST

mkdir -p /depotdata/p4/{1,2}/{checkpoints,depots,bin,etc,tmp}
mkdir -p /metadata/p4/{1,2}/{root,offline_db}
mkdir -p /p4logs/p4/{1,2}/logs
mkdir -p /p4/{1,2}
[[ -d $P4BIN_DIR ]] || mkdir -p $P4BIN_DIR
# If the home directory does not exist then exit
[[ -d /home/uperforce ]] || exit 3
mkdir -p /home/uperforce/{p4-broker,depot}

# Create our symlink tree
# /p4/common          -->        /depotdata/p4/common/bin
# /p4/1
#     /checkpoints    -->        /depotdata/p4/1/checkpoints
#     /depots         -->        /depotdata/p4/1/depots
#     /bin            -->        /depotdata/p4/1/bin
#     /etc            -->        /depotdata/p4/1/etc
#     /tmp            -->        /depotdata/p4/1/tmp
#     /root           -->        /metadata/p4/1/root
#     /offline_db     -->        /metadata/p4/1/offline_db
#     /logs           -->        /p4logs/p4/1/logs

ln -s /depotdata/p4/common/bin /p4/common
# THIS ISN'T WORKING!!!
for INSTANCE in 1 2
do
  for DIR in checkpoints depots bin etc tmp
  do
    ln -s /depotdata/p4/${INSTANCE}/${DIR} /p4/${INSTANCE}/${DIR}
  done
done

for INSTANCE in 1 2
do
  for DIR in root offline_db
  do
    ln -s /metadata/p4/${INSTANCE}/${DIR} /p4/${INSTANCE}/${DIR}
  done
done

for INSTANCE in 1 2
do
  ln -s /p4logs/p4/${INSTANCE}/logs /p4/${INSTANCE}/logs
done

chown -Rc uperforce:gp4admin /depotdata
chown -Rc uperforce:gp4admin /metadata
chown -Rc uperforce:gp4admin /p4logs
chown -Rc uperforce:gp4admin /home/uperforce

}

# ================================================================================

install_p4() {
# REQUIRES USERS TO EXIST FIRST

for FILENAME in SHA256SUMS p4d p4broker p4 p4p p4api.tgz # p4ftpd p4v.tgz perfmerge
do
  # Don't download if the files already exist
  [[ -f $P4BIN_DIR/${FILENAME} ]] || wget $WGETGLOBALS $P4BIN_DOWNLOAD/$P4BIN_VERSION/$P4BIN_PLATFORM/${FILENAME} --output-document=$P4BIN_DIR/${FILENAME} 
done

# p4web is not at the same release version as everything else
[[ -f $P4BIN_DIR/SHA256SUMS.r12.1 ]] || wget $WGETGLOBALS $P4BIN_DOWNLOAD/r12.1/$P4BIN_PLATFORM/SHA256SUMS --output-document=$P4BIN_DIR/SHA256SUMS.r12.1
[[ -f $P4BIN_DIR/p4web ]] || wget $WGETGLOBALS $P4BIN_DOWNLOAD/r12.1/$P4BIN_PLATFORM/p4web --output-document=$P4BIN_DIR/p4web

# Comment out the files we don't need/want from the hash manifest, if we don't do this and haven't downloaded the files the hash test in the following step will fail
sed -i '/p4v.tgz/s/^/# /g' $P4BIN_DIR/SHA256SUMS
sed -i '/perfmerge/s/^/# /g' $P4BIN_DIR/SHA256SUMS
sed -i '/p4ftpd/s/^/# /g' $P4BIN_DIR/SHA256SUMS
# Do the same for the p4web binary
sed -i '/p4web/!s/^/# /g' $P4BIN_DIR/SHA256SUMS.r12.1

# Verify the downloaded files
cd $P4BIN_DIR/
sha256sum -c $P4BIN_DIR/SHA256SUMS
exit_status=$?
if test $exit_status -eq 0
then
  echo "Files match precomputed SHA256 hashes"
else
  echo "Files DO NOT match precomputed SHA256 hashes. Exiting."
  exit 1
fi
cd ->nul

# And again for p4web
cd $P4BIN_DIR/
sha256sum -c $P4BIN_DIR/SHA256SUMS.r12.1
exit_status=$?
if test $exit_status -eq 0
then
  echo "Files match precomputed SHA256 hashes"
else
  echo "Files DO NOT match precomputed SHA256 hashes. Exiting."
  exit 1
fi
cd ->nul

# Make the binaries executable
chmod -c u+x $P4BIN_DIR/p4*
# but not the tgz files
chmod -c u-x $P4BIN_DIR/p4*.tgz

# Rename the binaries so that they have the version string in their name (
curl -L -u ${GITHUB_OAUTH_KEY}:x-oauth-basic https://raw.github.com/patrickmslatteryvt/mi-perforce/master/rename_p4_binaries.sh -o ~/rename_p4_binaries.sh
chmod -c +x ~/rename_p4_binaries.sh
~/rename_p4_binaries.sh

for INSTANCE in 1 2
do
  for EXECUTABLE in p4d p4broker p4web p4
  do
    ln -s $P4BIN_DIR/${EXECUTABLE}.????.?.?????? /p4/${INSTANCE}/bin/${EXECUTABLE}
  done
done

touch /home/uperforce/.p4tickets

for INSTANCE in 1 2
do
  for LOGFILE in p4d.log p4d_audit.log p4broker.log p4web.log
  do
    touch /p4logs/p4/${INSTANCE}/logs/${LOGFILE}
  done
done

# Download the customised p4broker conf files
for FILENAME in p4broker.conf.up p4broker.conf.down p4broker_sideload_p4web.conf.up p4broker_sideload_p4web.conf.down P4WEBMIMEFILE
do
  # Don't download if the files already exist
  [[ -f /p4/1/root/${FILENAME} ]] || wget $WGETGLOBALS $P4SCRIPTS_DOWNLOAD/${FILENAME} --output-document=/p4/1/root/${FILENAME}
done

chown -Rc uperforce:gp4admin /depotdata
chown -Rc uperforce:gp4admin /metadata
chown -Rc uperforce:gp4admin /p4logs
chown -Rc uperforce:gp4admin /p4

}

# ================================================================================

config_p4_initd() {
  echo ''
  echo 'Perforce - Install service instances...'
  # RH based Linux distros are 10 years behind SMF in Solaris in this respect

  for SERVICE in p4broker p4d p4d_sideload p4web
  do
    # Don't download if the services already exist
    [[ -f $P4BIN_DIR/${SERVICE} ]] || curl -L -u ${GITHUB_OAUTH_KEY}:x-oauth-basic $P4SCRIPTS_DOWNLOAD/init.d/${SERVICE} -o /etc/init.d/${SERVICE}
    # Make the Perforce init scripts executable
    chmod -c +x /etc/init.d/${SERVICE}
    # Create the RHEL services
    /sbin/chkconfig --add ${SERVICE}
    # Set the services to autostart in the necessary runlevels
    /sbin/chkconfig --level 345 ${SERVICE} on
  done
  # Do not start services at this time, they must be properly setup first
  
# get the conf files for the services

# [root@perforce ~]# service p4broker
# /etc/init.d/p4broker: line 51: /p4/1/etc/p4d.conf: No such file or directory
# Usage: /etc/init.d/p4broker {start|restart|stop|status|logtail}

  for INSTANCE in 1 2
  do
    for CONF in p4broker.conf.down p4broker.conf.up p4broker_sideload_p4web.conf.down p4broker_sideload_p4web.conf.up
    do
      [[ -f /p4/${INSTANCE}/etc/${CONF} ]] || curl -L -u ${GITHUB_OAUTH_KEY}:x-oauth-basic $P4SCRIPTS_DOWNLOAD/init.d/${CONF} -o /p4/${INSTANCE}/etc/${CONF}  
    done
  done

  ln -s /p4/1/etc/p4broker.conf.up /p4/1/etc/p4broker.conf
  ln -s /p4/2/etc/p4broker.conf.up /p4/2/etc/p4broker.conf

  
}

# ================================================================================

config_sshd_banner() {
  echo ''
  echo 'Enable SSHd login banner...'
  sed -i 's/#Banner none/Banner \/etc\/ssh\/ssh-banner/g' /etc/ssh/sshd_config
  echo  Notice To Users>/etc/ssh/ssh-banner
  echo  This computer system is the private property of MyWebGrocer Inc.>>/etc/ssh/ssh-banner
  echo  "It is for authorized use only. Users (authorized or unauthorized) have no">>/etc/ssh/ssh-banner
  echo  explicit or implicit expectation of privacy.>>/etc/ssh/ssh-banner
  echo  Any or all uses of this system and all files on this system may be intercepted,>>/etc/ssh/ssh-banner
  echo  monitored, recorded, copied, audited, inspected, and disclosed to authorized>>/etc/ssh/ssh-banner
  echo  law enforcement personnel, as well as authorized officials of other agencies,>>/etc/ssh/ssh-banner
  echo  both domestic and foreign.>>/etc/ssh/ssh-banner
  echo  By using this system, the user consents to such interception, monitoring,>>/etc/ssh/ssh-banner
  echo  recording, copying, auditing, inspection, and disclosure at the discretion of>>/etc/ssh/ssh-banner
  echo  authorized personnel.>>/etc/ssh/ssh-banner
  echo  Unauthorized or improper use of this system may result in administrative>>/etc/ssh/ssh-banner
  echo  disciplinary action and civil and criminal penalties. By continuing to use this>>/etc/ssh/ssh-banner
  echo  system you indicate your awareness of and consent to these terms and conditions>>/etc/ssh/ssh-banner
  echo  of use.>>/etc/ssh/ssh-banner
  echo  LOG OFF IMMEDIATELY if you do not agree to the conditions stated in this warning>>/etc/ssh/ssh-banner
  service sshd reload
}

# ================================================================================

config_ntp() {
  echo ''
  echo 'Perforce - Configure NTP settings...'
  cp /etc/ntp.conf /etc/ntp.conf.default
  echo '#' company NTP servers>/etc/ntp.conf
  echo server wvt2012r2stdco.devdmz.mywebgrocer.com iburst>>/etc/ntp.conf
  echo '#' restrict everything>>/etc/ntp.conf
  echo restrict default ignore>>/etc/ntp.conf
  echo '#' allow access via the loopback network>>/etc/ntp.conf
  echo restrict 127.0.0.1>>/etc/ntp.conf
  echo '#' allow access to the company NTP servers>>/etc/ntp.conf
  echo '#' you must use numeric addresses here>>/etc/ntp.conf
  echo restrict wvt2012r2stdco.devdmz.mywebgrocer.com>>/etc/ntp.conf
  echo '#' if you wanted to serve time to other systems on on the 10.17.0.0/16 network, you would add a line like the one below>>/etc/ntp.conf
  echo '#' restrict 10.17.0.0 netmask 255.255.0.0 nomodify>>/etc/ntp.conf
  echo '#' use the local clock fudged down to stratum 10 as a last resort if the company NTP servers are not reachable>>/etc/ntp.conf
  echo server 127.127.1.0>>/etc/ntp.conf
  echo fudge 127.127.1.0 stratum 10>>/etc/ntp.conf
  echo '#' specify the location of the drift file>>/etc/ntp.conf
  echo '#' this contains the systemic frequency correction for your hardware. >>/etc/ntp.conf
  echo driftfile /var/lib/ntp/drift>>/etc/ntp.conf
  echo wvt2012r2stdco.devdmz.mywebgrocer.com>/etc/ntp/step-tickers
  # Enable the NTPD service
  chkconfig --level 345 ntpd on
  service ntpd start
  # Check our drift
  ntpdate -q wvt2012r2stdco.devdmz.mywebgrocer.com
}

# ================================================================================

config_crontab() {
# REQUIRES USERS TO EXIST FIRST
  echo ''
  echo 'Perforce - Setup contab jobs'
  echo  "# MAILTO=${PERFORCE_ADMINS}">/root/crontab.input.perforce
  echo  '# Example of job definition'>>/root/crontab.input.perforce
  echo  '# .---------------- minute (0 - 59)'>>/root/crontab.input.perforce
  echo  '# |  .------------- hour (0 - 23)'>>/root/crontab.input.perforce
  echo  '# |  |  .---------- day of month (1 - 31)'>>/root/crontab.input.perforce
  echo  '# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...'>>/root/crontab.input.perforce
  echo  '# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat'>>/root/crontab.input.perforce
  echo  '# |  |  |  |  |'>>/root/crontab.input.perforce
  echo  '# *  *  *  *  * user-name command to be executed'>>/root/crontab.input.perforce
  echo  '#':>>/root/crontab.input.perforce
  crontab -u uperforce /root/crontab.input.perforce
  rm -f /root/crontab.input.perforce
}

# ================================================================================

config_env() {
  echo ''
  echo 'Perforce - Configure shell environment...'
  touch /etc/profile.d/environ.sh
  echo export EDITOR=/bin/nano>/etc/profile.d/environ.sh
  echo export VISUAL=/bin/nano>>/etc/profile.d/environ.sh
  echo alias vi=/bin/nano>>/etc/profile.d/environ.sh
  chmod -c +x /etc/profile.d/environ.sh
  #. /etc/profile.d/environ.sh

  # echo "JAVA_HOME=/usr/lib/jvm/java-1.6.0-openjdk-1.6.0.0.x86_64/jre" > /etc/profile.d/javahome.sh
  # echo "export JAVA_HOME" >> /etc/profile.d/javahome.sh
}

# ================================================================================

config_logwatch() {
  echo ''
  echo 'Configure logwatch...'
  # logwatch
  # /etc/logwatch/conf/logwatch.conf						# Local configuration options go here
  # /usr/share/logwatch/default.conf/logwatch.conf		# defaults are here
  # logwatch --service sshd --range=Today
  # Range = yesterday
  # Detail = Low
  # Archives = No
}

# ================================================================================

config_postfix() {
  echo ''
  echo 'Configure postfix...'
  # Setup our mail relay host
  # Change "inet_protocols = all" => "inet_protocols = ipv4"
  sed -i 's/inet_protocols = all/inet_protocols = ipv4/g' /etc/postfix/main.cf
  # change "#relayhost = [gateway.my.domain]"=> "relayhost = smarthost1.mywebgrocer.com"
  sed -i 's/#relayhost = uucphost/relayhost = smarthost1.mywebgrocer.com/g' /etc/postfix/main.cf
  service postfix restart

  # Send the Perforce admin root's email.
  sed -i 's/#root/root/g' /etc/aliases
  sed -i "s/marc/${PERFORCE_ADMINS}/g" /etc/aliases
  # Since cron runs the proxy sync jobs as user up4d, that user will get any mail if there are sync errors etc.
  echo "up4d:       ${PERFORCE_ADMINS}">>/etc/aliases
  # recompile the alias file
  newaliases
}

# ================================================================================

# Call our subroutines

export_vars
install_base
install_nginx
install_htop
install_vmtools
create_users
install_java
config_nginx
config_network
config_firewall
config_etc-services
create_p4_dirs
install_p4
config_p4_initd
config_sshd_banner
config_ntp
config_crontab
config_env
config_logwatch
config_postfix
# Things to do
# p4_logrotate
# 

echo "Perforce installation complete, please configure the system before use."
