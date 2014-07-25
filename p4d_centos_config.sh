# First start
chown -c -R uperforce:gp4admin /p4/
chown -c -R uperforce:gp4admin /metadata/
chown -c -R uperforce:gp4admin /depotdata/
chown -c -R uperforce:gp4admin /logs/

# Turn Unicode on, will exit immediately
su - uperforce -s /bin/bash -c "/p4/1/bin/p4d -d -A /p4/1/logs/audit.log -J /p4/1/logs/p4d.journal -L /p4/1/logs/p4d.log -p 1667 -r /p4/1/root -xi"
# Start the main server
su - uperforce -s /bin/bash -c "/p4/1/bin/p4d -d -A /p4/1/logs/audit.log -J /p4/1/logs/p4d.journal -L /p4/1/logs/p4d.log -p 1667 -r /p4/1/root"

# Start the broker
su - uperforce -s /bin/bash -c "/p4/1/bin/p4broker -d -c /p4/1/etc/p4broker.conf"

# Start the sidetrack server for p4web
# su - uperforce -s /bin/bash -c "/depotdata/p4/1/bin/p4d -d -A /p4/1/logs/audit.log -J /p4/1/logs/p4d.journal -L /p4/1/logs/p4d.log -p 1667 -r /p4/1/root"

# Start the web server
# su - uperforce -s /bin/bash -c "/depotdata/p4/1/bin/p4web"

# Configure the server

ln -sfn /p4/1/bin/p4 /usr/bin/p4

su uperforce
cd ~

export P4EDITOR=/bin/nano
export P4CHARSET=utf8
export P4USER=p4_superuser

# No p4 users exist initially, need to create one to be superuser
cat <<EOF >/tmp/p4_user
User:   p4_superuser
Email:  pslattery@mywebgrocer.com
FullName:       p4_superuser
EOF
p4 user -f -i </tmp/p4_user

# Set the initial superuser password
p4 passwd -P "MyWebGrocer2013#" p4_superuser

# Must set password for user superuser to continue
p4 login

# Users must use ticket-based authentication
p4 configure set security=3

# Looks like it needs a service restart...

# Requires a password reset after enabling ticket based auth
# p4 passwd -O "MyWebGrocer2013#" -P "MyWebGrocer2014#" p4_superuser
Password change only seems to work from the P4V client ???

# Login with new password
p4 login

# If set to 1, p4 keys requires admin access.
p4 configure set dm.keys.hide=1

# Minimum diskspace required on server root filesystem before server rejects commands.
p4 configure set filesys.P4ROOT.min=100M

# Minimum diskspace required on server journal filesystem before server rejects commands.
p4 configure set filesys.P4JOURNAL.min=100M

# Minimum diskspace required on server log filesystem before server rejects commands.
p4 configure set filesys.P4LOG.min=100M

# Minimum diskspace required for temporary operations before server rejects commands.
p4 configure set filesys.TEMP.min=100M

# Minimum diskspace required for any depot before server rejects commands. (If there is less than filesys.depot.min diskspace available for any one depot, commands are rejected for transactions involving all depots.)
p4 configure set filesys.depot.min=100M

# Proxy - 2: File paths are case-insensitive if server is case-insensitive
p4 configure set lbr.proxy.case=2

# If set, changes default behavior of p4 sync such that if a client workspace begins with this prefix, all sync operations to affected workspaces assume p4 sync -k, and do not alter contents of the workspace.
p4 configure set zerosyncPrefix=zerosync

# Preventing automatic creation of users - new users may only be created by superusers running p4 user
p4 configure set dm.user.noautocreate=2

# Requiring minimum revisions of client software
p4 configure set minClient=2012.1
p4 configure set minClientMessage="Your Perforce client is too old. Please upgrade to Perforce client version r2012.1 or higher"

# If monitoring is enabled, and if this configurable is set to a nonzero value, the service refuses to accept more than this many simultaneous command requests.
# p4 configure set server.maxcommands=10

# Ignore all nonlocal connection requests
# P4PORT=localhost:port

# Enabling process monitoring (including idle processes)
p4 configure set monitor=2

# Command tracing flags (log everything)
# server=3 - In addition to data logged at level 2, adds usage information for compute phases of p4 sync and p4 flush (p4 sync -k) commands.
# http://www.perforce.com/perforce/doc.current/manuals/p4sag/03_superuser.html
p4 configure set server=3

# Centralized management of P4V settings
# http://www.perforce.com/perforce/doc.current/manuals/p4sag/03_superuser.html#1101165
# If Off, the labels tab does not appear.
# p4 property -a -n P4V.Features.Labeling -v Off

# If Off, P4V does not attempt to use the New Connection Wizard.
p4 property -a -n P4V.Features.ConnectionWizard -v Off

# If Off, streams-related icons, menus, and the Stream Graph do not appear.
# p4 property -a -n P4V.Features.Streams -v Off

# Require passwords to be at least 16 characters in length
p4 configure set dm.password.minlength=16

# Delete the default depot named "depot"
p4 depot -d depot

# Create spec depot
echo 'Depot:  p4-spec'>/tmp/p4tmp
echo 'Description: 	Created by p4_superuser.'>>/tmp/p4tmp
echo 'Type:   spec'>>/tmp/p4tmp
echo 'Address:      local'>>/tmp/p4tmp
echo 'Map:    /p4/1/depots/p4-spec/...'>>/tmp/p4tmp
echo 'Suffix:  .p4s'>>/tmp/p4tmp
echo 'SpecMap: //p4-spec/...'>>/tmp/p4tmp
p4 depot -i</tmp/p4tmp
p4 admin updatespecdepot -a

# Create unload depot
echo 'Depot:  p4-unload'>/tmp/p4tmp
echo 'Description: 	Created by p4_superuser.'>>/tmp/p4tmp
echo 'Type:   unload'>>/tmp/p4tmp
echo 'Address:      local'>>/tmp/p4tmp
echo 'Map:    /p4/1/depots/p4-unload/...'>>/tmp/p4tmp
p4 depot -i</tmp/p4tmp

# Create a new depot named "MWG"
echo 'Depot:  MWG'>/tmp/p4tmp
echo 'Description: 	Created by p4_superuser.'>>/tmp/p4tmp
echo 'Type:   local'>>/tmp/p4tmp
echo 'Address:      local'>>/tmp/p4tmp
echo 'Map:    /p4/1/depots/MWG/...'>>/tmp/p4tmp
p4 depot -i</tmp/p4tmp

# Create a new depot named "3rdparty"
echo 'Depot:  3rdparty'>/tmp/p4tmp
echo 'Description: 	Created by p4_superuser.'>>/tmp/p4tmp
echo 'Type:   local'>>/tmp/p4tmp
echo 'Address:      local'>>/tmp/p4tmp
echo 'Map:    /p4/1/depots/3rdparty/...'>>/tmp/p4tmp
p4 depot -i</tmp/p4tmp

# Create the base typemap (need more definitions)
echo 'TypeMap:'>/tmp/p4tmp
echo '  text //....asp'>>/tmp/p4tmp
echo '  binary+F //....avi'>>/tmp/p4tmp
echo '  binary //....bmp'>>/tmp/p4tmp
echo '  binary //....btr'>>/tmp/p4tmp
echo '  text //....cnf'>>/tmp/p4tmp
echo '  text //....css'>>/tmp/p4tmp
echo '  binary //....doc'>>/tmp/p4tmp
echo '  binary //....dot'>>/tmp/p4tmp
echo '  binary+w //....exp'>>/tmp/p4tmp
echo '  binary+F //....gif'>>/tmp/p4tmp
echo '  binary+F //....gz'>>/tmp/p4tmp
echo '  text //....htm'>>/tmp/p4tmp
echo '  text //....html'>>/tmp/p4tmp
echo '  binary //....ico'>>/tmp/p4tmp
echo '  text //....inc'>>/tmp/p4tmp
echo '  text+w //....ini'>>/tmp/p4tmp
echo '  binary //....jpg'>>/tmp/p4tmp
echo '  text //....js'>>/tmp/p4tmp
echo '  binary+w //....lib'>>/tmp/p4tmp
echo '  text+w //....log'>>/tmp/p4tmp
echo '  binary+F //....mpg'>>/tmp/p4tmp
echo '  binary //....pdf'>>/tmp/p4tmp
echo '  text+w //....pdm'>>/tmp/p4tmp
echo '  binary //....ppt'>>/tmp/p4tmp
echo '  binary //....xls'>>/tmp/p4tmp
p4 typemap -i</tmp/p4tmp

# Enable structured logging
p4 configure set serverlog.file.1=/p4/1/logs/all.csv
p4 configure set serverlog.file.2=/p4/1/logs/commands.csv
p4 configure set serverlog.file.3=/p4/1/logs/errors.csv
p4 configure set serverlog.file.4=/p4/1/logs/audit.csv
p4 configure set serverlog.file.5=/p4/1/logs/track.csv
p4 configure set serverlog.file.6=/p4/1/logs/user.csv
p4 configure set serverlog.file.7=/p4/1/logs/events.csv

# Populate P4WEBMIMEFILE
echo '.h text/plain'>/p4/1/etc/P4WEBMIMEFILE
echo '.c text/plain'>>/p4/1/etc/P4WEBMIMEFILE
echo '.C text/plain'>>/p4/1/etc/P4WEBMIMEFILE
echo '.cc text/plain'>>/p4/1/etc/P4WEBMIMEFILE
echo '.cpp text/plain'>>/p4/1/etc/P4WEBMIMEFILE
echo '.java text/plain'>>/p4/1/etc/P4WEBMIMEFILE
echo '.pl text/plain'>>/p4/1/etc/P4WEBMIMEFILE
echo '.py text/plain'>>/p4/1/etc/P4WEBMIMEFILE

# Create a web user
cat <<EOF >/tmp/p4_user
User:   p4_www
Email:  pslattery+p4_www@mywebgrocer.com
FullName:       p4_www
EOF
p4 user -f -i </tmp/p4_user

# p4 passwd -P "MyWebGrocer2013#_www" p4_www
# Had to set password from P4Admin GUI

p4 -u p4_www login


# Start the web server
# su - uperforce -s /bin/bash -c "/p4/1/bin/p4web"

# If started by root, the -U is the Linux user, -u is the p4 user
/p4/1/bin/p4web -w 8080 -b -m /p4/1/etc/P4WEBMIMEFILE -U uperforce -p 1666 -c p4_www -u p4_www -L /p4/1/logs/p4web.log -C utf8 -P "MyWebGrocer2013#_www"

# For Nginx use
# As root user:
/p4/1/bin/p4web -w 8080 -b -m /p4/1/etc/P4WEBMIMEFILE -s sar -U uperforce -p 1666 -c p4_www -u p4_www -L /p4/1/logs/p4web.log -C utf8 -P "MyWebGrocer2013#_www" &



http://perforce.devdmz.mywebgrocer.com:8080/

# Stop p4web
kill -s TERM $(ps aux | grep "/p4/1/bin/p4web" | grep -v grep | awk '{print $2}')

# Stop p4broker
kill -s TERM $(ps aux | grep "/p4/1/bin/p4broker" | grep -v grep | awk '{print $2}')

# Stop p4d
kill -s TERM $(ps aux | grep "/p4/1/bin/p4d" | grep -v grep | awk '{print $2}')

# p4 serverid

# Install Nginx
# http://nginx.org/packages/keys/nginx_signing.key
CENTOS_VERSION=$( cat /etc/*-release | grep release | grep -o "[0-9]" | head -n 1 )
echo "[nginx]">/etc/yum.repos.d/nginx.repo
echo "name=nginx repo">>/etc/yum.repos.d/nginx.repo
echo "baseurl=http://nginx.org/packages/centos/$CENTOS_VERSION/x86_64/">>/etc/yum.repos.d/nginx.repo
echo "enabled=1">>/etc/yum.repos.d/nginx.repo
echo "gpgcheck=0">>/etc/yum.repos.d/nginx.repo
# Verify we can download from the repo
REPO_ACTIVE=$( yum list | grep "nginx" | wc -l )
if [ ${REPO_ACTIVE} -gt 0 ]; then
  log_success_msg "Yum repo [nginx] is available"
  # Install nginx
  yum install -y nginx
  # Check the packages were installed
  PKG_INSTALLED=$( yum list installed|grep "nginx" | wc -l )
  if [ ${PKG_INSTALLED} -gt 0 ]; then
    log_success_msg "Package was installed"
  else
    log_failure_msg "Package was NOT installed"
    # We need the packages installed so exiting if the package was not installed
    exit 1
  fi
else
  log_failure_msg "Yum repo [nginx] is NOT available"
  # We need the packages in the repo so exiting if the repo is not available
  exit 1
fi

# As root user
systemctl start nginx.service
# test in browser
systemctl stop nginx.service

export GITHUB_OAUTH_KEY=8b929a85412a65b53d2707eb8edfcd2c894ecdd5
GH_FILE="https://api.github.com/repos/patrickmslatteryvt/mi-perforce/contents/nginx/nginx.conf"
curl --header "Authorization: token ${GITHUB_OAUTH_KEY}" --header "Accept: application/vnd.github.v3.raw" --location $GH_FILE -o /etc/nginx/nginx.conf
GH_FILE="https://api.github.com/repos/patrickmslatteryvt/mi-perforce/contents/nginx/blockips.conf"
curl --header "Authorization: token ${GITHUB_OAUTH_KEY}" --header "Accept: application/vnd.github.v3.raw" --location $GH_FILE -o /etc/nginx/blockips.conf

sed -i "s/HOSTNAME/perforce.devdmz.mywebgrocer.com/g" /etc/nginx/nginx.conf
grep -i --color perforce.devdmz.mywebgrocer.com /etc/nginx/nginx.conf

IP_ADDRESS=$(ip addr | sed -En 's/127.0.0.1//;s/.*inet (addr:)?(([0-9]*\.){3}[0-9]*).*/\2/p')
sed -i "s/IP_ADDRESS/${IP_ADDRESS}/g" /etc/nginx/nginx.conf
grep -i --color ${IP_ADDRESS} /etc/nginx/nginx.conf

# Fix the user name in the conf file (www in SmartOS, nginx in CentOS 6.x)
sed -i "s@www www;@nginx nginx;@g" /etc/nginx/nginx.conf

# Create a directory for nginx status and error pages.
mkdir -p /srv/www/MWG_images
cp /usr/share/nginx/html/* /srv/www/

# download the static error pages
mkdir -p /srv/www/error
mv /srv/www/50x.html /srv/www/error/50x.html
GH_FILE="https://api.github.com/repos/patrickmslatteryvt/mi-perforce/contents/nginx/403.html"
curl --header "Authorization: token ${GITHUB_OAUTH_KEY}" --header "Accept: application/vnd.github.v3.raw" --location $GH_FILE -o /srv/www/error/403.html
GH_FILE="https://api.github.com/repos/patrickmslatteryvt/mi-perforce/contents/nginx/502.html"
curl --header "Authorization: token ${GITHUB_OAUTH_KEY}" --header "Accept: application/vnd.github.v3.raw" --location $GH_FILE -o /srv/www/error/502.html
GH_FILE="https://api.github.com/repos/patrickmslatteryvt/mi-perforce/contents/nginx/503.html"
curl --header "Authorization: token ${GITHUB_OAUTH_KEY}" --header "Accept: application/vnd.github.v3.raw" --location $GH_FILE -o /srv/www/error/503.html
# Create self signed SSL Cert for HTTPS
GH_FILE="https://api.github.com/repos/patrickmslatteryvt/shell/contents/bash/generateSSLSelfSignCert.sh"
curl --header "Authorization: token ${GITHUB_OAUTH_KEY}" --header "Accept: application/vnd.github.v3.raw" --location $GH_FILE -o ~/generateSSLSelfSignCert.sh
chmod -c +x ~/generateSSLSelfSignCert.sh
~/generateSSLSelfSignCert.sh

# Set security on the keys so that only the root user can read them (but even root cannot write to them)
chown -c -R root:root /etc/ssl/
chmod -c 400 /etc/ssl/certs/*.crt
chmod -c 400 /etc/ssl/private_keys/*.key

systemctl start nginx.service

http://perforce.devdmz.mywebgrocer.com/MWG/kickstarts/ws02gw01.ks