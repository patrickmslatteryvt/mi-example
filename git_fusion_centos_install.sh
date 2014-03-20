#!/usr/bin/env bash

# TODO: compile P4Python with SSL support

set -e

echo ''
echo 'This script will install the requirements for Git Fusion. It will:'
echo '  * Download, build, and install Git 1.8.2.3 and its build dependencies'
echo '  * Download, build, and install Python 3.3.2, P4Python, the P4API, and the p4 command line'
echo '  * Download, build, and install libgit2 and pygit2'
echo '  * Install the Git Fusion scripts'
echo '  * Optionally, create a user account for Git'
echo ''
echo 'To install Git Fusion you will need to have Perforce super user access and you will need'
echo 'to be able to install triggers on the Perforce server machine itself. This script will'
echo 'only install software to this machine. We will detail the trigger installation process'
echo 'after Git Fusion is configured locally.'
echo ''
echo "Do you wish to continue?"
select yn in "Yes" "No"; do
    case $yn in
        Yes ) break;;
        No ) exit;;
    esac
done

echo 'Grabbing build tools...'
sudo yum -y groupinstall "Development Tools"
sudo yum -y install cpan
sudo yum -y install perl-ExtUtils-CBuilder perl-ExtUtils-MakeMaker perl-Time-HiRes
sudo yum -y install openssl-devel cpio expat-devel gettext-devel
sudo yum -y install bzip2-devel gdbm-devel readline-devel sqlite-devel

echo 'Grabbing the required version of Git and its build dependencies...'
wget http://git-core.googlecode.com/files/git-1.8.2.3.tar.gz

echo Building Git...
tar xvzf git-1.8.2.3.tar.gz
cd git-1.8.2.3
autoconf
./configure
make
make test || :
sudo make install
cd ..

echo 'Grabbing the required versions of Python, P4Python, and the P4API...'
wget http://www.python.org/ftp/python/3.3.2/Python-3.3.2.tar.bz2
tar -xjf Python-3.3.2.tar.bz2 
cd Python-3.3.2
./configure
make 
sudo make install
cd ..

wget http://ftp.perforce.com/perforce/r13.1/bin.tools/p4python.tgz
wget http://ftp.perforce.com/perforce/r13.1/bin.linux26x86_64/p4api.tgz
wget http://ftp.perforce.com/perforce/r13.1/bin.linux26x86_64/p4
wget http://ftp.perforce.com/perforce/r13.1/bin.linux26x86_64/p4d

echo 'Building P4Python...'
tar xvzf p4python.tgz 
tar xvzf p4api.tgz
chmod +x p4 p4d
sudo cp p4 /usr/local/bin/p4
mv p4 p4python-*
mv p4d p4python-*
cd p4python-*
export PATH=.:$PATH
/usr/local/bin/python3 setup.py build --apidir ../p4api-2013.1.*/

sudo /usr/local/bin/python3 setup.py install --apidir ../p4api-2013.1.*/

echo 'Testing the installation...'
echo import P4 > p4python_version_check.py
echo 'print(P4.P4.identify())' >> p4python_version_check.py
/usr/local/bin/python3 p4python_version_check.py
cd ..

echo "Grabbing libgit2, pygit, and their dependencies..."
wget http://www.cmake.org/files/v2.8/cmake-2.8.3.tar.gz
tar xzf cmake-2.8.3.tar.gz
cd cmake-2.8.3
./configure
make
sudo make install
cd ..

git clone git://github.com/libgit2/libgit2.git
cd libgit2
git checkout v0.18.0 
mkdir -p build
cd build
cmake -DBUILD_CLAR=off ..
cmake --build .
sudo /usr/local/bin/cmake --build . --target install
cd ../..

git clone git://github.com/libgit2/pygit2.git
cd pygit2
git checkout v0.18.0 
export LIBGIT2="/usr/local"
export LDFLAGS="-Wl,-rpath='$LIBGIT2/lib',--enable-new-dtags $LDFLAGS"
python3 setup.py build
sudo /usr/local/bin/python3 setup.py install
/usr/local/bin/python3 setup.py test
cd ..

echo ""
read -e -p "What directory should the Git Fusion scripts be installed to? " -i "/usr/local/git-fusion/bin" FILEPATH

sudo mkdir -p $FILEPATH
sudo cp *.py $FILEPATH
sudo cp *.txt $FILEPATH
sudo cp Version $FILEPATH
echo "Git Fusion installed to $FILEPATH"
echo ""

echo "Do you wish to create a user account for Git? This will be the account your users use when connecting to Git."
echo "For example: git clone <user account name>@$HOSTNAME:repo"
echo "If you choose not to create a user for Git, your current username will be used."
select yn in "Yes" "No"; do
    case $yn in
        Yes ) read -e -p "Account name? " -i "git" ACCOUNTNAME
              echo "Creating git user account $ACCOUNTNAME..."; 
              sudo adduser $ACCOUNTNAME; 
              sudo passwd $ACCOUNTNAME;
              break;;
        No ) ACCOUNTNAME="$USER"; break;;
    esac
done

echo ''
echo 'Enabling logging to the system log...'
sudo cp git-fusion.log.conf /etc/git-fusion.log.conf
echo ':syslogtag,contains,"git-fusion[" -/var/log/git-fusion.log' > /tmp/out
echo ':syslogtag,contains,"git-fusion-auth[" -/var/log/git-fusion-auth.log' >> /tmp/out
sudo mkdir -p /etc/rsyslog.d
sudo cp /tmp/out /etc/rsyslog.d/git-fusion.conf
echo "/var/log/git-fusion-auth.log" | cat -  /etc/logrotate.d/syslog  > /tmp/out && sudo cp /tmp/out /etc/logrotate.d/syslog
echo "/var/log/git-fusion.log" | cat -  /etc/logrotate.d/syslog  > /tmp/out && sudo cp /tmp/out /etc/logrotate.d/syslog
sudo service rsyslog restart

echo ""
echo "===================================================================================="
echo 'Automated install complete! Now a few final bits to do manually.'
echo "===================================================================================="
echo ''
echo "Add the following export lines to the top of the $ACCOUNTNAME .bashrc (/home/$ACCOUNTNAME/.bashrc)"
echo ''
echo "export PATH=$FILEPATH"':$PATH'
echo 'export P4USER=git-fusion-user'
echo 'export P4PORT=<your Perforce port>'
echo ''
echo 'After updating your .bashrc file run:'
echo ''
echo "source /home/$ACCOUNTNAME/.bashrc"
echo 'p4 -u <Perforce super user account> login'
echo 'p4gf_super_init.py --user <Perforce super user account>'
echo ''
echo 'Make sure to set a password for git-fusion-user and run p4 login as git-fusion-user to setup a ticket'
echo ''
echo 'Git Fusion requires a trigger to be installed on your Perforce server to '
echo 'properly support atomic checkins in Git. To install the trigger:'
echo ''
echo '1) Copy "p4gf_submit_trigger_26.py" to your Perforce server machine'
echo '2) As a Perforce super user run "p4 triggers" and add the following entries:'
echo 'GF-pre-submit change-submit //depot/... "/path/to/python /path/to/p4gf_submit_trigger_26.py change-submit %change% %user% %serverport%"'
echo 'GF-post-submit change-commit //depot/... "/path/to/python /path/to/p4gf_submit_trigger_26.py change-commit %change% %user% %serverport%"'
echo 'GF-chg-submit change-content //depot/... "/path/to/python /path/to/p4gf_submit_trigger_26.py change-content %change% %user% %serverport%"'
echo ''
echo 'You will need to add triggers as above for each depot where you want to enable Git Fusion.'
echo 'The final step is to setup the version counter by running the following commands from the Perforce server'
echo ''
echo 'p4 -u git-fusion-user login'
echo 'python p4gf_submit_trigger_26.py --set-version-counter <your server port>'
echo ''
echo 'If your server runs in Unicode mode, you will need to make a slight change to the trigger script:'
echo 'For unicode servers uncomment the following line'
echo "#CHARSET = ['-C', 'utf8']"
echo ''
echo 'You will need to add a cronjob to check for and install new SSH keys.'
echo "Add the following lines to cron as user $ACCOUNTNAME:"
echo ''
echo 'PATH = /usr/local/git-fusion/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
echo '# update auth keys EVERY MINUTE '
echo '*   *  *   *   *     bash -i -c p4gf_auth_update_authorized_keys.py'
echo ''
echo 'Now either add user keys and/or run the following to create a repository'
echo 'p4gf_init_repo.py'

if [ $ACCOUNTNAME != $USER ]
	then
      echo 'Switching you to the new user account for Git Fusion...'
      echo 'Done'
      sudo su - $ACCOUNTNAME
fi
