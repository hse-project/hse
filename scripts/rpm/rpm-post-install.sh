# rpm-post-install.sh
# rpm will execute the contents of this file with /bin/sh
# https://fedoraproject.org/wiki/Packaging:Scriptlets

# add jni lib to cache
/sbin/ldconfig

# create dt.log

PERMS=666
MAXSIZE=10M # When to rotate logs
MINSIZE=9M  # Until when not to rotate logs
ARCHIVE_CNT=100 # Max compressed archive files to maintain at any point in time

conf="# Config to rotate dt.log
/var/log/hse/dt.log{
    create $PERMS
    compress
    notifempty
    rotate $ARCHIVE_CNT
    nomissingok
    weekly
    size $MAXSIZE
    minsize $MINSIZE
    maxage 90
}
"

conf_hse="/etc/logrotate.d/hse"
dtlog="/var/log/hse/dt.log"

# logrotate config
rm -f $conf_hse
printf "$conf" > $conf_hse

# log file
mkdir -p /var/log/hse
touch $dtlog
chmod $PERMS $dtlog

exit 0
