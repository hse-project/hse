# rpm-post-install.sh
# rpm will execute the contents of this file with /bin/sh
# https://fedoraproject.org/wiki/Packaging:Scriptlets

# add jni lib to cache
/sbin/ldconfig

# log file
mkdir -p /var/log/hse

exit 0
