#!/bin/bash

cd `dirname $0`
BRANCH=$1
echo "------- start post update branch: $BRANCH --------" >> var/update.log

# echo "cron update"
# sudo cp -rvf cron.d/* /etc/cron.d/

grep VERSION /etc/ossec-init.conf | cut -d'"' -f 2 > var/ossec.version

# only migrate if develop or
echo "**** start migration ****" >> var/update.log
./django/manage.py migrate >> var/update.log
echo "**** end migration ***" >> var/update.log

echo '------- end post update --------' >> var/update.log

VERSION=`cat django/version.py | grep -v VERSION | tr '\n' ' '`
echo "version now: $VERSION" >> var/update.log

wall "updated to $VERSION"
