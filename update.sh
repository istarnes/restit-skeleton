#!/bin/bash

cd `dirname $0`

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$BRANCH" != "$1" ]]; then
  echo 'wrong branch $1' >> var/update.log;
  exit 1;
fi

SCRIPTPATH=`pwd -P`
PROD_PATH=/opt/proj_name
STAGE_PATH=/opt/stage.proj_name

echo '------- start update --------'
echo `date` >> var/update.log

# random delays to prevent all servers updating same time
if [[ "$BRANCH" != "develop" && "$BRANCH" != "r1" ]]; then
  sleep $[ ( $RANDOM % 60 )  + 1 ]s
fi

echo "fetching latest code..." >> var/update.log
git reset --hard
echo "reseting local to remote..." >> var/update.log
git pull

./post_update.sh $BRANCH

echo `date`

echo '------- end update --------' >> var/update.log
