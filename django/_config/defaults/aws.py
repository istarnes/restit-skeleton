AWS_KEY = 'XXXX'
AWS_SECRET = 'XXXX'

AWS_ADMIN_KEY = AWS_KEY
AWS_ADMIN_SECRET = AWS_SECRET

AWS_ACCESS_KEY_ID = AWS_KEY
AWS_SECRET_ACCESS_KEY = AWS_SECRET

AWS_EC2_KEY = AWS_KEY
AWS_EC2_SECRET = AWS_SECRET

AWS_REGION = "us-west-2"

AWS_S3_BUCKET = "restit"
MEDIALIB_DEFAULT_STORE = 's3://{0}'.format(AWS_S3_BUCKET)
MEDIALIB_STORE = {
    1: '{0}/store'.format(MEDIALIB_DEFAULT_STORE),
}

RENDER_INSTANCE_RATIO = 3
RENDER_IMAGE_TYPE = 'c1.medium'
RENDER_AMI = 'ami-c21645aa'
RENDER_SECURITY_GROUPS=['webserver']
# number of seconds the image should remain alive for
RENDER_INSTANCE_ALIVE = 14400
# number of seconds to kill after idle
RENDER_INSTANCE_IDLE = 1800

RENDER_AWS_BUCKET = AWS_S3_BUCKET
RENDER_IMAGE_NAME = "xxxx"
ZIP_PASSWORD = ""
RENDER_USER_DATA = """#!/bin/sh
/etc/init.d/network restart
cd /opt/
rm -rf /opt/xxxx
rm -rf /opt/xxxx.zip
wget https://s3.amazonaws.com/{0}/archive/{3}.zip
unzip -qq -P {4} {3}.zip
echo "from _config._renderer import *" > /opt/{3}/django/settings.py
/opt/{3}/bin/do_render.py -r -i {1} -m {2} -u root
""".format(RENDER_AWS_BUCKET, RENDER_INSTANCE_ALIVE, RENDER_INSTANCE_IDLE, RENDER_IMAGE_NAME, ZIP_PASSWORD)

CLOUDFRONT_MIRRORS = {
    MEDIALIB_DEFAULT_STORE: {
        "url": "http://cdn.xxxx.io",
        "url_secure": "https://cdn.xxxx.io",
        "no_sign": ('jpg', ),
    }
}

# filter videos by browser locale
VIDEOS_FILTER_BY_LOCALE = False
# filter videos that have been rendered
VIDEOS_FILTER_READY = True

YOUTUBE_DESCRIPTION = """I made this with {0} app http://{0}/getapp""".format("xxxx.io")
