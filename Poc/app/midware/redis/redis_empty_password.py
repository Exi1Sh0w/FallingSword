"""
@Author: exiashow
@File: redis_empty_password.py
@Date: 2024/3/6 16:31
@Desc: redis empty password
@Summary:  After being connected by the attacker, the code will be executed to obtain permissions.
"""

import redis
import sys
from urllib.parse import urlparse


def extract_domain(url):
    """
    Extract the domain name of the URL
    """
    parsed_url = urlparse(url)
    if parsed_url.hostname:
        return parsed_url.hostname
    else:
        return None
class RedisEmptyPassword(object):
    def __init__(self, url):
        self.url = url

    def run(self):
        target_host = extract_domain(self.url)
        target_port = 6379

        try:
            r = redis.Redis(host=target_host, port=target_port)
            if "redis_version" in r.info():
                return "[Warning] Redis vulnerability discovered: Empty Password "
            else:
                return None
        except redis.exceptions.ResponseError:
            pass

if __name__ == '__main__':
    fallingSword = RedisEmptyPassword(sys.argv[1])
    print(fallingSword.run())
