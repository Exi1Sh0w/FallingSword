"""
@Author: exiashow
@File: Same_IP.py
@Date: 2024/2/24 10:27
@Desc: 
@Summary:
"""

import requests, json, sys


def research_domain(domain):
    headers = {
        'User-Agent': 'Mozilla/5.0 ('
    }

    url = f'https://api.webscan.cc/?action=query&ip={domain}'
    try:
        conn = requests.get(url, headers=headers)
        json_file = json.loads(conn.content)
        return json_file
    except Exception as e:
        return "[Error]" + str(e)


class Same_IP(object):
    def __init__(self, url):
        self.url = url

    def run(self):
        return research_domain(self.url)


if __name__ == '__main__':
    fallingSword = Same_IP(sys.argv[1])
    fallingSword.run()
