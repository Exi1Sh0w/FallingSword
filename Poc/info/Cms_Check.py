"""
@Author: exiashow
@File: Cms_Check.py
@Date: 2024/2/24 18:50
@Desc: 
@Module: 
"""

import requests, sys, json

headers = {
    'user-agent': 'Mozilla/5.0 (Windows NT 10'
}
def detect_cms(url, cms_fingerprints):
    """
    检测用户输入的应用是什么CMS
    :param url:
    :param cms_fingerprints:
    :return:
    """
    if "http://" or "https://" not in url:
        url = "http://" + url
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            for fingerprint in cms_fingerprints:
                method = fingerprint.get('method', 'keyword')
                location = fingerprint.get('location', 'body')
                keywords = fingerprint.get('keyword', [])

                content = response.text if location == 'body' else response.headers
                if method == 'keyword':
                    for keyword in keywords:
                        if keyword in content:
                            return fingerprint['cms']
                # 可以添加其他检测方法，比如正则表达式匹配等
            return "Unknown CMS"
        else:
            return "Failed to retrieve content. Status code: {}".format(response.status_code)
    except requests.exceptions.RequestException as e:
        return "Error: {}".format(e)


class CMSCheck(object):
    def __init__(self, url):
        self.url = url

    def run(self):
        with open('static/cms.json', 'r') as f:
            cms_fingerprints = json.load(f)["fingerprint"]
            cms = detect_cms(self.url, cms_fingerprints)
        return cms


if __name__ == '__main__':
    testVuln = CMSCheck(sys.argv[1])
    print(testVuln.run())
