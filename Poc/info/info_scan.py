"""
@Author: exiashow
@File: info_scan.py
@Date: 2024/2/24 15:41
@Desc:
@Summary:
"""

import threading
import requests
import sys

headers = {
    'User-Agent': 'Mozilla/5.0'
}


def scan_path(base_url, path, results):
    """
    检查给定路径是否存在
    :param base_url: 基础URL
    :param path: 要扫描的路径
    :param results: 存储结果的列表
    """
    base_url = base_url + "/" + path
    try:
        conn = requests.get(base_url, headers=headers)
        if conn.status_code == 200:
            results.append(base_url)
    except requests.exceptions.ConnectionError as e:
        pass  # 网络错误时忽略，不做处理


def scan_domain(url):
    """
    使用多线程来启动scan_path函数
    :param url:
    :return:
    """
    results = []

    with open("static/dict.txt", "r") as f:
        threads = []
        for line in f.readlines():
            path = line.strip()
            thread = threading.Thread(target=scan_path, args=(url, path, results))
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()  # 等待所有线程结束

    return results


class infoscan(object):
    def __init__(self, url):
        self.url = url

    def run(self):
        return scan_domain(self.url)


if __name__ == '__main__':
    fallingSword = infoscan(sys.argv[1])
    fallingSword.run()
