"""
@Author: exiashow
@File: Domain_research.py
@Date: 2024/2/23 15:22
@Desc:
@Summary:
"""
import sys
from bs4 import BeautifulSoup
import requests


class DomainResearch(object):
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "Host": "dnsdumpster.com",
            "Cookie": "csrftoken=M8OfHWWLB1dYk6YGoSIAp9EtHqDJ5fkTfuMn20k0yF9LL3xrW28qG7AdQKdB0VGf; _ga_FPGN9YXFNE=GS1.1.1708683994.1.0.1708684005.0.0.0; _ga=GA1.1.1757802606.1708683995",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://dnsdumpster.com",
            "Dnt": "1",
            "Sec-Gpc": "1",
            "Referer": "https://dnsdumpster.com/",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-User": "?1",
            "Te": "trailers",
        }

        # 定义请求数据
        data = {
            "csrfmiddlewaretoken": "wKnvGNlKv2ROVihOw3SmJ3XyvSVKlXZHZ6lD1RJZsGNBmfQz4dic01TiEcvCgDl3",
            "targetip": self.url,
            "user": "free",
        }
        response = requests.post("https://dnsdumpster.com/", headers=headers, data=data)
        try:
            if response.status_code == 200:

                # 解析 HTML 内容
                soup = BeautifulSoup(response.content, "lxml")

                # 找到第四个 class 为 "table-responsive" 的 div
                div = soup.find_all("div", class_="table-responsive")[3]

                # 提取 div 中的所有内容
                results = []
                for row in div.find_all("tr"):
                    # 找到二级域名
                    domain_name = row.find("td", class_="col-md-4")
                    if domain_name:
                        # 找到IP
                        ip = row.find("td", class_="col-md-3")
                        if ip:
                            results.append({
                                "domain_name": domain_name.text.strip(),
                                "ip": ip.text.strip(),
                            })
                return results
        except Exception as e:
            return "[Error] " + str(e)


if __name__ == '__main__':
    fallingSword = DomainResearch(sys.argv[1])
    fallingSword.run()
