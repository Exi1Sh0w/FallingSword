"""
@Author: exiashow
@File: Subnet_C.py
@Date: 2024/2/24 10:01
@Desc: 
@Module: 
"""
from concurrent.futures import ThreadPoolExecutor
import socket, ipaddress, sys, json, requests
from .Same_IP import research_domain


def scan_ip(ip):
    try:
        return ip, research_domain(ip)
    except Exception as e:
        return ip, None


class subnet():
    def __init__(self, url):
        self.url = url

    def run(self):
        """
        将获取的到的域名转化为IP，然后扩充至这个C段:1-255。最后调用scan_ip模块对每个IP进行扫描
        :param domain:
        :return:
        notes: 这部分的代码与get_webscan_info有点重合了，等结束了再整!
        """
        results = []
        try:
            ip = socket.gethostbyname(self.url)
            network = ipaddress.ip_network(ip + '/24', strict=False)
            with ThreadPoolExecutor() as executor:
                futures = [executor.submit(scan_ip, str(ip_address)) for ip_address in network.hosts()]
                for future in futures:
                    results.append(future.result())
        except Exception as e:
            return "Error" + str(e)
        return results


if __name__ == '__main__':
    testVuln = subnet(sys.argv[1])
    print(testVuln.run())
