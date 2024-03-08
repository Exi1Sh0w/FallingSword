"""
@Author: exiashow
@File: appLoader.py
@Date: 2024/2/26 15:08
@Desc: 
@Summary:
"""

from flask import Blueprint, request, render_template
from Poc.app.midware.elasticsearch.es_command_execute import CVE20143120
from Poc.app.midware.elasticsearch.es_code_execute import CVE20151427
from Poc.app.midware.elasticsearch.es_dir_traversal import ElasticSearchDirTraversal
from Poc.app.midware.elasticsearch.es_dir_traversal_2 import ElasticSearchDirTraversal2

from Poc.app.midware.jenkins.jenkins_rce import JenkinsRce
from Poc.app.midware.jenkins.jenkins_api_read_any_file import JenkinsApiReadAnyFile

from Poc.app.midware.redis.redis_sandbox_rce import RedisSandboxRce
from Poc.app.midware.redis.redis_empty_password import RedisEmptyPassword

from Poc.app.framework.Spring.spring_dataBinding_rce import SpringDataBinding_rce
from Poc.app.framework.Spring.spring_spel_code_injection import SpringSpellCodeInjection
from Poc.app.framework.Spring.spring_actuator_api_spel import SpringActuatorApiSpel

from Poc.app.midware.skywalking.skywalking_sql_injection import SkywalkingSQLInjection

from Poc.app.midware.kafka.kafka_clients_jndi_injection import KafkaClients



appLoader = Blueprint('appLoader', __name__)


def all_app_Vuln(target):
    """
    把所有关于app的模块整合在一起方便调用
    :param target:
    :return:
    """
    results = []
    results.append(CVE20143120(target).run())
    results.append(CVE20151427(target).run())
    results.append(ElasticSearchDirTraversal(target).run())
    results.append(ElasticSearchDirTraversal2(target).run())

    results.append(JenkinsRce(target).run())
    results.append(JenkinsApiReadAnyFile(target).run())

    results.append(RedisSandboxRce(target).run())
    results.append(RedisEmptyPassword(target).run())

    results.append(SpringDataBinding_rce(target).run())
    results.append(SpringSpellCodeInjection(target).run())
    results.append(SpringActuatorApiSpel(target).run())

    results.append(SkywalkingSQLInjection(target).run())

    results.append(KafkaClients(target).run())

    return results


@appLoader.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        domain = request.form.get('domain')
        result = all_app_Vuln(domain)
        return render_template('app.html', result=result)
    else:
        return render_template('app.html')
