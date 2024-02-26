"""
@Author: exiashow
@File: appLoader.py
@Date: 2024/2/26 15:08
@Desc: 
@Module: 
"""

from flask import Blueprint, request, render_template
from Poc.app.midware.elasticsearch.es_command_execute import CVE20143120
from Poc.app.midware.elasticsearch.es_code_execute import CVE20151427

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
    return results


@appLoader.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        domain = request.form.get('domain')
        result = all_app_Vuln(domain)
        return render_template('app.html', result=result)
    else:
        return render_template('app.html')
