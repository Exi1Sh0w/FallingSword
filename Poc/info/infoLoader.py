"""
@Author: exiashow
@File: infoLoader.py
@Date: 2024/2/23 10:39
@Desc:
@Summary:
"""

from flask import Blueprint, request, render_template
from Poc.info.info_scan import infoscan
from Poc.info.Domain_research import DomainResearch
from Poc.info.Same_IP import Same_IP
from Poc.info.Subnet_C import subnet
from Poc.info.Cms_Check import CMSCheck

infoLoader = Blueprint('infoLoader', __name__)


@infoLoader.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        domain = request.form.get('domain')
        file = infoscan(domain).run()
        cms = CMSCheck(domain).run()
        return render_template('info.html', file=file, cms=cms)
    else:
        return render_template('info.html')


@infoLoader.route('/domainresearch', methods=['GET', 'POST'])
def domain_research():
    if request.method == 'POST':
        domain = request.form.get('domain')
        secondary_domain = DomainResearch(domain).run()
        return render_template('domain_research.html', secondary_domain=secondary_domain)
    else:
        return render_template('domain_research.html')


@infoLoader.route('/sameip', methods=['GET', 'POST'])
def sameip():
    if request.method == 'POST':
        domain = request.form.get('domain')
        same_ip = Same_IP(domain).run()
        return render_template('same_ip.html', same_ip=same_ip)
    else:
        return render_template('same_ip.html')


@infoLoader.route('/subnet', methods=['GET', 'POST'])
def subnet_info():
    if request.method == 'POST':
        domain = request.form.get('domain')
        data = subnet(domain).run()
        formatted_data = []
        for ip, domains_and_titles in data:
            if not domains_and_titles:
                continue  # Skip empty data entries
            formatted_data.append(
                {"ip": ip, "domains": [domain_and_title["domain"] for domain_and_title in domains_and_titles],
                 "titles": [domain_and_title["title"] for domain_and_title in domains_and_titles]})
        return render_template('subnet.html', data=formatted_data)
    else:
        return render_template('subnet.html')
