import requests
import sys
requests.post ('http://dev.yoonjin2.kr:32000/create', json = {"req": "req"}, auth = (sys.argv[1], sys.argv[2]))
