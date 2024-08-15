import requests
import sys
requests.post ('http://dev.yoonjin2.kr:32000/create', json = {"username": sys.argv[1], "password": sys.argv[2], "tag": "dummy", "serverip": "dummy", "serverport": "27020"}, auth = (sys.argv[1], sys.argv[2]))
