# -*- coding:utf-8 -*-

import hashlib
import base64
import time
import urllib.request, sys, re, os, json
from pyDes import *

url = "http://identify-auth.zztfly.com/auth/auth/sdkClientFreeLogin"

appkey = ""
appSecret = ""
token = "59616292321333248"
opToken = "opToken"
operator = "CUCC"
md5 = ""

class NoExceptionCookieProcesser(urllib.request.HTTPCookieProcessor):
    def http_error_403(self, req, fp, code, msg, hdrs):
        return fp
    def http_error_400(self, req, fp, code, msg, hdrs):
        return fp
    def http_error_404(self, req, fp, code, msg, hdrs):
        return fp
    def http_error_500(self, req, fp, code, msg, hdrs):
        return fp

def generateSign(request, secret):
    if type(request) != dict or type(secret) != str:
        raise Exception("type error")
    ret = ""
    stmp = sorted(request.items(), key=lambda d: d[0])
    for i in stmp:
        ret += i[0] + "=" + str(i[1]) + "&"
    print(ret[:-1])
    return hashlib.md5((ret[:-1] + secret).encode('utf-8')).hexdigest()

def getPhone():
    opener = urllib.request.build_opener(NoExceptionCookieProcesser())
    method = urllib.request.Request(url)
    method.add_header('Content-Type', 'application/json')

    data = {
        'appkey': appkey,
        'token': token,
        'opToken': opToken,
        'operator': operator,
        'timestamp': int(time.time()*1000)
    }
    if md5 != "":
        data['md5'] = md5
    data['sign'] = generateSign(data, appSecret)

    result = None;
    try:
        result = opener.open(method, json.dumps(data).encode('utf-8'), timeout=100)
    except Exception as err:
        print(err)


    data = result.read()
    ret = json.loads(data)

    if ret['status'] == 200:
        k = des(appSecret[:8], CBC, "00000000", pad=None, padmode=PAD_PKCS5)
        ret['res'] = k.decrypt(base64.b64decode(ret['res']))

    return data

if __name__ == "__main__":
    print(getPhone())