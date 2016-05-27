__author__ = 'powergx'
import requests
import random
import json
from util import md5, sha1
from base64 import b64encode
from urllib.parse import unquote, urlencode
import hashlib


def StrToInt(str):
    bigInteger = 0

    for char in str:
        bigInteger <<= 8
        bigInteger += ord(char)

    return bigInteger


def pow_mod(x, y, z):
    "Calculate (x ** y) % z efficiently."
    number = 1
    while y:
        if y & 1:
            number = number * x % z
        y >>= 1
        x = x * x % z
    return number


def old_login(username, md5_password):
    from api import agent_header
    exponent = int("010001", 16)
    modulus = int("AC69F5CCC8BDE47CD3D371603748378C9CFAD2938A6B021E0E191013975AD683F5CBF9ADE8BD7D46B4D2EC2D78A"
                  "F146F1DD2D50DC51446BB8880B8CE88D476694DFC60594393BEEFAA16F5DBCEBE22F89D640F5336E42F587DC4AF"
                  "EDEFEAC36CF007009CCCE5C1ACB4FF06FBA69802A8085C2C54BADD0597FC83E6870F1E36FD", 16)

    param = '{"cmdID":1,"isCompressed":0,"rsaKey":{"n":"AC69F5CCC8BDE47CD3D371603748378C9CFAD2938A6B0' \
            '21E0E191013975AD683F5CBF9ADE8BD7D46B4D2EC2D78AF146F1DD2D50DC51446BB8880B8CE88D476694DFC60594393BEEFAA16F' \
            '5DBCEBE22F89D640F5336E42F587DC4AFEDEFEAC36CF007009CCCE5C1ACB4FF06FBA69802A8085C2C54BADD0597FC83E6870F1E3' \
            '6FD","e":"010001"},"businessType":%s,"passWord":"%s","loginType":0,"sdkVersion":177588,' \
            '"appName":"ANDROID-com.xunlei.redcrystalandroid","platformVersion":1,"devicesign":"%s",' \
            '"sessionID":"","protocolVersion":%s,"userName":"%s","extensionList":"","sequenceNo":%s,' \
            '"peerID":"","clientVersion":"1.0.0"}'

    _chars = "0123456789ABCDEF"

    deviceid = username
    device_id = md5(deviceid)

    appName = 'com.xunlei.redcrystalandroid'
    businessType = '61'
    key = 'C2049664-1E4A-4E1C-A475-977F0E207C9C'
    key_md5 = md5(key)

    device_sign = "div100.%s%s" % (device_id, md5(sha1("%s%s%s%s" % (device_id, appName, businessType, key_md5))))

    hash_password = hex(pow_mod(StrToInt(md5_password), exponent, modulus))[2:].upper().zfill(256)

    params = param % (61, hash_password, device_sign, 108, username, 1000006)

    r = requests.post("https://login.mobile.reg2t.sandai.net/", data=params, headers=agent_header, verify=False)
    login_status = json.loads(r.text)

    return login_status

def login(username, md5_password, encrypt_pwd_url=None):
    if encrypt_pwd_url is None or encrypt_pwd_url == '':
        return old_login(username, md5_password)

    xunlei_domain = 'login.xunlei.com'
    s = requests.Session()
    r = s.get('http://%s/check/?u=%s&v=100' % (xunlei_domain, username))
    if r.cookies.get('check_n') is None:
        xunlei_domain = 'login2.xunlei.com'
        r = s.get('http://%s/check/?u=%s&v=100' % (xunlei_domain, username))

    if r.cookies.get('check_n') is None:
        return old_login(username, md5_password)
    check_n = unquote(r.cookies.get('check_n'))
    check_e = unquote(r.cookies.get('check_e'))
    check_result = unquote(r.cookies.get('check_result'))

    need_captcha = check_result.split(':')[0]
    if need_captcha == '1':
        return old_login(username, md5_password)
    captcha = check_result.split(':')[1].upper()

    params = dict(password=md5_password, captcha=captcha, check_n=check_n, check_e=check_e)
    urlencode(params)
    r = requests.get(encrypt_pwd_url + '?' + urlencode(params))
    e_pwd = r.text
    if r.text == 'false':
        return old_login(username, md5_password)

    data = dict(business_type='100', login_enable='0', verifycode=captcha, v='100', e=check_e, n=check_n, u=username,
                p=e_pwd)
    r = s.post('http://%s/sec2login/' % xunlei_domain, data=data)

    cookies = r.cookies.get_dict()
    if len(cookies) < 5:
        return old_login(username, md5_password)

    return dict(errorCode=0, sessionID=cookies.get('sessionid'), nickName=cookies.get('usernick'),
                userName=cookies.get('usrname'), userID=cookies.get('userid'), userNewNo=cookies.get('usernewno'))
