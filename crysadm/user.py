__author__ = 'powergx'
from flask import request, Response, render_template, session, url_for, redirect
from crysadm import app, r_session
from auth import requires_admin, requires_auth
import json
from util import hash_password
import uuid
import re
import random
import base64
from datetime import datetime, timedelta


@app.route('/user/login', methods=['POST'])
def user_login():
    username = request.values.get('username')
    password = request.values.get('password')

    hashed_password = hash_password(password)

    user_info = r_session.get('%s:%s' % ('user', username))
    if user_info is None:
        session['error_message'] = '用户不存在'
        return redirect(url_for('login'))

    user = json.loads(user_info.decode('utf-8'))

    if user.get('password') != hashed_password:
        session['error_message'] = '密码错误'
        return redirect(url_for('login'))

    if not user.get('active'):
        session['error_message'] = '您的账号已被禁用.'
        return redirect(url_for('login'))

    if user.get('log_as_body') is not None:
        if len(user.get('log_as_body')) > 0:
            r_session.set('%s:%s' % ('record', username), json.dumps(dict(diary=user.get('log_as_body')))) # 创建新通道,转移原本日记
            user['log_as_body'] = []

    user['login_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S') # 记录登陆时间
    r_session.set('%s:%s' % ('user', username), json.dumps(user)) # 修正数据

    if r_session.get('%s:%s' % ('record', username)) is None:
        r_session.set('%s:%s' % ('record', username), json.dumps(dict(diary=[]))) # 创建缺失的日记

    session['user_info'] = user

    guest_diary(request, username)

    return redirect(url_for('dashboard'))


@app.route('/login')
def login():
    if session.get('user_info') is not None:
        return redirect(url_for('dashboard'))

    err_msg = None
    if session.get('error_message') is not None:
        err_msg = session.get('error_message')
        session['error_message'] = None

    return render_template('login.html', err_msg=err_msg)


@app.route('/invitations')
def public_invitation():
    if session.get('user_info') is not None:
        return redirect(url_for('dashboard'))

    err_msg = None
    if session.get('error_message') is not None:
        err_msg = session.get('error_message')
        session['error_message'] = None

    inv_code = None
    if session.get('invitation_code') is not None:
        inv_code = session.get('invitation_code')
        session['invitation_code'] = None

    HTTP_X_REAL_IP = request.environ.get('HTTP_X_REAL_IP')

    return render_template('public_invitation.html', err_msg=err_msg, inv_code=inv_code, ip=HTTP_X_REAL_IP)


@app.route('/inv_codes', methods=['POST'])
def public_inv_code():

    public_key = 'invitation'
    if r_session.get(public_key) is None:
        r_session.set(public_key, json.dumps(dict(diary=[])))
    public_info = json.loads(r_session.get(public_key).decode('utf-8'))

    HTTP_X_REAL_IP = request.environ.get('HTTP_X_REAL_IP')
    for public_code in public_info.get('diary'):
        if HTTP_X_REAL_IP == public_code.get('ip'):
            session['error_message'] = '您已经获取过邀请码了,请勿重复获取.'
            session['invitation_code'] = public_code.get('inv_code')
            return redirect(url_for('public_invitation'))

    inv_codes = r_session.smembers('public_invitation_codes')
    if not inv_codes:
        session['error_message'] = '暂时没有可用的邀请码,请稍后再试.'
        return redirect(url_for('public_invitation'))

    for code in inv_codes: continue
    invitation_code = code.decode('utf-8')

    public_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    body = dict(time=public_time, inv_code=invitation_code, ip=HTTP_X_REAL_IP)

    public_body = public_info.get('diary')
    public_body.append(body)

    public_info['diary'] = public_body

    r_session.set(public_key, json.dumps(public_info))

    return render_template('register.html', invitation_code=invitation_code)


@app.route('/user/logout')
@requires_auth
def logout():
    if session.get('admin_user_info') is not None:
        session['user_info'] = session.get('admin_user_info')
        del session['admin_user_info']
        return redirect(url_for('admin_user'))

    user = session.get('user_info')
    guest_diary(request, user.get('username'))

    session.clear()
    return redirect(url_for('login'))
    
type_dict = {'0':'','1':'收取','2':'宝箱','3':'转盘','4':'进攻','5':'复仇','6':'提现','7':'状态'}
@app.route('/log')
@requires_auth
def user_log():
    log_as = []
    user = session.get('user_info')
    if request.args.get('time') is not None:
        session['log_sel_time']=request.args.get('time')
    if request.args.get('type') is not None:
        session['log_sel_type']=request.args.get('type')

    record_key = '%s:%s' % ('record', user.get('username'))
    record_info = json.loads(r_session.get(record_key).decode('utf-8'))

    user_key = '%s:%s' % ('user', user.get('username'))
    user_info = json.loads(r_session.get(user_key).decode('utf-8'))

    accounts_key = 'accounts:%s' % user.get('username')
    id_map = {}

    for acct in sorted(r_session.smembers(accounts_key)):
        account_key = 'account:%s:%s' % (user.get('username'), acct.decode("utf-8"))
        account_info = json.loads(r_session.get(account_key).decode("utf-8"))
        if user_info.get('is_show_byname') != True:
            id_map[account_info.get('user_id')]=account_info.get('username')
        else:
            id_map[account_info.get('user_id')]=account_info.get('account_name')
    for row in record_info.get('diary'):
        row['id']=id_map.get(row['id'])
        if '1day' == session.get('log_sel_time'):
            if (datetime.now().date() - datetime.strptime(row.get('time'), '%Y-%m-%d %H:%M:%S').date()).days < 1:
                if row.get('type').find(str(type_dict.get(session.get('log_sel_type'))))!=-1:
                    log_as.append(row)
        elif 'all' == session.get('log_sel_time'):
            if row.get('type').find(str(type_dict.get(session.get('log_sel_type'))))!=-1: log_as.append(row)
        else:
            if (datetime.now().date() - datetime.strptime(row.get('time'), '%Y-%m-%d %H:%M:%S').date()).days < 7:
                if row.get('type').find(str(type_dict.get(session.get('log_sel_type'))))!=-1: log_as.append(row)


    log_as.reverse()

    return render_template('log.html', log_user=log_as)


@app.route('/log/delete_sel')
@requires_auth
def user_log_delete_sel():
    user = session.get('user_info')

    record_key = '%s:%s' % ('record', user.get('username'))
    record_info = json.loads(r_session.get(record_key).decode('utf-8'))

    diary = []

    for row in record_info.get('diary'):
        if '1day' == session.get('log_sel_time'):
            if (datetime.now() - datetime.strptime(row.get('time'), '%Y-%m-%d %H:%M:%S')).days >= 1:
                diary.append(row)
            else:
                if row.get('type').find(str(type_dict.get(session.get('log_sel_type')))) == -1:
                    diary.append(row)
        elif 'all' == session.get('log_sel_time'):
            if row.get('type').find(str(type_dict.get(session.get('log_sel_type')))) == -1: diary.append(row)
        else:
            if (datetime.now() - datetime.strptime(row.get('time'), '%Y-%m-%d %H:%M:%S')).days >= 7:
                diary.append(row)
            else:
                if row.get('type').find(str(type_dict.get(session.get('log_sel_type')))) == -1: diary.append(row)

    record_info['diary'] = diary

    r_session.set(record_key, json.dumps(record_info))

    return redirect('/log')


@app.route('/log/delete')
@requires_auth
def user_log_delete():
    user = session.get('user_info')

    record_key = '%s:%s' % ('record', user.get('username'))
    record_info = json.loads(r_session.get(record_key).decode('utf-8'))

    record_info['diary'] = []

    r_session.set(record_key, json.dumps(record_info))

    return redirect('/log')


def guest_diary(request, username):

    guest_key = 'guest'
    if r_session.get(guest_key) is None:
        r_session.set(guest_key, json.dumps(dict(diary=[])))
    guest_info = json.loads(r_session.get(guest_key).decode('utf-8'))

    guest_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S') #时间

    url_scheme = request.environ.get('wsgi.url_scheme') #请求头
    HTTP_HOST = request.environ.get('HTTP_HOST') #地址
    PATH_INFO = request.environ.get('PATH_INFO') #后缀
    REQUEST_METHOD = request.environ.get('REQUEST_METHOD') #方式
    HTTP_X_REAL_IP = request.environ.get('HTTP_X_REAL_IP') #IP
    REMOTE_PORT = request.environ.get('REMOTE_PORT') #端口

    http = '%s://%s%s' % (url_scheme, HTTP_HOST, PATH_INFO) #链接

    body = dict(time=guest_time, http=http, method=REQUEST_METHOD, ip=HTTP_X_REAL_IP, port=REMOTE_PORT, username=username)

    guest_body = guest_info.get('diary')
    guest_body.append(body)

    guest_info['diary'] = guest_body

    r_session.set(guest_key, json.dumps(guest_info))


@app.route('/user/profile')
@requires_auth
def user_profile():
    user = session.get('user_info')

    user_key = '%s:%s' % ('user', user.get('username'))
    user_info = json.loads(r_session.get(user_key).decode('utf-8'))

    config_key = '%s:%s' % ('user', 'system')
    config_info = json.loads(r_session.get(config_key).decode('utf-8'))

    err_msg = None
    if session.get('error_message') is not None:
        err_msg = session.get('error_message')
        session['error_message'] = None
    action = None
    if session.get('action') is not None:
        action = session.get('action')
        session['action'] = None

    return render_template('profile.html', user_info=user_info, system=config_info, err_msg=err_msg, action=action)


@app.route('/user/change_info', methods=['POST'])
@requires_auth
def user_change_info():
    user = session.get('user_info')
    email = request.values.get('email')
    session['action'] = 'info'
    r = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"

    if re.match(r, email) is None:
        session['error_message'] = '邮箱地址格式不正确.'

        return redirect(url_for('user_profile'))

    user_key = '%s:%s' % ('user', user.get('username'))
    user_info = json.loads(r_session.get(user_key).decode('utf-8'))

    user_info['email'] = email
    r_session.set(user_key, json.dumps(user_info))

    return redirect(url_for('user_profile'))


@app.route('/user/turn<field>', methods=['POST'])
@requires_auth
def user_turn(field):
    user = session.get('user_info')
    user_key = '%s:%s' % ('user', user.get('username'))
    user_info = json.loads(r_session.get(user_key).decode('utf-8'))
    if field == 'income':
       if 'auto_column' in user_info.keys():
           user_info['auto_column'] = True if user_info['auto_column'] == False else False 
       else:
           user_info['auto_column'] = True
    elif field == 'speed':
       if 'is_show_speed_data' in user_info.keys():
           user_info['is_show_speed_data'] = True if user_info['is_show_speed_data'] == False else False 
       else:
           user_info['is_show_speed_data'] = True
    elif field == 'award':
       if 'is_show_wpdc' in user_info.keys():
           user_info['is_show_wpdc'] = (user_info['is_show_wpdc'] + 1) % 3
       else:
           user_info['is_show_wpdc'] = 0
    r_session.set(user_key, json.dumps(user_info))
    return redirect(url_for('dashboard'))

@app.route('/user/change_property/<field>/<value>', methods=['POST'])
@requires_auth
def user_change_property(field, value):
    user = session.get('user_info')
    user_key = '%s:%s' % ('user', user.get('username'))

    user_info = json.loads(r_session.get(user_key).decode('utf-8'))
    config_key = '%s:%s' % ('user', 'system')
    config_info = json.loads(r_session.get(config_key).decode('utf-8'))

    err_msg = None
    if session.get('error_message') is not None:
        err_msg = session.get('error_message')
        session['error_message'] = None
    action = None
    if session.get('action') is not None:
        action = session.get('action')
        session['action'] = None

    if field == 'auto_column':
        user_info['auto_column'] = True if value == '1' else False
    if field == 'auto_collect':
        user_info['auto_collect'] = True if value == '1' else False
        session['action'] = 'profile'
    if field == 'auto_drawcash':
        user_info['auto_drawcash'] = True if value == '1' else False
        session['action'] = 'profile'
    if field == 'auto_giftbox':
        user_info['auto_giftbox'] = True if value == '1' else False
        session['action'] = 'profile'
    if field == 'auto_searcht':
        user_info['auto_searcht'] = True if value == '1' else False
        session['action'] = 'profile'
    if field == 'auto_revenge':
        user_info['auto_revenge'] = True if value == '1' else False
        session['action'] = 'profile'
    if field == 'auto_getaward':
        user_info['auto_getaward'] = True if value == '1' else False
        session['action'] = 'profile'
    if field == 'is_show_speed_data':
        user_info['is_show_speed_data'] = True if value == '1' else False
    if field == 'is_show_wpdc':
        user_info['is_show_wpdc'] = int(value)
    if field == 'is_show_byname':
        user_info['is_show_byname'] = True if value == '1' else False
    if field == 'auto_detect':
        user_info['auto_detect'] = True if value == '1' else False
        session['action'] = 'profile'
    if field == 'auto_report':
        user_info['auto_report'] = True if value == '1' else False
        session['action'] = 'profile'
    if field == 'collect_crystal_modify':
        try:
            if int(str(request.values.get('collect_crystal_modify'))) >= 3000:
                user_info['collect_crystal_modify'] = int(str(request.values.get('collect_crystal_modify')))
        except ValueError:
            return redirect(url_for('user_profile'))
    if field == 'draw_money_modify':
        try:
            user_info['draw_money_modify'] = float(str(request.values.get('draw_money_modify')))
        except ValueError:
            return redirect(url_for('user_profile'))
    r_session.set(user_key, json.dumps(user_info))


    return redirect(url_for('user_profile'))


@app.route('/user/change_password', methods=['POST'])
@requires_auth
def user_change_password():
    user = session.get('user_info')
    o_password = request.values.get('old_password')
    n_password = request.values.get('new_password')
    n2_password = request.values.get('new2_password')
    session['action'] = 'password'

    if n_password != n2_password:
        session['error_message'] = '新密码输入不一致.'
        return redirect(url_for('user_profile'))

    if len(n_password) < 8:
        session['error_message'] = '密码必须8位及以上.'
        return redirect(url_for('user_profile'))

    user_key = '%s:%s' % ('user', user.get('username'))
    user_info = json.loads(r_session.get(user_key).decode('utf-8'))

    hashed_password = hash_password(o_password)

    if user_info.get('password') != hashed_password:
        session['error_message'] = '原密码错误'
        return redirect(url_for('user_profile'))

    user_info['password'] = hash_password(n_password)
    r_session.set(user_key, json.dumps(user_info))

    return redirect(url_for('user_profile'))

@app.route('/register')
def register():
    if session.get('user_info') is not None:
        return redirect(url_for('dashboard'))

    err_msg = None
    if session.get('error_message') is not None:
        err_msg = session.get('error_message')
        session['error_message'] = None

    info_msg = None
    if session.get('info_message') is not None:
        info_msg = session.get('info_message')
        session['info_message'] = None

    invitation_code = ''
    if request.values.get('inv_code') is not None and len(request.values.get('inv_code')) > 0 :
        invitation_code = request.values.get('inv_code')

    if request.values.get('active') is not None and len(request.values.get('active')) > 0 :
        active_code = request.values.get('active')
        try:
            validate = base64.b64decode(active_code)
            code = validate.decode('utf-8')
        except Exception as e:
            session['error_message'] = '非法参数错误.'
            return redirect(url_for('register'))

        key = 'activecode:%s' % code
        activecode = r_session.get(key)
        if activecode is None:
            session['error_message'] = '激活帐户链接已失效.'
            return redirect(url_for('register'))

        user = json.loads(activecode.decode('utf-8'))

        r_session.set('%s:%s' % ('user', user.get('username')), json.dumps(user))
        r_session.set('%s:%s' % ('record', user.get('username')), json.dumps(dict(diary=[])))
        r_session.sadd('users', user.get('username'))
        r_session.sadd('email', user.get('email'))
        r_session.delete(key)

        session['info_message'] = '恭喜你，注册成功.'
        return redirect(url_for('register'))

    return render_template('register.html', err_msg=err_msg, info_msg=info_msg, invitation_code=invitation_code)

def user_email(email, key):
    from mailsand import send_email

    url_scheme = request.environ.get('wsgi.url_scheme')
    HTTP_HOST = request.environ.get('HTTP_HOST')

    http = '%s://%s/register?active=%s' % (url_scheme, HTTP_HOST, key)

    mail = dict()
    mail['to'] = email
    mail['subject'] = '云监工-激活注册账号'
    mail['text'] = """
<td align="center" valign="top" width="592" style="padding:10px; text-align:center; border:1px solid #eee">
<table align="left" border="0" cellpadding="0" cellspacing="0" width="100%" style="text-align:left; background-color:#fff">
<tbody>
<tr>
<td style="font-size:14px; color:#333; padding:23px 20px 0; line-height:1.46"><span style="margin:0; padding:0">亲爱的用户：</span> 
<p style="margin:0; padding:0">您好，感谢您使用云监工，您正在激活帐户！</p>
<p style="margin:0; padding:0">激活链接：<a target="_blank" href=""" + http + """>立即激活</a></p>
<p style="color:#cb2222; padding:20px 0 0; margin:0">提示：为了保障您账号的安全性，该链接有效期为30分钟。</p>
<p style="margin:0; padding:0; width:70%">如果您误收到此电子邮件，则可能是其他用户在尝试帐号设置时的误操作，可以放心地忽略此电子邮件。</p>
</td>
</tr>
<tr>
<td style="color:#333; line-height:2; padding:30px 20px 10px; font-size:14px">
<p style="margin:0; padding:0">此邮件为自动发送，请勿回复！</p>
</td>
</tr>
</tbody>
</table>
</td>
    """
    config_key = '%s:%s' % ('user', 'system')
    config_info = json.loads(r_session.get(config_key).decode('utf-8'))
    return send_email(mail,config_info)

@app.route('/user/register', methods=['POST'])
def user_register():
    email = request.values.get('username')
    invitation_code = request.values.get('invitation_code')
    username = request.values.get('username')
    password = request.values.get('password')
    re_password = request.values.get('re_password')

    r = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
    if re.match(r, email) is None:
        session['error_message'] = '邮箱地址格式不正确.'
        return redirect(url_for('register'))

    if username == '':
        session['error_message'] = '账号名不能为空。'
        return redirect(url_for('register'))

    if r_session.get('%s:%s' % ('user', username)) is not None:
        session['error_message'] = '该账号名已存在。'
        return redirect(url_for('register'))

    if password != re_password:
        session['error_message'] = '新密码输入不一致.'
        return redirect(url_for('register'))

    if len(password) < 8:
        session['error_message'] = '密码必须8位及以上.'
        return redirect(url_for('register'))

    if r_session.sismember('email', email):
        session['error_message'] = '该邮件地址已被注册.'
        return redirect(url_for('register'))

    if not r_session.sismember('invitation_codes', invitation_code) and \
            not r_session.sismember('public_invitation_codes', invitation_code):
        session['error_message'] = '无效的邀请码。'
        return redirect(url_for('register'))

    email_code = r_session.get('emailcode:%s' % email)
    if email_code is not None:
        code_time = json.loads(email_code.decode('utf-8'))
        if datetime.strptime(code_time, '%Y-%m-%d %H:%M:%S') + timedelta(minutes=5) > datetime.now():
            session['error_message'] = '发送邮件过于频繁 请稍候再试.'
            return redirect(url_for('register'))

    _chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    key = ''.join(random.sample(_chars, 36))
    user = dict(username=username, password=hash_password(password), id=str(uuid.uuid1()),
                active=True, is_admin=False, max_account_no=20, email=email,
                created_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    r_session.setex('emailcode:%s' % email, json.dumps(user.get('created_time')), 60*5)
    r_session.setex('activecode:%s' % key, json.dumps(user), 60*30)

    bytesString = key.encode('utf-8')
    encodestr = base64.b64encode(bytesString)

    if user_email(email, encodestr.decode('utf-8')) != True:
        session['error_message'] = '激活帐户邮件发送失败 邮箱不存在.'
        return redirect(url_for('register'))

    r_session.srem('invitation_codes', invitation_code)
    r_session.srem('public_invitation_codes', invitation_code)

    session['info_message'] = '激活帐户邮件已发送到您的邮箱.'
    return redirect(url_for('register'))

