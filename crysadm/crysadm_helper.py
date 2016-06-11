__author__ = 'powergx'
from flask import Flask,render_template
import config, socket, redis
import time
from login import login
from datetime import datetime, timedelta
from multiprocessing import Process
from multiprocessing.dummy import Pool as ThreadPool
import threading


conf = None
if socket.gethostname() == 'GXMBP.local':
    conf = config.DevelopmentConfig
elif socket.gethostname() == 'iZ23bo17lpkZ':
    conf = config.ProductionConfig
else:
    conf = config.TestingConfig

redis_conf = conf.REDIS_CONF
pool = redis.ConnectionPool(host=redis_conf.host, port=redis_conf.port, db=redis_conf.db, password=redis_conf.password)
r_session = redis.Redis(connection_pool=pool)


from api import *

# 获取用户数据
def get_data(username):
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'get_data')

    start_time = datetime.now()
    try:
        for user_id in r_session.smembers('accounts:%s' % username):
            time.sleep(3)
            account_key = 'account:%s:%s' % (username, user_id.decode('utf-8'))
            account_info = json.loads(r_session.get(account_key).decode('utf-8'))

            if not account_info.get('active'): continue

            print("start get_data with userID:", user_id)

            session_id = account_info.get('session_id')
            user_id = account_info.get('user_id')
            cookies = dict(sessionid=session_id, userid=str(user_id))

            mine_info = get_mine_info(cookies)
            if is_api_error(mine_info):
                print('get_data:', user_id, mine_info, 'error')
                return

            if mine_info.get('r') != 0:

                success, account_info = __relogin(account_info.get('account_name'), account_info.get('password'), account_info, account_key)
                if not success:
                    print('get_data:', user_id, 'relogin failed')
                    continue
                session_id = account_info.get('session_id')
                user_id = account_info.get('user_id')
                cookies = dict(sessionid=session_id, userid=str(user_id))
                mine_info = get_mine_info(cookies)

            if mine_info.get('r') != 0:
                print('get_data:', user_id, mine_info, 'error')
                continue

            device_info = ubus_cd(session_id, user_id, 'get_devices', ["server", "get_devices", {}])
            red_zqb = device_info['result'][1]

            account_data_key = account_key + ':data'
            exist_account_data = r_session.get(account_data_key)
            if exist_account_data is None:
                account_data = dict()
                account_data['privilege'] = get_privilege(cookies)
            else:
                account_data = json.loads(exist_account_data.decode('utf-8'))

            balance_log = get_balance_log(cookies)
            if balance_log.get('r') == 0 and 'ioi' in balance_log.keys():
                account_data['ioi'] = balance_log['ioi']
                
            if account_data.get('updated_time') is not None:
                last_updated_time = datetime.strptime(account_data.get('updated_time'), '%Y-%m-%d %H:%M:%S')
                if last_updated_time.hour != datetime.now().hour:
                    account_data['zqb_speed_stat'] = get_speed_stat(cookies)
            else:
                account_data['zqb_speed_stat'] = get_speed_stat(cookies)

            account_data['updated_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            account_data['mine_info'] = mine_info
            account_data['device_info'] = red_zqb.get('devices')
            account_data['income'] = get_balance_info(cookies)
            
            account_data['produce_info'] = get_produce_stat(cookies)

            if is_api_error(account_data.get('income')):
                print('get_data:', user_id, 'income', 'error')
                return

            r_session.set(account_data_key, json.dumps(account_data))
            if not r_session.exists('can_drawcash'):
                r = get_can_drawcash(cookies=cookies)
                if r.get('r') == 0:
                    r_session.setex('can_drawcash', r.get('is_tm'), 60)

        if start_time.day == datetime.now().day:
            save_history(username)

        r_session.setex('user:%s:cron_queued' % username, '1', 60)
        print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), username.encode('utf-8'), 'successed')

    except Exception as ex:
        print(username.encode('utf-8'), 'failed', datetime.now().strftime('%Y-%m-%d %H:%M:%S'), ex)


# 保存历史数据
def save_history(username):
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'save_history')
    str_today = datetime.now().strftime('%Y-%m-%d')
    key = 'user_data:%s:%s' % (username, str_today)
    b_today_data = r_session.get(key)
    today_data = dict()

    if b_today_data is not None:
        today_data = json.loads(b_today_data.decode('utf-8'))

    today_data['updated_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    today_data['pdc'] = 0
    today_data['last_speed'] = 0
    today_data['deploy_speed'] = 0
    today_data['uncollect'] = 0
    today_data['balance'] = 0
    today_data['income'] = 0
    today_data['speed_stat'] = list()
    today_data['pdc_detail'] = []
    today_data['produce_stat'] = [] 
    today_data['award_income'] = 0

    for user_id in r_session.smembers('accounts:%s' % username):
        # 获取账号所有数据
        account_data_key = 'account:%s:%s:data' % (username, user_id.decode('utf-8'))
        b_data = r_session.get(account_data_key)
        if b_data is None:
            continue
        data = json.loads(b_data.decode('utf-8'))

        if datetime.strptime(data.get('updated_time'), '%Y-%m-%d %H:%M:%S').day != datetime.now().day:
            continue
        today_data.get('speed_stat').append(dict(mid=data.get('privilege').get('mid'),
                                                 dev_speed=data.get('zqb_speed_stat') if data.get(
                                                     'zqb_speed_stat') is not None else [0] * 24))
        this_pdc = data.get('mine_info').get('dev_m').get('pdc')

        today_data['pdc'] += this_pdc
        today_data.get('pdc_detail').append(dict(mid=data.get('privilege').get('mid'), pdc=this_pdc))

        today_data['uncollect'] += data.get('mine_info').get('td_not_in_a')
        today_data['balance'] += data.get('income').get('r_can_use')
        today_data['income'] += data.get('income').get('r_h_a')
        today_data.get('produce_stat').append(dict(mid=data.get('privilege').get('mid'), hourly_list=data.get('produce_info').get('hourly_list')))
        if 'ioi' in data.keys():
            for ioi in data['ioi']:
                if 'cn' in ioi.keys() and 'ct' in ioi.keys() and time.localtime(ioi['ct']).tm_mday == datetime.now().day:
                    if ioi['cn'].find('宝箱') != -1 or ioi['cn'].find('转盘') != -1:
                        today_data['award_income'] += ioi['c']
        for device in data.get('device_info'):
            today_data['last_speed'] += int(int(device.get('dcdn_upload_speed')) / 1024)
            today_data['deploy_speed'] += int(device.get('dcdn_download_speed') / 1024)
    today_data['pdc'] += today_data['award_income'] 
    r_session.setex(key, json.dumps(today_data), 3600 * 24 * 35)

    extra_info_key='extra_info:%s' % (username)
    b_extra_info=r_session.get(extra_info_key)
    if b_extra_info is None:
        extra_info={}
    else:
        extra_info=json.loads(b_extra_info.decode('utf-8'))
    if 'last_adjust_date' not in extra_info.keys():
        extra_info['last_adjust_date'] = '1997-1-1 1:1:1'
    if datetime.now().hour<20 and datetime.strptime(extra_info['last_adjust_date'],'%Y-%m-%d %H:%M:%S').day != datetime.now().day:
        str_yesterday = (datetime.now() + timedelta(days=-1)).strftime('%Y-%m-%d')
        yesterday_key = 'user_data:%s:%s' % (username, str_yesterday)
        b_yesterday_data = r_session.get(yesterday_key)
        if b_yesterday_data is None: return
        yesterday_data = json.loads(b_yesterday_data.decode('utf-8'))
        if 'produce_stat' in yesterday_data.keys():
            td_produce={}
            for td_stat in today_data['produce_stat']:
                td_produce[td_stat['mid']]=td_stat['hourly_list']
            detail_adjust_dict={}
            for stat in yesterday_data['produce_stat']:
                if stat['mid'] in td_produce.keys():
                    last_hour_pdc=td_produce[stat['mid']][23-datetime.strptime(today_data['updated_time'],'%Y-%m-%d %H:%M:%S').hour]
                    detail_adjust_dict[stat['mid']] = last_hour_pdc - stat['hourly_list'][24]
                    stat['hourly_list'][24] = last_hour_pdc
            for pdc_info in yesterday_data.get('pdc_detail'):
                if pdc_info.get('mid') is not None and pdc_info.get('pdc') is not None:
                    pdc_info['pdc'] += detail_adjust_dict[pdc_info.get('mid')]
        r_session.setex(yesterday_key, json.dumps(yesterday_data), 3600 * 24 * 34)
        extra_info['last_adjust_date']=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        r_session.set(extra_info_key,json.dumps(extra_info))
    save_income_history(username, today_data.get('pdc_detail'))

# 获取保存的历史数据
def save_income_history(username, pdc_detail):
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), username.encode('utf-8'), 'save_income_history')
    now = datetime.now()
    key = 'user_data:%s:%s' % (username, 'income.history')
    b_income_history = r_session.get(key)
    income_history = dict()

    if b_income_history is not None:
        income_history = json.loads(b_income_history.decode('utf-8'))

#    if now.minute < 50:
#        return

    if income_history.get(now.strftime('%Y-%m-%d')) is None:
        income_history[now.strftime('%Y-%m-%d')] = dict()

    income_history[now.strftime('%Y-%m-%d')][now.strftime('%H')] = pdc_detail

    r_session.setex(key, json.dumps(income_history), 3600 * 72)

# 重新登录
def __relogin(username, password, account_info, account_key):
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), username.encode('utf-8'), 'relogin')
    login_result = login(username, password, conf.ENCRYPT_PWD_URL)

    if login_result.get('errorCode') != 0:
        account_info['status'] = login_result.get('errorDesc')
        account_info['active'] = False
        r_session.set(account_key, json.dumps(account_info))
        return False, account_info

    account_info['session_id'] = login_result.get('sessionID')
    account_info['status'] = 'OK'
    r_session.set(account_key, json.dumps(account_info))
    return True, account_info

# 获取在线用户数据
def get_online_user_data():
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'get_online_user_data')
    if r_session.exists('api_error_info'): return

    pool = ThreadPool(processes=5)

    pool.map(get_data, (u.decode('utf-8') for u in r_session.smembers('global:online.users')))
    pool.close()
    pool.join()

# 获取离线用户数据
def get_offline_user_data():
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'get_offline_user_data')
    if r_session.exists('api_error_info'): return
#    if datetime.now().minute < 50: return

    offline_users = []
    for b_user in r_session.mget(*['user:%s' % name.decode('utf-8') for name in r_session.sdiff('users', *r_session.smembers('global:online.users'))]):
        user_info = json.loads(b_user.decode('utf-8'))

        username = user_info.get('username')

        if not user_info.get('active'): continue

        every_hour_key = 'user:%s:cron_queued' % username
        if r_session.exists(every_hour_key): continue

        offline_users.append(username)

    pool = ThreadPool(processes=5)

    pool.map(get_data, offline_users)
    pool.close()
    pool.join()

# 从在线用户列表中清除离线用户
def clear_offline_user():
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'clear_offline_user')
    for b_username in r_session.smembers('global:online.users'):
        username = b_username.decode('utf-8')
        if not r_session.exists('user:%s:is_online' % username):
            r_session.srem('global:online.users', username)

# 刷新选择自动任务的用户
def select_auto_task_user():
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'select_auto_task_user')
    auto_collect_accounts = []
    auto_drawcash_accounts = []
    auto_giftbox_accounts = []
    auto_searcht_accounts = []
    auto_revenge_accounts = []
    auto_getaward_accounts = []
    auto_detect_accounts = []
    auto_report_accounts = []
    for b_user in r_session.mget(*['user:%s' % name.decode('utf-8') for name in r_session.smembers('users')]):
        user_info = json.loads(b_user.decode('utf-8'))
        if not user_info.get('active'): continue
        username = user_info.get('username')
        account_keys = ['account:%s:%s' % (username, user_id.decode('utf-8')) for user_id in r_session.smembers('accounts:%s' % username)]
        if len(account_keys) == 0: continue
        for b_account in r_session.mget(*account_keys):
            account_info = json.loads(b_account.decode('utf-8'))
            if not (account_info.get('active')): continue
            session_id = account_info.get('session_id')
            user_id = account_info.get('user_id')
            cookies = json.dumps(dict(sessionid=session_id, userid=user_id, user_info=user_info))
            if user_info.get('auto_collect'): auto_collect_accounts.append(cookies)
            if user_info.get('auto_drawcash'): auto_drawcash_accounts.append(cookies)
            if user_info.get('auto_giftbox'): auto_giftbox_accounts.append(cookies)
            if user_info.get('auto_searcht'): auto_searcht_accounts.append(cookies)
            if user_info.get('auto_revenge'): auto_revenge_accounts.append(cookies)
            if user_info.get('auto_getaward'): auto_getaward_accounts.append(cookies)
            if user_info.get('auto_detect'): auto_detect_accounts.append(cookies)
            if user_info.get('auto_report'): auto_report_accounts.append(cookies)
    r_session.delete('global:auto.collect.cookies')
    if len(auto_collect_accounts) != 0:
        r_session.sadd('global:auto.collect.cookies', *auto_collect_accounts)
    r_session.delete('global:auto.drawcash.cookies')
    if len(auto_drawcash_accounts) != 0:
        r_session.sadd('global:auto.drawcash.cookies', *auto_drawcash_accounts)
    r_session.delete('global:auto.giftbox.cookies')
    if len(auto_giftbox_accounts) != 0:
        r_session.sadd('global:auto.giftbox.cookies', *auto_giftbox_accounts)
    r_session.delete('global:auto.searcht.cookies')
    if len(auto_searcht_accounts) != 0:
        r_session.sadd('global:auto.searcht.cookies', *auto_searcht_accounts)
    r_session.delete('global:auto.revenge.cookies')
    if len(auto_revenge_accounts) != 0:
        r_session.sadd('global:auto.revenge.cookies', *auto_revenge_accounts)
    r_session.delete('global:auto.getaward.cookies')
    if len(auto_getaward_accounts) != 0:
        r_session.sadd('global:auto.getaward.cookies', *auto_getaward_accounts)
    r_session.delete('global:auto.detect.cookies')
    if len(auto_detect_accounts) != 0:
        r_session.sadd('global:auto.detect.cookies', *auto_detect_accounts)
    r_session.delete('global:auto.report.cookies')
    if len(auto_report_accounts) != 0:
        r_session.sadd('global:auto.report.cookies', *auto_report_accounts)

# 执行检测收益报告函数
def check_report(user, cookies, user_info):
    from mailsand import send_email
    from mailsand import validateEmail
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'check_report')
    extra_info_key='extra_info:%s' % (user_info.get('username'))
    b_extra_info=r_session.get(extra_info_key)
    if b_extra_info is None:
        extra_info={}
    else:
        extra_info=json.loads(b_extra_info.decode('utf-8'))
    if 'last_adjust_date' not in extra_info.keys() or datetime.strptime(extra_info['last_adjust_date'],'%Y-%m-%d %H:%M:%S').day != datetime.now().day:
        return
    if 'last_report_date' not in extra_info.keys():
        extra_info['last_report_date'] = '1997-1-1 1:1:1'
    if datetime.strptime(extra_info['last_report_date'],'%Y-%m-%d %H:%M:%S').day == datetime.now().day: return
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'check_report')
    str_yesterday = (datetime.now() + timedelta(days=-1)).strftime('%Y-%m-%d')
    yesterday_key = 'user_data:%s:%s' % (user_info.get('username'), str_yesterday)
    b_yesterday_data = r_session.get(yesterday_key)
    if b_yesterday_data is None: return
    yesterday_data = json.loads(b_yesterday_data.decode('utf-8'))
    if 'produce_stat' in yesterday_data.keys():
        if validateEmail(user_info['email']) != 1: return
        mail = dict()
        mail['to'] = user_info['email']
        mail['subject'] = '云监工-收益报告'
        mail['text'] = """
<DIV style="BACKGROUND-COLOR: #e6eae9">
    <TABLE style="WIDTH: 100%; COLOR: #4f6b72; PADDING-BOTTOM: 0px; PADDING-TOP: 0px; PADDING-LEFT: 0px; MARGIN: 0px; PADDING-RIGHT: 0px" cellSpacing=0 summary="The technical specifications of the Apple PowerMac G5 series">
        <CAPTION style="WIDTH: 700px; PADDING-BOTTOM: 5px; TEXT-ALIGN: center; PADDING-TOP: 0px; FONT: italic 11px 'Trebuchet MS', Verdana, Arial, Helvetica, sans-serif; PADDING-LEFT: 0px; PADDING-RIGHT: 0px">
            收益报告
        </CAPTION>
        <TBODY>
            <TR>
                <TH style="BORDER-LEFT-WIDTH: 0px; BORDER-RIGHT: #c1dad7 1px solid; BACKGROUND: none transparent scroll repeat 0% 0%; BORDER-BOTTOM: #c1dad7 1px solid; TEXT-TRANSFORM: uppercase; COLOR: #4f6b72; PADDING-BOTTOM: 6px; TEXT-ALIGN: left; PADDING-TOP: 6px; FONT: bold 11px 'Trebuchet MS', Verdana, Arial, Helvetica, sans-serif; PADDING-LEFT: 12px; LETTER-SPACING: 2px; PADDING-RIGHT: 6px; BORDER-TOP-WIDTH: 0px" scope=col>
                    矿主ID
                </TH>
                <TH style="BORDER-TOP: #c1dad7 1px solid; BORDER-RIGHT: #c1dad7 1px solid; BACKGROUND: #cae8ea; BORDER-BOTTOM: #c1dad7 1px solid; TEXT-TRANSFORM: uppercase; COLOR: #4f6b72; PADDING-BOTTOM: 6px; TEXT-ALIGN: left; PADDING-TOP: 6px; FONT: bold 11px 'Trebuchet MS', Verdana, Arial, Helvetica, sans-serif; PADDING-LEFT: 12px; LETTER-SPACING: 2px; PADDING-RIGHT: 6px" scope=col>
                    平均速度(KB/S)
                </TH>
                <TH style="BORDER-TOP: #c1dad7 1px solid; BORDER-RIGHT: #c1dad7 1px solid; BACKGROUND: #cae8ea; BORDER-BOTTOM: #c1dad7 1px solid; TEXT-TRANSFORM: uppercase; COLOR: #4f6b72; PADDING-BOTTOM: 6px; TEXT-ALIGN: left; PADDING-TOP: 6px; FONT: bold 11px 'Trebuchet MS', Verdana, Arial, Helvetica, sans-serif; PADDING-LEFT: 12px; LETTER-SPACING: 2px; PADDING-RIGHT: 6px" scope=col>
                    今日收益(￥)
                </TH>
            </TR>
    """
        td_speed={}
        td_produce={}
        s_sum=0
        p_sum=0
        for stat in yesterday_data['speed_stat']:
            s=0
            for i in range(0,24):
               s+=stat['dev_speed'][i]
            td_speed[stat['mid']]=s/24/8
            s_sum+=td_speed[stat['mid']]
        for j,stat in enumerate(yesterday_data['produce_stat']):
            s=0
            for i in range(1,25):
               s+=stat['hourly_list'][i]
            td_produce[stat['mid']]=s/10000
            p_sum+=td_produce[stat['mid']]
            if j % 2 == 0:
                mail['text']=mail['text'] + """
            <TR>
                <TH style="BORDER-RIGHT: #c1dad7 1px solid; BACKGROUND: #fff; BORDER-BOTTOM: #c1dad7 1px solid; TEXT-TRANSFORM: uppercase; COLOR: #4f6b72; PADDING-BOTTOM: 6px; TEXT-ALIGN: left; PADDING-TOP: 6px; FONT: bold 10px 'Trebuchet MS', Verdana, Arial, Helvetica, sans-serif; PADDING-LEFT: 12px; BORDER-LEFT: #c1dad7 1px solid; LETTER-SPACING: 2px; PADDING-RIGHT: 6px; BORDER-TOP-WIDTH: 0px" scope=row>
                    """ + ('%d' % (stat['mid'])) + """
                </TH>
                <TD style="FONT-SIZE: 11px; BORDER-RIGHT: #c1dad7 1px solid; BACKGROUND: #fff; BORDER-BOTTOM: #c1dad7 1px solid; COLOR: #4f6b72; PADDING-BOTTOM: 6px; PADDING-TOP: 6px; PADDING-LEFT: 12px; PADDING-RIGHT: 6px">
                    """ + ('%.1f' % (td_speed[stat['mid']])) + """
                </TD>
                <TD style="FONT-SIZE: 11px; BORDER-RIGHT: #c1dad7 1px solid; BACKGROUND: #fff; BORDER-BOTTOM: #c1dad7 1px solid; COLOR: #4f6b72; PADDING-BOTTOM: 6px; PADDING-TOP: 6px; PADDING-LEFT: 12px; PADDING-RIGHT: 6px">
                    """ + ('%.2f' % (td_produce[stat['mid']])) + """
                </TD>
            </TR>
    """
            else:
                mail['text']=mail['text'] + """
                <TH style="BORDER-RIGHT: #c1dad7 1px solid; BACKGROUND: #f5fafa; BORDER-BOTTOM: #c1dad7 1px solid; TEXT-TRANSFORM: uppercase; COLOR: #797268; PADDING-BOTTOM: 6px; TEXT-ALIGN: left; PADDING-TOP: 6px; FONT: bold 10px 'Trebuchet MS', Verdana, Arial, Helvetica, sans-serif; PADDING-LEFT: 12px; BORDER-LEFT: #c1dad7 1px solid; LETTER-SPACING: 2px; PADDING-RIGHT: 6px; BORDER-TOP-WIDTH: 0px" scope=row>
                    """ + ('%d' % (stat['mid'])) + """
                </TH>
                <TD style="FONT-SIZE: 11px; BORDER-RIGHT: #c1dad7 1px solid; BACKGROUND: #f5fafa; BORDER-BOTTOM: #c1dad7 1px solid; COLOR: #797268; PADDING-BOTTOM: 6px; PADDING-TOP: 6px; PADDING-LEFT: 12px; PADDING-RIGHT: 6px">
                    """ + ('%.1f' % (td_speed[stat['mid']])) + """
                </TD>
                <TD style="FONT-SIZE: 11px; BORDER-RIGHT: #c1dad7 1px solid; BACKGROUND: #f5fafa; BORDER-BOTTOM: #c1dad7 1px solid; COLOR: #797268; PADDING-BOTTOM: 6px; PADDING-TOP: 6px; PADDING-LEFT: 12px; PADDING-RIGHT: 6px">
                    """ + ('%.2f' % (td_produce[stat['mid']])) + """
                </TD>
            </TR>
    """
        mail['text']=mail['text'] + """
            <TR>
                <TH style="BORDER-LEFT-WIDTH: 0px; BORDER-RIGHT: #c1dad7 1px solid; BACKGROUND: none transparent scroll repeat 0% 0%; TEXT-TRANSFORM: uppercase; COLOR: #4f6b72; PADDING-BOTTOM: 6px; TEXT-ALIGN: left; PADDING-TOP: 6px; FONT: bold 11px 'Trebuchet MS', Verdana, Arial, Helvetica, sans-serif; PADDING-LEFT: 12px; LETTER-SPACING: 2px; PADDING-RIGHT: 6px; BORDER-TOP-WIDTH: 0px" scope=col>
                    总计
                </TH>
                <TD style="FONT-SIZE: 11px; BORDER-RIGHT: #c1dad7 1px solid; BACKGROUND: none transparent scroll repeat 0% 0%; COLOR: #4f6b72; PADDING-BOTTOM: 6px; PADDING-TOP: 6px; PADDING-LEFT: 12px; PADDING-RIGHT: 6px">
                    """ + ('%.1f' % (s_sum)) + """
                </TD>
                <TD style="FONT-SIZE: 11px; BORDER-RIGHT: #c1dad7 1px solid; BACKGROUND: none transparent scroll repeat 0% 0%; COLOR: #4f6b72; PADDING-BOTTOM: 6px; PADDING-TOP: 6px; PADDING-LEFT: 12px; PADDING-RIGHT: 6px">
                    """ + ('%.2f' % (p_sum)) + """
                </TD>
            </TR>
        </TBODY>
        <TFOOT style="FONT-SIZE: 11px; BACKGROUND: none transparent scroll repeat 0% 0%">
            <TR>
                <TD colSpan=4 align=right>
                """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """
                </TD>
            </TR>
        </TFOOT>
    </TABLE>
</DIV>
    """
        if send_email(mail,config_info) == True:
            extra_info['last_report_date']=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        r_session.set(extra_info_key,json.dumps(extra_info))
            

# 执行检测异常矿机函数
def detect_exception(user, cookies, user_info):
    from mailsand import send_email
    from mailsand import validateEmail
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'detect_exception')
    config_key = '%s:%s' % ('user', 'system')
    config_info = json.loads(r_session.get(config_key).decode('utf-8'))
    account_data_key = 'account:%s:%s:data' % (user_info.get('username'), user.get('userid'))        
    exist_account_data = r_session.get(account_data_key)
    if exist_account_data is None: return
    account_data = json.loads(exist_account_data.decode('utf-8'))

    extra_info_key='extra_info:%s' % (user_info.get('username'))
    b_extra_info=r_session.get(extra_info_key)
    if b_extra_info is None:
        extra_info={}
    else:
        extra_info=json.loads(b_extra_info.decode('utf-8'))
    if 'detect_info' not in extra_info.keys():
        detect_info={}
    else:
        detect_info=extra_info['detect_info']
    if not 'device_info' in account_data.keys(): return
    status_cn={'offline':'离线','online':'在线','exception':'异常'}
    warn_list=[]
    for dev in account_data['device_info']:
        if 'status_list' not in detect_info.keys():
            detect_info['status_list']={}
        if dev['device_name'] not in detect_info['status_list'].keys():
            detect_info['status_list'][dev['device_name']]=dev['status']
        elif dev['status'] != detect_info['status_list'][dev['device_name']]:
            red_log(user, '矿机状态', '状态', '%s:%s -> %s' % (dev['device_name'],status_cn[detect_info['status_list'][dev['device_name']]],status_cn[dev['status']]))
            detect_info['status_list'][dev['device_name']]=dev['status']
            if 'exception_occured' not in detect_info.keys():
                detect_info['exception_occured'] = True
        if dev['status'] != 'online':
            warn_list.append(dev);
        if 'dcdn_clients' in dev.keys():
            for i,client in enumerate(dev['dcdn_clients']):
                space_last_key='space_%s:%s:%s' % (i,user.get('userid'),dev['device_name'])
                if space_last_key in detect_info.keys():
                    last_space=detect_info[space_last_key]
                    if last_space - 100*1024*1024 > int(client['space_used']):
                        red_log(user, '缓存变动', '状态', '%s:删除了%.2fGB缓存,当前%.2fGB' % (dev['device_name'],float(last_space)/1024/1024/1024-float(client['space_used'])/1024/1024/1024,float(client['space_used'])/1024/1024/1024))
                        detect_info[space_last_key] = int(client['space_used'])
                    elif last_space < int(client['space_used']):
                        detect_info[space_last_key] = int(client['space_used'])
                else:
                   detect_info[space_last_key] = int(client['space_used'])
    if len(warn_list) != 0:
        if 'updated_time' in detect_info.keys() and account_data['updated_time'] != detect_info['updated_time']:
            if 'exception_occured' in detect_info.keys() and detect_info['exception_occured'] == True:
                if 'last_warn' not in detect_info.keys() or (datetime.now() - datetime.strptime(detect_info['last_warn'],'%Y-%m-%d %H:%M:%S')).seconds > 60*60:
                    if validateEmail(user_info['email']) == 1:
                        mail = dict()
                        mail['to'] = user_info['email']
                        mail['subject'] = '云监工-矿机异常'
                        mail['text'] = ''
                        for dev in warn_list:
                            mail['text'] = mail['text'].join(['您的矿机：',dev['device_name'],'<br />状态：',status_cn[dev['status']] ,'<br />时间：',datetime.now().strftime('%Y-%m-%d %H:%M:%S'),'<br />==================<br />'])
                        if send_email(mail,config_info) == True:
                            detect_info['last_warn']=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            detect_info['exception_occured'] = False
    else:
        detect_info.pop('exception_occured','^.^')

    detect_info['updated_time'] = account_data['updated_time']
    extra_info['detect_info']=detect_info
    r_session.set(extra_info_key, json.dumps(extra_info))


# 执行收取水晶函数
def check_collect(user, cookies, user_info):
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'check_collect')
    mine_info = get_mine_info(cookies)
    time.sleep(2)
    if mine_info.get('r') != 0: return
    if 'collect_crystal_modify' in user_info.keys():
        limit=user_info.get('collect_crystal_modify')
    else:
        limit=16000;

    if mine_info.get('td_not_in_a') > limit:
        r = collect(cookies)
        if r.get('rd') != 'ok':
            log = '%s' % r.get('rd')
        else:
            log = '收取:%s水晶.' % mine_info.get('td_not_in_a')
        red_log(user, '自动执行', '收取', log)
    time.sleep(3)

# 执行自动提现的函数
def check_drawcash(user, cookies, user_info):
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'check_drawcash')
    if 'draw_money_modify' in user_info.keys():
        limit=user_info.get('draw_money_modify')
    else:
        limit=10.0
    r = exec_draw_cash(cookies=cookies, limits=limit)
    red_log(user, '自动执行', '提现', r.get('rd'))
    time.sleep(3)

# 执行免费宝箱函数
def check_giftbox(user, cookies, user_info):
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'check_giftbox')
    box_info = api_giftbox(cookies)
    time.sleep(2)
    if box_info.get('r') != 0: return
    for box in box_info.get('ci'):
        if box.get('cnum') == 0:
            r_info = api_openStone(cookies=cookies, giftbox_id=box.get('id'), direction='3')
            if r_info.get('r') != 0:
                log = r_info.get('rd')
            else:
                r = r_info.get('get')
                log = '开启:获得:%s水晶.' % r.get('num')
        else:
            r_info = api_giveUpGift(cookies=cookies, giftbox_id=box.get('id'))
            if r_info.get('r') != 0:
                log = r_info.get('rd')
            else:
                log = '丢弃:收费:%s水晶.' % box.get('cnum')
        red_log(user, '自动执行', '宝箱', log)
    time.sleep(3)

# 执行秘银进攻函数
def check_searcht(user, cookies, user_info):
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'check_searcht')
    r = api_sys_getEntry(cookies)
    time.sleep(2)
    if r.get('r') != 0: return
    if r.get('steal_free') > 0:
        steal_info = api_steal_search(cookies)
        if steal_info.get('r') != 0:
            log = regular_html(r.get('rd'))
        else:
            time.sleep(3)
            t = api_steal_collect(cookies=cookies, searcht_id=steal_info.get('sid'))
            if t.get('r') != 0:
                log = 'Forbidden'
            else:
                log = '获得:%s秘银.' % t.get('s')
                time.sleep(1)
                api_steal_summary(cookies=cookies, searcht_id=steal_info.get('sid'))
        red_log(user, '自动执行', '进攻', log)
    time.sleep(3)

# 执行秘银复仇函数
def check_revenge(user, cookies, user_info):
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'check_revenge')
    r = api_steal_stolenSilverHistory(cookies)
    time.sleep(2)
    if r.get('r') != 0: return
    for q in r.get('list'):
        if q.get('st') == 0:
            steal_info = api_steal_search(cookies, q.get('sid'))
            if steal_info.get('r') != 0:
                log = regular_html(r.get('rd'))
            else:
                time.sleep(3)
                t = api_steal_collect(cookies=cookies, searcht_id=steal_info.get('sid'))
                if t.get('r') != 0:
                    log = 'Forbidden'
                else:
                    log = '获得:%s秘银.' % t.get('s')
                    time.sleep(1)
                    api_steal_summary(cookies=cookies, searcht_id=steal_info.get('sid'))
            red_log(user, '自动执行', '复仇', log)
    time.sleep(3)

# 执行幸运转盘函数
def check_getaward(user, cookies, user_info):
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'check_getaward')
    r = api_getconfig(cookies)
    time.sleep(2)
    if r.get('rd') != 'ok': return
    if r.get('cost') == 5000:
        t = api_getaward(cookies)
        if t.get('rd') != 'ok':
            log = t.get('rd')
        else:
            log = '获得:%s' % regular_html(t.get('tip'))
        red_log(user, '自动执行', '转盘', log)
    time.sleep(3)

# 收取水晶
def collect_crystal():
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'collect_crystal')

    cookies_auto(check_collect, 'global:auto.collect.cookies')
#    for cookie in r_session.smembers('global:auto.collect.cookies'):
#        check_collect(json.loads(cookie.decode('utf-8')))

# 自动提现
def drawcash_crystal():
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'drawcash_crystal')
    time_now = datetime.now()
    if int(time_now.isoweekday()) != 2: return
    if int(time_now.hour) < 12 or int(time_now.hour) > 18: return

    cookies_auto(check_drawcash, 'global:auto.drawcash.cookies')
#    for cookie in r_session.smembers('global:auto.drawcash.cookies'):
#        check_drawcash(json.loads(cookie.decode('utf-8')))

# 免费宝箱
def giftbox_crystal():
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'giftbox_crystal')

    cookies_auto(check_giftbox, 'global:auto.giftbox.cookies')
#    for cookie in r_session.smembers('global:auto.giftbox.cookies'):
#        check_giftbox(json.loads(cookie.decode('utf-8')))

# 秘银进攻
def searcht_crystal():
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'searcht_crystal')

    cookies_auto(check_searcht, 'global:auto.searcht.cookies')
#    for cookie in r_session.smembers('global:auto.searcht.cookies'):
#        check_searcht(json.loads(cookie.decode('utf-8')))

# 秘银复仇
def revenge_crystal():
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'revenge_crystal')

    cookies_auto(check_revenge, 'global:auto.revenge.cookies')
#    for cookie in r_session.smembers('global:auto.searcht.cookies'):
#        check_searcht(json.loads(cookie.decode('utf-8')))

# 幸运转盘
def getaward_crystal():
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'getaward_crystal')

    cookies_auto(check_getaward, 'global:auto.getaward.cookies')
#    for cookie in r_session.smembers('global:auto.getaward.cookies'):
#        check_getaward(json.loads(cookie.decode('utf-8')))

# 自动监测
def auto_detect():
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'auto_detect')

    cookies_auto(detect_exception, 'global:auto.detect.cookies')

# 自动报告
def auto_report():
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'auto_report')
    cookies_auto(check_report, 'global:auto.report.cookies')

# 处理函数[重组]
def cookies_auto(func, cookiename):
    users = r_session.smembers(cookiename)
    if users is not None and len(users) > 0:
        for user in users:
            try:
                cookies = json.loads(user.decode('utf-8'))
                session_id=cookies.get('sessionid')
                user_id=cookies.get('userid')
                user_info=cookies.get('user_info')
                func(cookies, dict(sessionid=session_id, userid=user_id), user_info)
            except Exception as e:
                print(e)
                continue

# 正则过滤+URL转码
def regular_html(info):
    import re
    from urllib.parse import unquote
    regular = re.compile('<[^>]+>')
    url = unquote(info)
    return regular.sub("", url)

# 自动日记记录
def red_log(cook, clas, type, gets):
    user = cook.get('user_info')

    record_key = '%s:%s' % ('record', user.get('username'))
    if r_session.get(record_key) is None:
        record_info = dict(diary=[])
    else:
        record_info = json.loads(r_session.get(record_key).decode('utf-8'))

    id = cook.get('userid')

    log_as_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    body = dict(time=log_as_time, clas=clas, type=type, id=id, gets=gets)

    log_as_body = record_info.get('diary')
    log_trimed = []
    for item in log_as_body:
       if (datetime.now() - datetime.strptime(item.get('time'), '%Y-%m-%d %H:%M:%S')).days < 31:
           log_trimed.append(item)
    log_trimed.append(body)

    record_info['diary'] = log_trimed

    r_session.set(record_key, json.dumps(record_info))

# 计时器函数，定期执行某个线程，时间单位为秒
def timer(func, seconds):
    while True:
        Process(target=func).start()
        time.sleep(seconds)

if __name__ == '__main__':
    config_key = '%s:%s' % ('user', 'system')
    r_config_info = r_session.get(config_key)
    if r_config_info is None:
        config_info = {
            'collect_crystal_interval':30*60,
            'drawcash_crystal_interval':60*60,
            'giftbox_crystal_interval':40*60,
            'searcht_crystal_interval':360*60,
            'revenge_crystal_interval':300*60,
            'getaward_crystal_interval':240*60,
            'get_online_user_data_interval':30,
            'get_offline_user_data_interval':600,
            'clear_offline_user_interval':60,
            'select_auto_task_user_interval':10*60,
            'auto_detect_interval':5*60,
            'master_mail_smtp':'smtp.163.com',
            'master_email':'xxxxxxxx@163.com',
            'master_mail_password':'xxxxxxxxxxxxxx',
        }
        r_session.set(config_key, json.dumps(config_info))
    else:
        config_info = json.loads(r_config_info.decode('utf-8'))
    for k in config_info.keys():
        if k.endswith('_interval') and config_info[k]<15:
            config_info[k]=15
         
    # 如有任何疑问及Bug欢迎加入L.k群讨论
    # 执行收取水晶时间，单位为秒，默认为30秒。
    # 每30分钟检测一次收取水晶
    threading.Thread(target=timer, args=(collect_crystal, config_info['collect_crystal_interval'])).start()
    # 执行自动提现时间，单位为秒，默认为60秒。
    # 每60分钟检测一次自动提现
    threading.Thread(target=timer, args=(drawcash_crystal, config_info['drawcash_crystal_interval'])).start()
    # 执行免费宝箱时间，单位为秒，默认为40秒。
    # 每40分钟检测一次免费宝箱
    threading.Thread(target=timer, args=(giftbox_crystal, config_info['giftbox_crystal_interval'])).start()
    # 执行秘银进攻时间，单位为秒，默认为360秒。
    # 每360分钟检测一次秘银进攻
    threading.Thread(target=timer, args=(searcht_crystal, config_info['searcht_crystal_interval'])).start()
    # 执行秘银复仇时间，单位为秒，默认为300秒。
    # 每300分钟检测一次秘银复仇
    threading.Thread(target=timer, args=(revenge_crystal, config_info['revenge_crystal_interval'])).start()
    # 执行幸运转盘时间，单位为秒，默认为240秒。
    # 每240分钟检测一次幸运转盘
    threading.Thread(target=timer, args=(getaward_crystal, config_info['getaward_crystal_interval'])).start()
    # 执行自动报告
    # 每30分钟检测一次自动报告，如果今天已报告过，则不执行操作
    threading.Thread(target=timer, args=(auto_report, 30*60)).start()
    # 执行自动监测时间，单位为秒，默认为300秒。
    # 每5分钟检测一次矿机状态
    threading.Thread(target=timer, args=(auto_detect, config_info['auto_detect_interval'])).start()
    # 刷新在线用户数据，单位为秒，默认为30秒。
    # 每30秒刷新一次在线用户数据
    threading.Thread(target=timer, args=(get_online_user_data, config_info['get_online_user_data_interval'])).start()
    # 刷新离线用户数据，单位为秒，默认为60秒。
    # 每10分钟刷新一次离线用户数据
    threading.Thread(target=timer, args=(get_offline_user_data, config_info['get_offline_user_data_interval'])).start()
    # 从在线用户列表中清除离线用户，单位为秒，默认为60秒。
    # 每分钟检测离线用户
    threading.Thread(target=timer, args=(clear_offline_user, config_info['clear_offline_user_interval'])).start()
    # 刷新选择自动任务的用户，单位为秒，默认为10分钟
    threading.Thread(target=timer, args=(select_auto_task_user, config_info['select_auto_task_user_interval'])).start()
    while True:
        time.sleep(1)

