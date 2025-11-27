import base64
import hashlib
import time
import json
import uuid
import schedule

import requests
import ddddocr
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
def get_sign(path, params, timestamp):
    """
    生成headers中的 sign 参数
    @param path: 请求路径，如 /api/venue/info
    @param params: 请求参数字典
    @param timestamp: 时间戳字符串，单位毫秒
    @return: sign 字符串
    """
    salt = "c640ca392cd45fb3a55b00a63a86c618"

    raw_str = f"{salt}{path}"

    if params:
        sorted_keys = sorted(params.keys())
        for key in sorted_keys:
            val = params[key]
            if val is None or val == "" or isinstance(val, (dict, list)):
                continue
            raw_str += f"{key}{str(val)}"

    raw_str += f"{timestamp} {salt}"

    md5 = hashlib.md5()
    md5.update(raw_str.encode('utf-8'))
    return md5.hexdigest()

def login(url, username, password):
    """
    使用 Selenium 自动化登录，获取 Cookies 并转移到 requests.Session 中
    @param url: 登录页面 URL
    @param username: 用户名
    @param password: 密码
    @return: 带有登录 Cookies 的 requests.Session 对象

    """
    ocr = ddddocr.DdddOcr(show_ad=False)

    chrome_options = Options()
    chrome_options.set_capability("goog:loggingPrefs", {"performance": "ALL"})
    chrome_options.add_argument("--headless=new")

    chrome_options.add_argument('--disable-gpu')
    chrome_options.add_argument("--disable-blink-features=AutomationControlled")

    driver = webdriver.Chrome(options=chrome_options)

    try:
        driver.get(url)
        wait = WebDriverWait(driver, 15)

        driver.find_element(By.ID, "username").send_keys(username)
        driver.find_element(By.ID, "password").send_keys(password)

        time.sleep(1)
        img_element = driver.find_element(By.ID, "captchaImg")
        captcha_code = ocr.classification(img_element.screenshot_as_png)

        print(f"DdddOCR 识别结果: {captcha_code}")
        driver.find_element(By.ID, "captchaResponse").send_keys(captcha_code)

        login_btn = driver.find_element(By.XPATH, '//*[@id="casLoginForm"]/p[4]/button')
        login_btn.click()

        time.sleep(1)

        login_ggtypt_btn = driver.find_element(By.XPATH, '/html/body/div[1]/div/div/div/div/div[3]/a')
        login_ggtypt_btn.click()
        time.sleep(1)
        book_btn = driver.find_element(By.XPATH, '/html/body/div[1]/div/div/div[3]/div/div[3]/div[1]')
        book_btn.click()
        time.sleep(1)
        suzhou_tennis_btn = driver.find_element(By.XPATH, '/html/body/div[1]/div/div/div[3]/div[2]/div/div[2]/div[6]/div[2]/div[2]/div[2]')
        suzhou_tennis_btn.click()

        time.sleep(1)

        cookie_data = driver.execute_cdp_cmd('Network.getAllCookies', {})
        all_cookies = cookie_data['cookies']
        print(f"抓取到了 {len(all_cookies)} 个 Cookie")

        session = requests.Session()
        session.trust_env = False

        for cookie in all_cookies:
            session.cookies.set(
                name=cookie['name'],
                value=cookie['value'],
                domain=cookie['domain'],
                path=cookie['path']
            )

        print("正在分析浏览器网络日志")

        logs = driver.get_log("performance")
        captured_headers = {}
        found = False

        for entry in logs:
            try:
                message = json.loads(entry["message"])["message"]
                if message["method"] == "Network.requestWillBeSent":
                    params = message["params"]
                    request_url = params["request"]["url"]

                    if "venue/info" in request_url:
                        print(f"命中目标请求: {request_url}")
                        captured_headers = params["request"]["headers"]
                        found = True
                        break
            except:
                continue

        if found:

            clean_headers = {}
            for key, value in captured_headers.items():
                if not key.startswith(":") and key.lower() != "content-length":
                    clean_headers[key] = value

            session.headers.update(clean_headers)
            print("成功复制浏览器 Headers 到 Session！")
            print(session.headers)
        else:
            print("未在日志中找到 venue/info 请求，将使用默认 User-Agent")
            session.headers.update({
                'User-Agent': driver.execute_script("return navigator.userAgent;")
            })

        print("Cookies 转移完毕，当前 Session Cookies:")
        print(session.cookies.get_dict())
        return session
    finally:
        driver.quit()

def aes_encrypt_string(secret_key, text):
    """
    AES ECB模式加密字符串并进行Base64编码
    @param secret_key: 加密密钥，必须是16、24或32字节长
    @param text: 待加密的字符串
    @return: 加密后的Base64编码字符串
    """
    key = secret_key.encode('utf-8')
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_bytes = cipher.encrypt(pad(text.encode('utf-8'), AES.block_size))
    encrypted_base64 = base64.b64encode(encrypted_bytes).decode('utf-8')

    return encrypted_base64

def get_blockPuzzle(session):
    """获取滑块验证码的验证参数 captchaVerification
    """
    url = "https://ggtypt.nju.edu.cn/venue-server/api/captcha/get"
    path = "/api/captcha/get"

    session.headers.pop("Origin", None)
    session.headers.update({
        "Content-Type": "application/x-www-form-urlencoded"
    })
    resp_json = {}
    while not resp_json or resp_json.get("code") == 250:
        timestamp = str(int(time.time() * 1000))
        params = {
            "captchaType": "blockPuzzle",
            "clientUid" : "slider-" + str(uuid.uuid4()),
            "ts" : timestamp,
            "nocache": timestamp
        }

        auto_update_headers(session, path, params,timestamp)

        resp = session.get(url, params=params, verify=False)
        # print(resp.url)
        resp_json = resp.json()

    jigsawImage = base64.b64decode(resp_json["data"]["repData"]["jigsawImageBase64"])
    originalImage = base64.b64decode(resp_json["data"]["repData"]["originalImageBase64"])
    secret_key = resp_json["data"]["repData"]["secretKey"]
    captchaToken = resp_json["data"]["repData"]["token"]

    # jigsawImage = base64.b64decode(jigsawImageBase64)
    # originalImage = base64.b64decode(originalImageBase64)

    ocr = ddddocr.DdddOcr(det=False, ocr=False, show_ad=False)

    res = ocr.slide_match(jigsawImage,originalImage)

    pos = {"x" : res["target"][0], "y" : 5}
    pos["x"] += 0.3030303030303
    text = json.dumps(pos, separators=(',', ':'))

    pointJson = aes_encrypt_string(secret_key, text)

    params = {
        "pointJson" : pointJson,
        "token": captchaToken
    }

    #检查是否正确，但是实际好像没有什么用
    check_url = "https://ggtypt.nju.edu.cn/venue-server/api/captcha/check"
    path = "/api/captcha/check"
    auto_update_headers(session, path, params)
    check_resp = session.post(check_url, params=params, verify=False)
    check_resp_json = check_resp.json()

    if check_resp_json["data"]["success"] != True:
        print("验证码校验失败！重新获取！")
        return get_blockPuzzle(session)

    #submit 时需要的参数captchaVerification
    plain_text = f"{captchaToken}---{json.dumps(pos, separators=(',', ':'))}"
    captcha_verification = aes_encrypt_string(secret_key, plain_text)

    return captcha_verification

def auto_update_headers(session,path,params,timestamp=None):
    if not timestamp:
        timestamp = str(int(time.time() * 1000))
    sign = get_sign(path, params, timestamp)
    session.headers.update({
        "sign": sign,
        "timestamp": timestamp
    })
    return session

def submit_and_pay(session, site_id, date, reservationOrderJson, buddyIds, token):

    """
    提交预约订单并支付
    @param session: 已登录的 requests.Session 对象
    @param site_id: 预约项目的场地ID
    @param date: 预约日期，格式 "YYYY-MM-DD"
    @param reservationOrderJson: 预约订单的 JSON 字符串
    @param buddyIds: 同伴ID列表，如不需要同伴可传入空列表 []
    @param token: 预约令牌
    @return: None
    """

    url = "https://ggtypt.nju.edu.cn/venue-server/api/reservation/order/submit"

    weekStartDate = date #我看不懂呢喃这个参数是何意未，测试时间是星期一，weekStartDate就等于date，但是startday是星期天
    captchaVerification = get_blockPuzzle(session)

    path = "/api/reservation/order/submit"
    params = {
        "venueSiteId" : site_id,
        "reservationDate" : date,
        "reservationOrderJson" : reservationOrderJson,
        "weekStartDate" : date,
        "captchaVerification" : captchaVerification,
        "isOfflineTicket" : 1,
        "token" : token
    }
    # 有一些项目是不需要同伴的，这时候就不传 buddyIds 参数
    if buddyIds:
        buddyIdsText = ",".join(buddyIds)
        params["buddyIds"] = buddyIdsText
    auto_update_headers(session,path,params)
    try:
        session.headers.update({
            "Origin" : "https://ggtypt.nju.edu.cn"
        })
        print("正在发送预约请求...")
        time.sleep(
            2)  # 呢喃大手，实测1.5-1.6偶然可以约上，所有估计就是1.6s足够，保守起见这里设置成2s{'code': 250, 'message': '预约步骤流程耗时异常，订单提交失败', 'data': None}
        resp = session.post(url, data=params, verify=False)
        print(f"响应状态码: {resp.status_code}")
        if resp.status_code == 200:
            # 请求速度太快被gank了，那就再试一次
            return submit_and_pay(session, site_id, date, reservationOrderJson, buddyIds, token)
        print(resp.json())
        venueTradeNo = resp.json()["data"]["orderInfo"]["tradeNo"]
    except Exception as e:
        print(f"请求失败: {e}")

    pay_url = "https://ggtypt.nju.edu.cn/venue-server/api/venue/finances/order/pay"
    path = "/api/venue/finances/order/pay"
    params = {
        "venueTradeNo" : venueTradeNo,
        "isApp" : 0
    }
    auto_update_headers(session,path,params)
    try:
        print("正在发送支付请求...")
        resp = session.post(pay_url, data=params, verify=False)
        print(f"响应状态码: {resp.status_code}")
        print(resp.json())


    except Exception as e:
        print(f"支付失败: {e}")

def get_site_info(session, venueSiteId, date):

    """
    获取具体的项目的场地和时间段信息
    注意，这里的项目是苏州校区体育馆羽毛球这种具体的项目，不是场馆
    @param session: 已登录的 requests.Session 对象
    @param venueSiteId: 项目的场地ID
    @param date: 查询日期，格式 "YYYY-MM-DD"
    @return: 返回项目ID和时间段信息的 JSON 数据
    """

    url = "https://ggtypt.nju.edu.cn/venue-server/api/reservation/day/info"
    path = "/api/reservation/day/info"
    params = {
        "venueSiteId" : venueSiteId,
        "searchDate" : date,
        "nocache": str(int(time.time() * 1000))
    }
    auto_update_headers(session,path,params)
    try:
        print("正在获取场地信息...")
        resp = session.get(url, params=params, verify=False)
        # print(resp.json())
        return resp.json()
    except Exception as e:
        print(f"请求失败: {e}")
        return None

def get_reservation_info(session,venueSiteId,date,reservationOrderJson,token):
    url = "https://ggtypt.nju.edu.cn/venue-server/api/reservation/order/info"
    path = "/api/reservation/order/info"
    params = {
        "venueSiteId" : int(venueSiteId),
        "reservationDate" : date,
        "weekStartDate" : date,
        "reservationOrderJson" : reservationOrderJson,
        "token" : token,
    }
    auto_update_headers(session,path,params)
    session.headers.update({
        "Origin" : "https://ggtypt.nju.edu.cn"
    })

    try:
        print("正在获取预约信息和同伴详情...")
        # resp = session.post(url, params=params, verify=False)
        # print(resp.json())

        resp = session.post(url, data=params, verify=False)
        return resp.json()
    except Exception as e:
        print(f"请求失败: {e}")
        return None

def get_all_gyms(session):
    url = "https://ggtypt.nju.edu.cn/venue-server/api/reservation/campus/venue/info"
    path = "/api/reservation/campus/venue/info"
    params = {
        "nocache": str(int(time.time() * 1000))
    }
    auto_update_headers(session,path,params)
    try:
        print("正在获取所有场馆信息...")
        resp = session.get(url, params=params, verify=False)
        # print(resp.json())
        return resp.json()
    except Exception as e:
        print(f"请求失败: {e}")
        return None

def parse_gym_info(gym_info):
    """
    解析场馆信息并让用户选择场馆和项目
    注意，这里的是场馆和项目：苏州校区体育馆是场馆，羽毛球是项目
    @param gym_info: 场馆信息的 JSON 数据
    @return: 选择的项目ID
    """

    print("\n=== 解析场馆信息 ===")
    gym_info = gym_info["data"]
    campus = {
        "苏州校区": 156,
        "仙林校区": 51,
        "鼓楼校区": 146,
        "浦口校区": 155
    }
    for campusName,campusID in campus.items():
        print(f"----校区: {campusName} (ID: {campusID})----")
        gyms = gym_info["venueInfo"].get(str(campusID), [])
        for gym in gyms:
            gym_name = gym["venueName"]
            gym_id = gym["id"]
            print(f"    场馆ID: {gym_id}, 场馆名称: {gym_name} ")

    site = input("请输入想预约的场馆ID：")
    print("该场馆包含以下项目：")
    for project in gym_info["venueSiteInfo"].get(str(site), []):
        site_id = project["id"]
        site_name = project["siteName"]
        print(f"    项目ID: {site_id}, 项目名称: {site_name} ")

    project_choice = input("请输入想预约的项目ID：")
    return project_choice


def parse_site_info(project_info):
    print("\n=== 解析项目场地信息 ===")
    project_info = project_info["data"]
    reservationToken = project_info["token"]
    reservationStatues = {
        0: "",
        1: "空闲",
        2: "不开放",
        3: "",
        4: "已预约"
    }

    # 打印场地和时间段信息
    for spaceTimeInfo in project_info["spaceTimeInfo"]:
        timePieceID = spaceTimeInfo["id"]
        beginTime = spaceTimeInfo["beginTime"]
        endTime = spaceTimeInfo["endTime"]
        print(f"时间段ID: {timePieceID}, 时间: {beginTime} - {endTime}")

    time_piece_id = input("请输入想预约的时间段ID：")

    reservationDateSpaceInfo = project_info["reservationDateSpaceInfo"]
    today = time.strftime("%Y-%m-%d", time.localtime())
    print(f"日期: {today}")
    spaces = reservationDateSpaceInfo.get(today, [])
    for space in spaces:
        space_name = space["spaceName"]
        space_id = space["id"]
        print(f"  场地: {space_name} (ID: {space_id})")

    space_choice = input("请输入想预约的场地ID：")

    #格式[{"spaceId":"460","timeId":"83320","venueSpaceGroupId":null}]
    reservationOrderJson = json.dumps([{
        "spaceId": space_choice,
        "timeId": time_piece_id,
        "venueSpaceGroupId": None
    }])

    print("你选择的预约信息为：")
    print(reservationOrderJson)

    return reservationToken, reservationOrderJson

def parse_reservation_info(reservation_info):
    print("\n=== 解析预约信息和同伴详情 ===")
    reservation_info = reservation_info["data"]
    buddyNumMin = reservation_info["venueInfoBean"]["buddyNumMin"]
    if buddyNumMin > 0:
        print(f"该项目需要至少 {buddyNumMin} 名同伴。")
        print("可选同伴列表：")
        buddyList = reservation_info["buddyList"]
        for buddy in buddyList:
            buddy_id = buddy["id"]
            buddy_name = buddy["name"]
            print(f"    同伴ID: {buddy_id}, 同伴名称: {buddy_name} ")

        buddy_choices = input(f"请输入至少 {buddyNumMin} 名同伴的ID，多个ID用逗号分隔：")
        buddy_ids = [bid.strip() for bid in buddy_choices.split(",") if bid.strip()]
        if len(buddy_ids) < buddyNumMin:
            print(f"错误：至少需要选择 {buddyNumMin} 名同伴。")
            return None
        print(f"你选择的同伴ID为：{buddy_ids}")
        return buddy_ids
    else:
        print("该项目不需要同伴。")
        return []

def sort_all_campus_venues_data(session):
    raw_data = get_all_gyms(session)
    try:

        if raw_data.get('code') != 200 or 'data' not in raw_data:
            print("错误: JSON 数据状态码不为 200 或缺少 data 字段")
            return
        venue_site_info = raw_data['data'].get('venueSiteInfo', {})

        result_tree = {}

        for venue_id_key, site_list in venue_site_info.items():
            for site in site_list:
                campus_id = str(site.get('campusId'))
                campus_name = site.get('campusName')

                venue_id = str(site.get('venueId'))
                venue_name = site.get('venueName')

                site_id = str(site.get('id'))
                site_name = site.get('siteName')

                if campus_id not in result_tree:
                    result_tree[campus_id] = {
                        "campusID": int(campus_id),
                        "campusName": campus_name,
                        "venues": {}
                    }

                current_campus_venues = result_tree[campus_id]['venues']
                if venue_id not in current_campus_venues:
                    current_campus_venues[venue_id] = {
                        "venueID": int(venue_id),
                        "venueName": venue_name,
                        "sites": {}
                    }
                current_venue_sites = current_campus_venues[venue_id]['sites']

                current_venue_sites[site_id] = {
                    "id": int(site_id),
                    "siteName": site_name
                }
        output_file = "parsed_gym_data.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result_tree, f, ensure_ascii=False, indent=4)

        print(f"成功！数据已整理并保存至: {output_file}")

    except Exception as e:
        print(f"发生未知错误: {e}")

def print_parsed_gyms_data(json_file= "./parsed_gym_data.json", campus_filter=None):
    """
    vibecoding真好用(),以下是哈基米写的
    读取整理后的 JSON 文件，并以美观的树状结构打印到控制台。

    :param json_file: json 文件路径
    :param campus_filter: (可选) 过滤条件，可以是校区ID(int/str) 或 校区名称(str)
                          例如: 155, "51", "仙林", "浦口校区"
    """
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # 准备显示的标题
        if campus_filter:
            title_suffix = f" (筛选条件: {campus_filter})"
        else:
            title_suffix = " (全部)"

        print("\n" + "=" * 60)
        print(f"🏟️  南京大学体育场馆数据总览{title_suffix}")
        print("=" * 60)

        found_count = 0

        # 预处理过滤条件：转为字符串以便比较
        filter_str = str(campus_filter) if campus_filter is not None else None

        # 遍历校区
        for campus_id_key, campus_data in data.items():
            c_name = campus_data.get('campusName', '未知校区')
            c_id = campus_data.get('campusID')

            # --- 筛选逻辑 ---
            if filter_str:
                # 逻辑：如果 ID 不相等 且 名称中也不包含关键词，则跳过
                # str(c_id) == filter_str : 精确匹配 ID
                # filter_str in c_name    : 模糊匹配 名称 (例如输入"仙林"匹配"仙林校区")
                if str(c_id) != filter_str and filter_str not in c_name:
                    continue
            # ----------------

            found_count += 1

            # 打印一级：校区
            print(f"\n📍 [校区] {c_name} (ID: {c_id})")

            venues = campus_data.get('venues', {})
            if not venues:
                print("    └─ (无场馆数据)")
                continue

            # 遍历场馆
            venue_items = list(venues.items())
            for v_idx, (venue_id, venue_data) in enumerate(venue_items):
                v_name = venue_data.get('venueName', '未知场馆')
                v_id = venue_data.get('venueID')

                # 树状图线条控制
                is_last_venue = (v_idx == len(venue_items) - 1)
                v_prefix = "    └─" if is_last_venue else "    ├─"

                # 打印二级：场馆
                print(f"{v_prefix} 🏢 [场馆] {v_name} (ID: {v_id})")

                sites = venue_data.get('sites', {})
                if not sites:
                    v_gap = "        " if is_last_venue else "    │   "
                    print(f"{v_gap}    └─ (无场地数据)")
                    continue

                # 遍历场地
                site_items = list(sites.items())
                for s_idx, (site_id, site_data) in enumerate(site_items):
                    s_name = site_data.get('siteName', '未知场地')
                    s_id = site_data.get('id')

                    # 树状图线条控制
                    is_last_site = (s_idx == len(site_items) - 1)
                    s_prefix = "└─" if is_last_site else "├─"
                    v_gap = "        " if is_last_venue else "    │   "

                    # 打印三级：场地
                    print(f"{v_gap}    {s_prefix} 🏸 {s_name} <ID: {s_id}>")

        # 结尾统计
        print("\n" + "=" * 60)
        if found_count == 0:
            print(f"⚠️  未找到匹配 '{campus_filter}' 的校区信息。")
        else:
            print(f"✅ 打印完成 (共显示 {found_count} 个校区)")
        print("=" * 60 + "\n")

    except json.JSONDecodeError:
        print(f"❌ 错误: {json_file} 文件格式损坏")
    except Exception as e:
        print(f"❌ 发生未知错误: {e}")

def test_reserve_by_hand(session):
    """
    测试函数尝试各个函数可用性的
    :param session:
    :return:
    """
    gyms_info = get_all_gyms(session)
    project_chosen = parse_gym_info(gyms_info)
    # project_chosen = 353  # 这里直接指定项目ID，避免每次运行都要输入

    date = time.strftime("%Y-%m-%d", time.localtime())
    project_info = get_site_info(session, project_chosen, date)
    token, reservationOrderJson = parse_site_info(project_info)
    reservationInfo = get_reservation_info(session, project_chosen, date, reservationOrderJson, token)
    buddyIds = parse_reservation_info(reservationInfo)
    submit_and_pay(session, project_chosen, date, reservationOrderJson, buddyIds, token)


def auto_grab_site(session, id, priorityTimeList=[], buddyIds=[], isFlexible=True):
    """
    自动抢场，id是想要抢的场地id
    :param id:
    :param priorityTimeList: 优先时间段列表，格式为starttime ["08:00","09:00"]，如果为空列表 [] 则表示不指定优先时间段，按系统默认顺序尝试所有时间段
    :param buddyIds: 同伴ID列表，如不需要同伴可传入空列表 []，如果没有指定同伴而项目需要同伴则会随机选择同伴（返回列表的前minBuddyNum个）
    :param isFlexible: 是否灵活选择时间段，如果为True，则在priorityTimeList中找不到可用时间段时会尝试其他时间段
    """
    date = time.strftime("%Y-%m-%d", time.localtime())
    print(f"正在获取 {date} 的场地信息 (ID: {id})...")

    siteInfo = get_site_info(session, id, date)
    if not siteInfo or siteInfo.get("code") != 200:
        print("获取场地信息失败，请检查网络或登录状态。")
        return

    data = siteInfo["data"]
    token = data["token"]
    # spaceTimeInfo 结构: [{"id": 83313, "beginTime": "09:00", ...}, ...]
    time_map = {item["beginTime"]: str(item["id"]) for item in data["spaceTimeInfo"]}

    search_list = []

    # 先加入优先时间段
    for t in priorityTimeList:
        nowTime = time.strftime("%H:%M", time.localtime())
        if t in time_map and t > nowTime:
            search_list.append(t)
        else:
            print(f"提示: 时间段 {t} 在该场地不存在或者已经是过去的时间，已跳过。")

    # 如果灵活模式，将剩余的时间段按顺序加入
    if isFlexible:
        all_times = sorted(time_map.keys())
        for t in all_times:
            if t not in search_list:
                search_list.append(t)

    if not search_list:
        print("错误: 没有可供搜索的时间段。可能是当天全部场次都不能用。")
        return

    found_space_id = None
    found_time_id = None
    found_time_str = None

    # reservationDateSpaceInfo 是一个字典，key是日期，value是场地列表
    # 场地列表结构见 siteinfo.json
    day_spaces = data["reservationDateSpaceInfo"].get(date, [])

    print(f"正在搜索可用场地，搜索顺序: {search_list}")

    for t_str in search_list:
        t_id = time_map[t_str]

        for space in day_spaces:
            # space 结构中，key 为 timeId，value 为状态对象
            # 状态对象中 "reservationStatus": 1 表示空闲
            if t_id in space:
                status_info = space[t_id]
                if status_info and status_info.get("reservationStatus") == 1:
                    found_space_id = str(space["id"])
                    found_time_id = t_id
                    found_time_str = t_str
                    print(f"✅ 成功找到空闲场地! 时间: {t_str}, 场地: {space.get('spaceName')}")
                    break

        if found_space_id:
            break

    if not found_space_id:
        print("❌ 抱歉，未找到符合条件的空闲场地。")
        return

    reservationOrderJson = json.dumps([{
        "spaceId": found_space_id,
        "timeId": found_time_id,
        "venueSpaceGroupId": None
    }])

    res_info = get_reservation_info(session, id, date, reservationOrderJson, token, SERVER_KEY)
    final_buddy_ids = list(buddyIds)  # 复制一份，避免修改默认参数

    if res_info and res_info.get("code") == 200:
        res_data = res_info["data"]
        min_buddy_num = res_data["venueInfoBean"].get("buddyNumMin", 0)

        if min_buddy_num > 0:
            current_count = len(final_buddy_ids)
            if current_count < min_buddy_num:
                print(f"⚠️ 该场地至少需要 {min_buddy_num} 名同伴，当前指定 {current_count} 名，正在自动从列表补充...")

                available_buddies = res_data.get("buddyList", [])
                needed = min_buddy_num - current_count

                pool = [str(b["id"]) for b in available_buddies if str(b["id"]) not in final_buddy_ids]

                if len(pool) < needed:
                    print(f"❌ 账号常用同伴不足！需要补 {needed} 人，实际可用 {len(pool)} 人。")
                    return

                final_buddy_ids.extend(pool[:needed])
                print(f"已自动补充同伴ID: {pool[:needed]}")

    print(f"🚀 开始提交订单... [时间: {found_time_str}]")
    submit_and_pay(session, id, date, reservationOrderJson, final_buddy_ids, token)

    if SERVER_KEY:
        url = f"https://sctapi.ftqq.com/{SERVER_KEY}.send"
        content = f"""### 南京大学体育场馆预约脚本通知
- 预约日期: {date}
- 预约时间: {found_time_str}
- 场地ID: {found_space_id}
- 同伴ID: {', '.join(final_buddy_ids) if final_buddy_ids else '无同伴'}
- 预约状态: {'成功' if found_space_id else '失败'}
- 完成时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}
"""
        data = {
            "title": "南京大学体育场馆预约脚本通知",
            "desp": content
        }
        try:
            resp = requests.post(url, data=data)
            if resp.status_code == 200:
                print("✅ 微信通知发送成功！")
            else:
                print(f"❌ 微信通知发送失败，状态码: {resp.status_code}")
        except Exception as e:
            print(f"❌ 发送微信通知时发生错误: {e}")


def sleep_until(target_time_str):
    """
    休眠直到指定的目标时间点
    :param target_time_str: 目标时间字符串，格式 "HH:MM"
    """
    now = time.localtime()
    t_part = time.strptime(target_time_str, "%H:%M:%S")
    target_time = now.replace(hour=t_part.tm_hour, minute=t_part.tm_min, second=t_part.tm_sec, microsecond=0)

    if now >= target_time:
        print(f"目标时间 {target_time_str} 已经过，跳过等待。")
        return

    while True:
        now = time.localtime()
        diff = (time.mktime(target_time) - time.mktime(now))
        if diff <= 0:
            break

        if diff > 60:
            print(f"距离目标时间 {target_time_str} 还有 {int(diff)} 秒，休眠30秒...")
            time.sleep(30)
        elif diff > 10:
            print(f"距离目标时间 {target_time_str} 还有 {int(diff)} 秒，休眠5秒...")
            time.sleep(5)
        else:
            time.sleep(0.01)


def job(USERNAME, PASSWORD, TARGET_ID, TARGET_BUDDIES, PRIORITY_TIMES, IS_FLEXIBLE, SERVER_KEY):
    print(f"⏰ 任务启动！当前时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}")

    url = "https://authserver.nju.edu.cn/authserver/login?service=https://ggtypt.nju.edu.cn/venue/login"
    session = login(url, USERNAME, PASSWORD)
    if session:
        print("✅ 登录成功，躁候8点")
        sleep_until("08:00:00")
        auto_grab_site(
            session,
            id=TARGET_ID,
            priorityTimeList=PRIORITY_TIMES,
            buddyIds=TARGET_BUDDIES,
            isFlexible=IS_FLEXIBLE)

        print(f"⏰ 任务结束！当前时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}")


if __name__ == "__main__":

    # print_parsed_gyms_data(campus_filter="苏州校区")
    # username = "241880000"
    # password = "password"
    # url = "https://authserver.nju.edu.cn/authserver/login?service=https://ggtypt.nju.edu.cn/venue/login"
    # session = login(url, username, password)
    # if session:
    #     auto_grab_site(
    #         session,
    #         id=171,
    #         priorityTimeList=["19:00", "20:00"],
    #         buddyIds=['114514','20250721'],
    #         isFlexible=True
    #     )

    # 打印项目ID:
    # print_parsed_gyms_data(campus_filter="苏州校区")

    # 更新缓存的所有体育场馆:
    # USERNAME = "241880000"
    # PASSWORD = "password"
    # url = "https://authserver.nju.edu.cn/authserver/login?service=https://ggtypt.nju.edu.cn/venue/login"
    # session = login(url, USERNAME, PASSWORD)
    # if session:
    #     sort_all_campus_venues_data(session)

    # 配置参数
    USERNAME = "241880000"
    PASSWORD = "password"
    TARGET_ID = 171  # 不知道这里的可以调用print_parsed_gyms_data()函数查看，或者直接去看parsed_gym_data.json文件
    TARGET_BUDDIES = ['114514', '20250721']  # 同伴ID列表，如果不知道同伴的id就传入空列表 []
    PRIORITY_TIMES = ["19:00", "20:00"]  # 优先预约的时间段的开始时间，如果不指定时间段就传入空列表 []
    IS_FLEXIBLE = True  # 是否灵活选择时间段，如果为True，则在priorityTimeList中找不到可用时间段时（被占用，未开放等情况）会尝试其他时间段
    SERVER_KEY = ""  # 如果需要微信通知，请填写 Server 酱的 SCKEY，否则留空字符串 ""

    print("🤖 脚本已启动")
    print("📅 计划每天 07:58 自动唤醒登录，08:00 准时开抢")
    print("👉 请不要关闭此窗口，保持电脑唤醒状态...")
    # 设置每天7:58执行任务

    schedule.every().day.at("07:58").do(
        job,
        USERNAME, PASSWORD, TARGET_ID, TARGET_BUDDIES, PRIORITY_TIMES, IS_FLEXIBLE, SERVER_KEY
    )

    while True:
        schedule.run_pending()
        time.sleep(1)
