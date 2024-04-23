import requests
import json
import random
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES,PKCS1_v1_5,PKCS1_OAEP
from Cryptodome.Random import get_random_bytes
import base64
import string
from Cryptodome.Util import Counter
import time
from bypass_ssl_v3 import get_legacy_session
requests = get_legacy_session()
class BIDV:
    def __init__(self, username, password, account_number):
        self.file = f"data/{username}.txt"
        self.captcha_key = '9bf19cdde5b4a2823228da8203e11950'
        self.default_public_key = "-----BEGIN PUBLIC KEY-----\r\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy6bC9ub46VDwZL5rwtbW\r\n2vBlHsqGzn6kr8OX7dKn+jHZxJxHSOGwTlqi+/QsSZ8wbUDkyK66atYB4Y06j1HS\r\nRimLG2zKK6BwqtMwM1VBwepy6nB+JsbobmvDInU/8cArdQRVNwWMHWwV0ZB0a3wp\r\nFCvVSwF61zFh5aG1Gbfvkbwdh4bpRa860MTyK19+rRXboROQmQYXfLWbrsI7vc3Q\r\nFRfgHIdh3baVd0mjmgMhE9yXwzroOxd418aWUQ9eSY1xmEmX9QynG9dYBMl/zzuS\r\nmM6CfJwKdsswKF0vmhRSLOBv+j/jABADcnrcIhcBS3EnTtSXDQPn/O/osqvRu5q\r\nxvQIDAQAB\r\n-----END PUBLIC KEY-----"
        self.key_anticaptcha = "f3a44e66302c61ffec07c80f4732baf3"
        self.client_public_key = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCLDAD6Wr+W7SXLJMECvt3/W9zMmVcbzwUniO7vYLBJDOEcWJoci5TrfAXlA+z3vxLmEKif41f6wlDBiY+Njj0fNkVH9w+dBbIz2CBaB8RsoDSFYA5zzUbdXfVMV+fs3o3nK/dDAZNX1MU96cISsgQTe+dIIkpMs3jSFvrxjtGg+wIDAQAB"
        self.client_private_key = """-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCLDAD6Wr+W7SXLJMECvt3/W9zMmVcbzwUniO7vYLBJDOEcWJoc
i5TrfAXlA+z3vxLmEKif41f6wlDBiY+Njj0fNkVH9w+dBbIz2CBaB8RsoDSFYA5z
zUbdXfVMV+fs3o3nK/dDAZNX1MU96cISsgQTe+dIIkpMs3jSFvrxjtGg+wIDAQAB
AoGAWyToMzNvKPCUeH/EIReaD3xY1KijJ/Bg0ZR6AuGfTJMrsFgH1TRNzrqCZqdX
GuLd8X7z+bKdhhr/so2IUuLs/uF8/dQHtT9TxFoM2SPsgAqWZlxPOUZ+cBdNEv94
JA9JywJQBuPTrnojrgcsODW3zOCMmiSWEr8lRtKZY/cvgWkCQQDbVqoKUl4T7yt2
Dz8DxcZvgHMqyzvZyuYXLWyCg+cc6pd9iJ0uJdVe7YEE7bVoyHEBCF/6ufF53UuE
dHPAnknPAkEAokm4A42/6BWFgL5R0UdDCoIp03ODn1GRo3Bcte/4b2Jm9pXsZrYS
lwKyT66UuwXzcG1qkeLY33H0Zo6tC9z9FQJAf42GlToRO8Z6n81999Or8mvgjaJi
y+USqafg0oWigU5rirVHsu6NhwbXYOZb+POXw+H67vPzWcs3f2+5YOqsQQJAbEDI
YnZ3gJR6jTpm0Ta73ZKd29K+BdQfVepprWL5UTNOg0XWf10MYXcHAmfuBiMeE+yo
nc+34rTc1lxtyfALUQJBANCy9hPELiv+c36RT7XISDfEX2ZwOo12yexNb545dL8n
5whUm8qm5P9OAGgPgHBIVbOVp8qdHmRr1FT/qJt/LFw=
-----END RSA PRIVATE KEY-----
"""
        self.url = {
            "getCaptcha": "https://smartbanking.bidv.com.vn/w2/captcha/",
            "auth": "https://smartbanking.bidv.com.vn/w2/auth",
            "process": "https://smartbanking.bidv.com.vn/w2/process"
        }
        self.lang = 'vi'
        self.timeout = 60
        self.DT = "WINDOWS"
        self.E = ""
        self.OV = "111.0.0.0"
        self.PM = "Chrome"
        self.app_version = "2.4.1.15"
        self.captcha_token = ""
        self.captcha_value = ""
        self.username = username
        self.password = password
        self.account_number = account_number
        self.session_id = ""
        self.mobile_id = ""
        self.client_id = ""
        self.cif = ""
        self.token = ""
        self.access_token = ""
        self.auth_token = ""
        self.is_login = False

        if not self.file_exists():
            self.username = username
            self.account_number = account_number
            self.client_id = ""
            self.E = ""
            self.save_data()
        else:
            self.parse_data()

    def file_exists(self):
        try:
            with open(self.file, "r"):
                return True
        except FileNotFoundError:
            return False

    def save_data(self):
        data = {
            "username": self.username,
            "password": self.password,
            "account_number": self.account_number,
            "session_id": self.session_id,
            "mobile_id": self.mobile_id,
            "client_id": self.client_id,
            "cif": self.cif,
            "token": self.token,
            "access_token": self.access_token,
            "E": self.E,
            "auth_token": self.auth_token,
        }
        with open(self.file, "w") as file:
            json.dump(data, file)

    def parse_data(self):
        with open(self.file, "r") as file:
            data = json.load(file)
            self.username = data["username"]
            self.password = data["password"]
            self.account_number = data["account_number"]
            self.session_id = data["session_id"]
            self.mobile_id = data["mobile_id"]
            self.client_id = data["client_id"]
            self.token = data["token"]
            self.access_token = data["access_token"]
            self.auth_token = data["auth_token"]
            self.cif = data["cif"]
            self.E = data["E"]

    def do_login(self):
        solve_captcha = self.solve_captcha()
        if not solve_captcha["success"]:
            return solve_captcha

        params = {
            "DT": self.DT,
            "E": self.E,
            "OV": self.OV,
            "PM": self.PM,
            "appVersion": self.app_version,
            "captchaToken": self.captcha_token,
            "captchaValue": self.captcha_value,
            "clientId": self.client_id,
            "mid": 1,
            "pin": self.password,
            "user": self.username,
        }
        result = self.curl_post(self.url["auth"], params)
        if result["code"] == '00':
            if "accessToken" in result:
                data = result
                self.session_id = data["sessionId"]
                self.access_token = data["accessToken"]
                self.save_data()
                if "loginType" in result and result["loginType"] == '1':
                    self.save_data()
                    return {
                    'code': 200,
                    'success': True,
                    'message': 'Đăng nhập thành công',
                    "data": result if result else "",
                }
            else:
                if "loginType" in result and result["loginType"] == '3':
                    print('Vui lòng nhập mã xác thực từ điện thoại')
                    self.token = result["token"]
                    self.save_data()
                    return {
                        'code': 302,
                        'success': True,
                        'message': 'Vui lòng nhập mã xác thực từ điện thoại',
                        'data': result if result else "",

                    }
                elif "loginType" in result and result["loginType"] == '8':
                    print('Vui lòng xác thực từ điện thoại')
                    self.token = result["token"]
                    self.save_data()
                    check_confirm = self.check_confirm_loop()
                    if check_confirm["success"]:
                        return {
                            'code': 200,
                            'success': True,
                            'message': 'Xác thực đăng nhập thành công',
                            "data": check_confirm['data'] if check_confirm and 'data' in check_confirm else "",
                        }

                    else:
                        return check_confirm
        else:
            return {
                "success": False,
                "message": result["des"],
                "data": result if result else "",
            }

    def verify_otp(self, otp):
        self.E = "".join(
            random.choices(string.ascii_letters + string.digits, k=10)
        ) + self.username

        data = {
            "user": self.username,
            "clientId": self.client_id,
            "location": "",
            "otp": otp,
            "mid": 56,
            "DT": self.DT,
            "E": self.E,
            "OV": self.OV,
            "PM": self.PM,
            "appVersion": self.app_version,
            "token": self.token,
        }
        res = self.curl_post(self.url["auth"], data)

        if res["code"] == "00":
            self.session_id = res["sessionId"]
            self.access_key = res["accessKey"]
            self.cif = res["cif"]
            self.access_token = res["accessToken"]
            self.client_id = res["clientId"]
            self.save_data()

            return {"code":200,"success": True, "message": res["des"], "data": res}
        else:
            return {"code":400,"success": False, "message": res["des"], "data": res}

    def check_confirm(self):
        self.E = "".join(
            random.choices(string.ascii_letters + string.digits, k=10)
        ) + self.username
        data = {
        "user": self.username,
        "token": self.token,
        "mid": 30,
        "DT": self.DT,
        "E": self.E,
        "OV": self.OV,
        "PM": self.PM,
        "appVersion": self.app_version,
        "clientId": self.username
        }
        res = self.curl_post(self.url["auth"], data)
        
        return res
    def trust_device(self):
        self.E = "".join(
            random.choices(string.ascii_letters + string.digits, k=10)
        ) + self.username

        data = {
            "user": self.username,
            "clientId": self.client_id,
            "location": "",
            "otp": "",
            "mid": 56,
            "DT": self.DT,
            "E": self.E,
            "OV": self.OV,
            "PM": self.PM,
            "appVersion": self.app_version,
            "token": self.token,
        }
        res = self.curl_post(self.url["auth"], data)
    def check_confirm_loop(self):
        i = 1
        while True:
            if i >= 10:
                return {"code":408,"success": False, "message": "Quá thời hạn xác thực, vui lòng thử lại!"}
            check_confirm = self.check_confirm()
            if check_confirm['code'] == '00':
                self.session_id = check_confirm["sessionId"]
                self.access_key = check_confirm["accessKey"]
                self.cif = check_confirm["cif"]
                self.access_token = check_confirm["accessToken"]
                self.client_id = check_confirm["clientId"]
                self.save_data()
                return {"code":200,"success": True, "message": check_confirm["des"], "data": check_confirm}       
            else:
                time.sleep(5)
            i += 1
    def get_transactions(self, acc_no):
        balance_result = self.get_balance(acc_no)
        if "success" in balance_result and balance_result["success"]:
            
            params = {
                "DT": self.DT,
                "E": self.E,
                "OV": self.OV,
                "PM": self.PM,
                "appVersion": self.app_version,
                "clientId": self.client_id,
                "accType": "D",
                "accNo": acc_no,
                "mid": 12,
                "serviceTypeCode": "",
                "transId": 0,
            }
            result = self.curl_post(self.url["process"], params, headers={"Authorization": self.auth_token})
            if result['code'] == '00' and 'txnList' in result:
                return {'code':200,'success': True, 'message': 'Thành công',
                                'data':{
                                    'transactions':result['txnList'],
                        }}
            else:
                return  {
                        "success": False,
                        "code": 503,
                        "message": "Service Unavailable!"
                    }
        return balance_result

    def get_balance(self,account_number):
        params = {
            "DT": self.DT,
            "E": self.E,
            "OV": self.OV,
            "PM": self.PM,
            "appVersion": self.app_version,
            "clientId": self.client_id,
            "accType": "D",
            "mid": 10,
            "isCache": False,
            "maxRequestInCache": False,
        }
        result = self.curl_post(self.url["process"], params, headers={"Authorization": self.auth_token})
        if 'accList' in result:
            for account_info in result['accList']:
                if account_info['accNo'] == account_number:
                    account_balance = account_info['balance']
                    if int(account_balance) < 0:
                        return {'code':448,'success': False, 'message': 'Blocked account with negative balances!',
                                'data': {
                                    'balance':int(account_balance)
                                }
                                } 
                    else:
                        return {'code':200,'success': True, 'message': 'Thành công',
                                'data':{
                                    'account_number':self.account_number,
                                    'balance':int(account_balance)
                        }}
            return {'code':404,'success': False, 'message': 'account_number not found!'} 
        else:
            return {'code':401 ,'success': False, 'message': 'Please relogin!'}

    def get_captcha(self):
        self.captcha_token = "".join(random.choices(string.ascii_letters + string.digits, k=30))
        response = requests.get(self.url["getCaptcha"] + self.captcha_token, headers={"user-agent": self.get_user_agent()})
        result = base64.b64encode(response.content).decode("utf-8")
        return result
    def createTaskCaptcha(self, base64_img):
        url = 'http://103.72.96.214:8277/api/captcha/bidv'
        payload = json.dumps({
        "base64": base64_img
        })
        headers = {
        'Content-Type': 'application/json'
        }
        response = requests.post(url, headers=headers, data=payload)
        return response.text


    def checkProgressCaptcha(self, task_id):
        url = 'https://api.anti-captcha.com/getTaskResult'
        data = {
            "clientKey": self.key_anticaptcha,
            "taskId": task_id
        }
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        response = requests.post(url, headers=headers, data=json.dumps(data))
        response_json = json.loads(response.text)
        if response_json["success"] != "ready":
            time.sleep(1)
            return self.checkProgressCaptcha(task_id)
        else:
            return response_json["solution"]["text"]
    def solve_captcha(self):
        get_captcha = self.get_captcha()
        task = self.createTaskCaptcha(get_captcha)
        captchaText =json.loads(task)['captcha']
        if not captchaText:
            return {"success": False, "msg": "Solve Captcha failed"}
        else:
            self.captcha_value = captchaText
            return {"success": True, "key": self.captcha_token, "captcha": self.captcha_value}

    # def encrypt_data_2(self, data):
    #     data["clientPubKey"] = self.client_public_key
    #     key = get_random_bytes(32)
    #     iv = get_random_bytes(16)
    #     rsa_key = RSA.import_key(self.default_public_key)
    #     cipher_rsa = PKCS1_OAEP.new(rsa_key)
    #     encrypted_key = base64.b64encode(cipher_rsa.encrypt(key)).decode("utf-8")
    #     cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    #     encryptor = cipher.encryptor()
    #     # encrypted_data = iv + cipher.encrypt(json.dumps(data).encode("utf-8"))

    #     encrypted_data = iv + encryptor.update(json.dumps(data).encode('utf-8')) + encryptor.finalize()
    #     return {"d": base64.b64encode(encrypted_data).decode("utf-8"), "k": encrypted_key}
    
    def encrypt_data(self, data):
        url = "https://encrypt.pay2world.org/api.php?act=encrypt"

        payload = json.dumps(data)
        headers = {
        'Content-Type': 'application/json',
        }
        response = requests.request("POST", url, headers=headers, data=payload)

        return json.loads(response.text)

    def decrypt_data_2(self, cipher):
        encrypted_key = base64.b64decode(cipher["k"])
        rsa_key = RSA.import_key(self.client_private_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        key = cipher_rsa.decrypt(encrypted_key)
        iv = base64.b64decode(cipher["d"])[:16]
        encrypted_data = base64.b64decode(cipher["d"])[16:]
        cipher = AES.new(key, AES.MODE_CFB, iv)
        decrypted_data = cipher.decrypt(encrypted_data).decode("utf-8")
        return json.loads(decrypted_data)
    
    def decrypt_data(self, cipher):
        url = "https://encrypt.pay2world.org/api.php?act=decrypt"

        payload = json.dumps(cipher)
        headers = {
        'Content-Type': 'application/json',
        }
        response = requests.request("POST", url, headers=headers, data=payload)

        return json.loads(response.text)

    def curl_post(self, url, data, headers=None):
        try:
            headers = self.header_null(headers)
            encrypted_data = self.encrypt_data(data)
            response = requests.post(url, headers=headers, data=json.dumps(encrypted_data), timeout=self.timeout)
            result = response.json()
            self.auth_token = response.headers.get("Authorization")
            return self.decrypt_data(result)
        except requests.exceptions.RequestException as e:
            if e.response.status_code == 403:
                return {"success": False, "msg": "Token hết hạn vui lòng đăng nhập lại"}

            response = e.response.content.decode("utf-8")
            return self.decrypt_data(json.loads(response))

    def header_null(self, headers=None):
        default_headers = {
            "Accept-Language": "vi",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": self.get_user_agent(),
            "Host": "smartbanking.bidv.com.vn",
            "Origin": "https://smartbanking.bidv.com.vn",
            "Referer": "https://smartbanking.bidv.com.vn/",
        }
        if headers:
            default_headers.update(headers)
        return default_headers

    def get_user_agent(self):
        user_agent_array = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36"
        ]
        return random.choice(user_agent_array)


# username = "0868124631"
# password = "Cuong7788@"
# account_number = "8851516111"
# bidv = BIDV(username, password, account_number)
# balance_result = bidv.get_balance(account_number)
# if "success" in balance_result and balance_result["success"]:
#         print(balance_result)
#         transactions_result = bidv.get_transactions(account_number)
#         print(transactions_result)
# else:
#     login_result = bidv.do_login()
#     print(login_result)
#     if "success" in login_result and login_result['success']:
#         if login_result['message'] == 'Vui lòng nhập OTP':
#             otp = input("Enter OTP: ")
#             verify_otp_result = bidv.verify_otp(otp)
#             if verify_otp_result["success"]:
#                 print("OTP verification successful")
#                 balance_result = bidv.get_balance(account_number)
#                 print(balance_result)
#             else:
#                 print(f"OTP verification failed: {verify_otp_result['des']}")
#         elif login_result['message'] == 'Vui lòng xác thực đăng nhập trên điện thoại':
#             otp = print("Vui lòng xác thực đăng nhập trên điện thoại...")
#             check_confirm = bidv.check_confirm_loop()
#             # check_confirm = bidv.check_confirm_loop()
#             # print(check_confirm)
#             if check_confirm["success"]:
#                 print("Confirm login successfully")
#                 balance_result = bidv.get_balance(account_number)
#                 print(balance_result)
#                 transactions_result = bidv.get_transactions(account_number)
#                 print(transactions_result)
#             else:
#                 print(f"Confirm login failed: {check_confirm['des']}")
#         else:
#             balance_result = bidv.get_balance(account_number)
#             print(balance_result)
#             transactions_result = bidv.get_transactions(account_number)
#             print(transactions_result)
            
#     else:
#         print(f"Login failed: {login_result['message']}")

