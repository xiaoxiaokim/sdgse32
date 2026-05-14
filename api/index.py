from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import time

app = Flask(__name__)
CORS(app)

# 这里是你的命根子，必须是 16 位！
SECRET_KEY = b"1234567890123456" 
IV = b"abcdefgh12345678"

@app.route('/')
def home():
    return "Server is running!"

@app.route('/auth', methods=['POST'])
def verify():
    try:
        data = request.get_json()
        user_token = data.get("token")
        current_uid = data.get("uid")

        # 1. 解密
        decoded_data = base64.b64decode(user_token)
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)
        pt_bytes = unpad(cipher.decrypt(decoded_data), 16)
        pt_str = pt_bytes.decode('utf-8')

        # 2. 拆分 Token (格式: 机器码|过期时间戳)
        token_uid, expire_at = pt_str.split("|")

        # 3. 校验
        server_now = int(time.time())
        if token_uid == current_uid:
            if server_now < int(expire_at):
                return jsonify({"code": 200, "msg": "授权成功"}), 200
            else:
                return jsonify({"code": 403, "msg": "授权已过期"}), 200
        else:
            return jsonify({"code": 403, "msg": "机器码不匹配"}), 200
            
    except:
        return jsonify({"code": 500, "msg": "无效授权"}), 200

# 必须保留
def handler(event, context):
    return app(event, context)
