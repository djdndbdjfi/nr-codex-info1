import asyncio
import time
import httpx
import json
from collections import defaultdict
from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES
import base64
from google.protobuf import json_format, message
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2

app = Flask(__name__)
CORS(app)

# Configuration
CONFIG = {
    "MAIN_KEY": base64.b64decode('WWcmdGMlREV1aDYlWmNeOA=='),
    "MAIN_IV": base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ=='),
    "RELEASEVERSION": "OB49",
    "USERAGENT": "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)",
    "SUPPORTED_REGIONS": {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID", "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EUROPE"},
    "TOKEN_EXPIRY": 25200  # 7 hours
}

# Global state
state = {
    "tokens": defaultdict(dict),
    "initialized": False
}

async def initialize():
    """Initialize the application"""
    if not state["initialized"]:
        await initialize_tokens()
        state["initialized"] = True

def pad(text: bytes) -> bytes:
    """PKCS7 padding for AES encryption"""
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """Encrypt data using AES-CBC"""
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    """Decode protobuf message"""
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

async def json_to_proto(json_data: str, proto_message: message.Message) -> bytes:
    """Convert JSON to protobuf"""
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def get_account_credentials(region: str) -> str:
    """Get credentials for specific region"""
    region = region.upper()
    credentials = {
        "IND": "uid=4025167895&password=EB7D45B6B897206B9B0EE1662D9B4EF9A90B04CFEE404975058B9360C51BD5AE",
        "BD": "uid=3957595605&password=7203510AB3D87E06CE54FC93ABE40D48AA6AEA55E2DEA2D2AA3487CBB20650D7",
        "BR": "uid=3788023112&password=5356B7495AC2AD04C0A483CF234D6E56FB29080AC2461DD51E0544F8D455CC24",
        "US": "uid=3788023112&password=5356B7495AC2AD04C0A483CF234D6E56FB29080AC2461DD51E0544F8D455CC24",
        "SAC": "uid=3788023112&password=5356B7495AC2AD04C0A483CF234D6E56FB29080AC2461DD51E0544F8D455CC24",
        "NA": "uid=3788023112&password=5356B7495AC2AD04C0A483CF234D6E56FB29080AC2461DD51E0544F8D455CC24",
    }
    return credentials.get(region, "uid=3301239795&password=DD40EE772FCBD61409BB15033E3DE1B1C54EDA83B75DF0CDD24C34C7C8798475")

async def get_access_token(account: str):
    """Get access token from authentication server"""
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = f"{account}&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        'User-Agent': CONFIG["USERAGENT"],
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded"
    }
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            resp = await client.post(url, data=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            return data.get("access_token", "0"), data.get("open_id", "0")
        except (httpx.HTTPError, json.JSONDecodeError) as e:
            raise Exception(f"Failed to get access token: {str(e)}")

async def create_jwt(region: str):
    """Create JWT token for a specific region"""
    try:
        account = get_account_credentials(region)
        token_val, open_id = await get_access_token(account)
        
        body = json.dumps({
            "open_id": open_id,
            "open_id_type": "4",
            "login_token": token_val,
            "orign_platform_type": "4"
        })
        
        proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
        payload = aes_cbc_encrypt(CONFIG["MAIN_KEY"], CONFIG["MAIN_IV"], proto_bytes)
        
        url = "https://loginbp.ggblueshark.com/MajorLogin"
        headers = {
            'User-Agent': CONFIG["USERAGENT"],
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': CONFIG["RELEASEVERSION"]
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, data=payload, headers=headers)
            resp.raise_for_status()
            
            msg = json.loads(json_format.MessageToJson(
                decode_protobuf(resp.content, FreeFire_pb2.LoginRes())
            ))
            
            state["tokens"][region] = {
                'token': f"Bearer {msg.get('token','0')}",
                'region': msg.get('lockRegion','0'),
                'server_url': msg.get('serverUrl','0'),
                'expires_at': time.time() + CONFIG["TOKEN_EXPIRY"]
            }
            
    except Exception as e:
        raise Exception(f"Failed to create JWT for region {region}: {str(e)}")

async def initialize_tokens():
    """Initialize tokens for all supported regions"""
    tasks = [create_jwt(r) for r in CONFIG["SUPPORTED_REGIONS"]]
    await asyncio.gather(*tasks, return_exceptions=True)

async def get_token_info(region: str):
    """Get token information for a region, refreshing if expired"""
    region = region.upper()
    token_info = state["tokens"].get(region)
    
    if not token_info or time.time() >= token_info['expires_at']:
        await create_jwt(region)
        token_info = state["tokens"][region]
    
    return token_info['token'], token_info['region'], token_info['server_url']

async def get_player_region(uid: str):
    """Get player's region by UID"""
    url = "https://shop2game.com/api/auth/player_id_login"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": CONFIG["USERAGENT"]
    }
    payload = {
        "app_id": 100067,
        "login_id": uid,
        "app_server_id": 0,
    }
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data.get('region', '').upper()
        except (httpx.HTTPError, json.JSONDecodeError):
            return ""

async def GetAccountInformation(uid: str, unk: str = "7", endpoint: str = "/GetPlayerPersonalShow"):
    """Get account information for a player"""
    try:
        # First detect the region from UID
        region = await get_player_region(uid)
        if not region or region not in CONFIG["SUPPORTED_REGIONS"]:
            raise ValueError(f"Could not determine valid region for UID: {uid}")
        
        # Get token and server info
        token, lock, server = await get_token_info(region)
        
        # Prepare payload
        payload = await json_to_proto(
            json.dumps({'a': uid, 'b': unk}),
            main_pb2.GetPlayerPersonalShow()
        )
        data_enc = aes_cbc_encrypt(CONFIG["MAIN_KEY"], CONFIG["MAIN_IV"], payload)
        
        # Make request
        headers = {
            'User-Agent': CONFIG["USERAGENT"],
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'Expect': "100-continue",
            'Authorization': token,
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': CONFIG["RELEASEVERSION"]
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(server + endpoint, data=data_enc, headers=headers)
            resp.raise_for_status()
            
            return json.loads(json_format.MessageToJson(
                decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo())
            ))
            
    except Exception as e:
        raise Exception(f"Failed to get account information: {str(e)}")

def format_response(data):
    """Format the response data"""
    if not data:
        return {"error": "No data received"}
    
    return {
        "status": "success",
        "data": {
            "basicInfo": {
                "uid": data.get("basicInfo", {}).get("uid"),
                "nickname": data.get("basicInfo", {}).get("nickname"),
                "level": data.get("basicInfo", {}).get("level"),
                "exp": data.get("basicInfo", {}).get("exp"),
                "liked": data.get("basicInfo", {}).get("liked"),
                "region": data.get("basicInfo", {}).get("region"),
                "headPic": data.get("basicInfo", {}).get("headPic"),
                "bannerId": data.get("basicInfo", {}).get("bannerId"),
                "createAt": data.get("basicInfo", {}).get("createAt"),
                "lastLoginAt": data.get("basicInfo", {}).get("lastLoginAt"),
                "rankingPoints": data.get("basicInfo", {}).get("rankingPoints"),
                "maxRank": data.get("basicInfo", {}).get("maxRank"),
            },
            "clanInfo": {
                "clanName": data.get("clanBasicInfo", {}).get("clanName"),
                "clanLevel": data.get("clanBasicInfo", {}).get("clanLevel"),
                "memberNum": data.get("clanBasicInfo", {}).get("memberNum"),
            }
        }
    }

@app.route('/player-info', methods=['GET'])
async def player_info():
    """Endpoint to get player information"""
    try:
        await initialize()
        uid = request.args.get('uid')
        
        if not uid:
            return jsonify({"error": "UID parameter is required"}), 400
        
        player_data = await GetAccountInformation(uid)
        formatted = format_response(player_data)
        return jsonify(formatted), 200
        
    except Exception as e:
        return jsonify({
            "error": "Failed to fetch player information",
            "details": str(e)
        }), 500

@app.route('/refresh-tokens', methods=['POST'])
async def refresh_tokens():
    """Endpoint to refresh tokens"""
    try:
        await initialize_tokens()
        return jsonify({"status": "success", "message": "Tokens refreshed"}), 200
    except Exception as e:
        return jsonify({"error": "Failed to refresh tokens", "details": str(e)}), 500

@app.before_request
async def before_request():
    """Initialize before each request if needed"""
    if not state["initialized"]:
        await initialize()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
