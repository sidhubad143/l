import requests

url = "https://loginbp.ggblueshark.com/MajorRegister"

# Your hex string without spaces, or convert properly
hex_string = "9A47AF9C2616135D3F08DE11EAE53A763408890B820ACBAC033BEE8982354616B26A2EE3F3EB93E813A4335924BAE96D20A78A45A822A46569E742301E87037A3787A480743B2E150C35E444D5A3352FC493782AF432B3D227E86409015E3B1FB1B429BECCE3C53AB985069815661167BB26CA710DF8AA2A8A993C384D7EC1906EC3DB9D1DB62B12DCAE6369A4065F88B2D303A3B3A94211C3FC764A82B86ECD73BF087ECEDF1B704C067FB2D236E236"

# Convert hex string to bytes
payload = bytes.fromhex(hex_string)

headers = {
    'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 15; I2404 Build/AP3A.240905.015)",
    'Connection': "Keep-Alive",
    'Accept-Encoding': "gzip",
    'Content-Type': "application/octet-stream",
    #'Authorization': "Bearer",
    'X-Unity-Version': "2018.4.11f1",
    'X-GA': "v1 1",
    'ReleaseVersion': "OB50",
}

response = requests.post(url, data=payload, headers=headers)
print(f"Status code: {response.status_code}")
print("Response text:")
print(response.text)
