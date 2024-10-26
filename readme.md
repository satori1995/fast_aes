**在程序开发中，特别是对安全性要求较高的支付系统，数据加密是必不可少的。而提到加密，最常见的莫过于 AES，这里我基于开源的 AES 的 C 实现，封装了一个 Python 扩展，能够同时保证速度和安全性。**

~~~Python
import fast_aes
import orjson

aes = fast_aes.FastAES()
aes.set_key(b"hello world")  # 加盐（可选）

origin_data = {"name": "中森明菜", "age": 18, "gender": "female"}
# 对数据进行加密，接收一个 bytes 对象
encrypted_data = aes.encrypt(orjson.dumps(origin_data))
print(encrypted_data)
"""
b'\xda\x8f%\x90d\x05=u\x9d\xa2\x94\x95\xa9\xf2K,\xfdy\xb2\x9fx%yOMKx<H\x91\x07b\xe4\xc0\x17......'
"""
# 对加密后的数据进行解密
print(orjson.loads(aes.decrypt(encrypted_data)))
"""
{'name': '中森明菜', 'age': 18, 'gender': 'female'}
"""
~~~

