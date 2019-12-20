import hashlib
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from framework.settings import ACRD_IV, ACRD_KEY, ACRD_PAYCODE


def encrypt(data):
    data = str.encode(data)
    cipher = AES.new(ACRD_KEY, AES.MODE_CBC, ACRD_IV)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    ct = b64encode(ct_bytes).decode('utf-8')
    return ct


def getTransactionPayload(amount, transactionID):
    plaintext = "transactionId=VIDYUT"+str(transactionID)+"|amount="+str(amount)+"|purpose="+str(ACRD_PAYCODE)+"|currency=inr"
    checksum = hashlib.md5(plaintext.encode())
    checksum = checksum.hexdigest()
    pwc = plaintext + "|checkSum=" + checksum
    encodedData = encrypt(pwc)
    return {
        'encdata': encodedData,
        'code': ACRD_PAYCODE
    }
