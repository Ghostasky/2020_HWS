import base64
from pyDes import *

word = [102, 67, 119, 112, 103, 86, 72, 55, 124, 88, 93, 74, 85, 56, 37, 107, \
        95, 114, 127, 124, 65, 124, 102, 78, 76, 106, 106, 105, 40, 36, 93, 115]
key = "poi7y6gt"
string = "" 
for i in range(32):
    word[i]=word[i]^i
    
for i in word:
    string+=chr(i)
    
print string
dec = base64.decodestring(string)

iv = "\x01\x02\x03\x04\x05\x06\x07\x08"
xx = des(key,CBC,iv,pad=None,padmode=PAD_PKCS5)
result = xx.decrypt(dec)
print result