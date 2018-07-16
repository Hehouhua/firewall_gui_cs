import rsa
key = rsa.newkeys(1200)#生成随机秘钥
privateKey = key[1]#私钥
publicKey = key[0]#公钥
message ='5555555555555555555555555555555555555555555555555555555555555555555.'

message = message.encode()
cryptedMessage = rsa.encrypt(message, publicKey)
message = rsa.decrypt(cryptedMessage, privateKey)
message = message.decode()
print(message)


message = message.encode()
cryptedMessage = rsa.encrypt(message, privateKey)
message = rsa.decrypt(cryptedMessage, publicKey)
message = message.decode()
print(message)