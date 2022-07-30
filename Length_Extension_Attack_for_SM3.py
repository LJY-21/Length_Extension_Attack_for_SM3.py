from gmssl import sm3,func
import random
import extension_sm3

secret = str(random.random())   #生成随机浮点数作为保密消息，且该消息的长度已知
secret_hash = sm3.sm3_hash(func.bytes_to_list(bytes(secret, encoding='utf-8')))
secret_len = len(secret)
extend_msg = "20220727"         #指定的附加消息
print("生成的随机保密消息为：%s，指定的附加消息为：%s"% (secret,extend_msg))

def padding(msg):
    len1 = len(msg)
    reserve1 = len1 % 64
    msg.append(0x80)
    reserve1 = reserve1 + 1
    range_end = 56
    if reserve1 > range_end:
        range_end = range_end + 64
    for i in range(reserve1, range_end):
        msg.append(0x00)
    bit_length = len1 * 8
    bit_length_str = [bit_length % 0x100]
    for i in range(7):
        bit_length = int(bit_length / 0x100)
        bit_length_str.append(bit_length % 0x100)
    for i in range(8):
        msg.append(bit_length_str[7 - i])
    return msg

def get_guess_hash(secret_hash, secret_len, extend_msg):
    #通过secret_hash获得当前8个向量值
    vectors = []
    for i in range(8):
        vectors.append(int(secret_hash[i * 8:(i + 1) * 8], 16))
    #以等长的任意字符串代替secret，在填充后级联extend_msg
    message = [65 for i in range(secret_len)]
    message = padding(message)
    old_len = len(message)
    message.extend(func.bytes_to_list(bytes(extend_msg, encoding='utf-8')))
    ret = extension_sm3.extension_sm3_hash(message, vectors, old_len)
    return ret

#验证get_guess_hash的结果是否正确
message = func.bytes_to_list(bytes(secret, encoding='utf-8'))
message = padding(message)
message.extend(func.bytes_to_list(bytes(extend_msg, encoding='utf-8')))
guess_hash = get_guess_hash(secret_hash, secret_len, extend_msg)
right_hash = sm3.sm3_hash(message)
print("长度扩展攻击猜测hash结果为：\t%s" % guess_hash)
print("正确hash结果为：\t\t\t%s" % right_hash)
if(guess_hash == right_hash):
    print("攻击成功")
else:
    print("攻击失败")





