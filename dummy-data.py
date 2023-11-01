import socket
import struct
import time
import numpy as np


UDP_IP = "127.0.0.1"  # 本机IP地址
UDP_PORT = 12345  # UDP端口号

# 创建UDP套接字
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
while True:
    x = np.linspace(0, 2*np.pi, 2052)
    freq = np.random.uniform(50, 70)
    phase = np.random.uniform(0, np.pi)
    y = np.sin(freq*x + phase)*5
    a =y*np.random.rand(2052)+5 
    b =y*np.random.rand(2052)+5

    # 生成两个长度为2054的float类型数组

    # 将两个数组打包成字节流
    data = struct.pack('2052f', *a) + struct.pack('2052f', *a)
    
    # 发送数据
    sock.sendto(data, (UDP_IP, UDP_PORT))
    time.sleep(0.01)
# 关闭套接字
sock.close()
