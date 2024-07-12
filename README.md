# LANGUAGE 

- [English](#English)
- [中文](#中文)

---

### English

# MyNetWorker
Golang tcp and udp worker.</br>
UdpServer.go is not encrypted.You can encrypt udp data with Aes.go by your self.</br>
AesTcpClient.go is encrypted with AES. AES's key is exchanged with ecc.</br>
</br>
tcpClientBase.go: Implement the most basic connect, disconnect, read, and write operations of TCP communication.</br>
</br>
Package.go: Define a tcp package.</br>
</br>
PackagedTcpClient.go: Inherits the tcpClientBase class. Implement the pairing of the sending package and the reply package</br>
</br>
AesTcpClient.go: Inherits the PackagedTcpClient class. Implement encrypted communication; Realize communication key exchange;</br>
</br>
AesCmd.go: Define AesTcpClient command.</br>
</br>
AesPackage.go: Define AesPackage.</br>
</br>
Aes.go: Implement AES Encryption and Decryption.</br>
</br>
ECC.go: Implement ECC Encryption and Decryption.</br>
</br>
IPHelper.go: Implement some IPv4 functions.</br>
</br>
UdpCmd.go: Define UDP command.</br>
</br>
UdpPackage.go: Define UdpPackage.</br>
</br>
UdpServer.go: Define UDP Server. Implement the most basic read, and write operations of UDP communication.</br>
</br>


---

### 中文

# Golang TCP 和 UDP 通讯类. 

Golang 封装TCP和UDP通讯。 

## TCP通讯类 

TCP通讯类主要解决TCP长连接通讯中以下问题： 

1. 通讯安全问题 
    - 明文传输或固定密钥传输导致的数据泄漏
2. CPU占用高，传输效率低 
    - 传统的TCP通讯协议有包头和包尾标识符，需要逐字节检查包尾标识符，导致CPU占用高，传输效率低下 
3. 粘包 
    - 两个包的数据同时到达：实现拆包处理 
4. 分包 
    - 一个包的数据分多次到达：实现组包处理 
5. 请求包与回复包的配对及超时机制 
    - 由于TCP长连接通常都有独立的线程处理接收包，数据发送与接收在不同的线程中执行，导致回复包与请求包的配对困难、超时判断困难