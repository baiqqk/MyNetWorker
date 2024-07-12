# README
[简体中文](./README.zh_cn.md) 

[English](./README.md) 

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
