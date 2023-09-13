# MyNetWorker
Golang tcp and udp worker.</br>
UdpServer.go is not encrypted.</br>
EccTcpClient.go is encrypted with AES. AES's key is exchanged with ecc.</br>
</br>
tcpClientBase.go: Implement the most basic connection, disconnection, read, and write operations of TCP communication.</br>
</br>
Package.go: Define a tcp package.</br>
</br>
PackagedTcpClient.go: Inherits the tcpClientBase class. Implement the pairing of the sending package and the reply package</br>
</br>
EccTcpClient.go: Inherits the PackagedTcpClient class. Implement encrypted communication; Realize communication key exchange;</br>
</br>
EccCmd.go: Define EccTcpClient command.</br>
</br>
EccPackage.go: Define EccPackage.</br>
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
