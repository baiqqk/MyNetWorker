# MyNetWorker
Golang tcp and udp worker.</br>
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