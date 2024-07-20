# 语言 
[English](README.md) 

[简体中文](README.zh_cn.md) 

# Golang TCP 和 UDP 通讯类. 

Golang 封装安全性极高的长连接TCP和明文UDP通讯。 



## TCP长连接通讯类 

TCP通讯类主要解决TCP长连接通讯中以下问题： 

1. 通讯安全问题 
    - 明文传输或固定密钥传输导致的数据泄漏
2. CPU占用高，传输效率低 
    - 传统的TCP通讯协议有包头和包尾标识符，需要逐字节检查包头和包尾标识符，导致CPU占用高，传输效率低下 
3. 粘包 
    - 两个包的数据同时到达，应用程序需要额外做包分离操作 
4. 分包 
    - 一个包的数据分多次到达：应用程序需要额外做组包处理 
5. 请求包与回复包的配对及超时机制 
    - 由于TCP长连接通常都有独立的线程处理接收包，数据发送与接收在不同的线程中执行，导致回复包与请求包的配对困难、超时判断困难 

### 解决TCP通讯安全问题的原理 

TCP通讯安全问题主要有两点：明文传输导致的数据泄漏；固定密钥传输因密钥泄漏导致的数据泄漏。 

另外还有一种情况是TCP劫持。这种情况在解决上面两个问题之后，配合定期心跳检测即可避免，无需再单独考虑。 

因此，解决TCP通讯安全问题就要实现可变密钥加密数据进行传输。 

本类库中通过ECC非对称加密算法和AES对称加密算法实现TCP安全通讯的功能。具体流程如下 
1. TcpListener 对每一个客户端生成一个随机的ECC公钥发给客户端
2. AesTcpClient 用收到的公钥加密随机生成的AES密钥并发给服务端
3. TcpListener 收到AES密钥后双方用AES密钥加密通讯 

虽然 ECC 算法相对较慢，但是因为只用于加密 AES 算法的密钥，数据量小，且只在连接初期使用，因此影响不大。<br />
虽然 ECC 算法的公钥是明文传输的，但是由于 ECC 是非对称加密算法，解密需要私钥，而私钥没有通过网络传输，因此可以保证安全性。<br />
客户端用 ECC 公钥把 AES 的密钥传给服务端后双方就会使用 AES 算法加密通讯。<br />
由于 AES 算法属于对称加密，加密效率高，对通讯的效率影响较小。<br />
由于 AesTcpClient 中的 ECC 密钥和 AES 密钥都是随机生成的，因此不存在密钥泄漏导致的安全问题。<br />
任何人(包括开发者本人)想要查看 AesTcpClient 通讯的内容都只能用暴力破解法，而 ECC 和 AES 算法的暴力破解时间(在目前的算力条件下)均需要百年以上。<br />
综上所述， AesTcpClient 之间的通讯是非常安全的。 

### TCP服务端用法 

``` golang 
var client *networker.AesTcpClient 

func main() { 
	//创建服务端 
	lsnr := networker.TcpListener{} 

	//指定服务端身份认证方法 
	lsnr.OnAuthorize = func(name, pwd string) bool { 
		return name == "admin" && pwd == "admin" 
	} 

	//服务端接收到客户端后的处理方法 
	lsnr.OnClientAccepted = func(conn *net.Conn) { 
		tmBegin := time.Now() 

		//networker.AuthorizeConn 方法中封装了密钥交换、回调身份认证方法的操作 
		aesClient := networker.AuthorizeConn(&lsnr, conn) 

		fmt.Println(time.Now(), "Authorize cost time:", time.Since(tmBegin)) 

		//认证成功不为nil 
		if nil != aesClient { 
			client = aesClient 

			//设置客户端请求处理方法 
			client.SetAesPackageHandler(func (tcp *networker.AesTcpClient, pkg *networker.AesPackage) { 
				fmt.Println("clientPkgHandler Received: SN=", pkg.PacSN, " JSON=", pkg.Json, " Cmd=", pkg.Cmd, "len(ExtData)=", len(pkg.ExtData)) 

				cmd := networker.AesCmd{ 
					Data: nil, 
					IsOK: true, 
					Msg:  "eccclient got " + pkg.Json, 
				} 

				jstr, err := json.Marshal(cmd) 
				if nil != err { 
					fmt.Println(err) 
				} 

				//回复请求。必须将PacSN最高位置1才能匹配为客户端的请求结果，否则客户端按服务端请求处理。
				tcp.SendJson(0x8000|pkg.PacSN, networker.Cmd_Test, string(jstr), nil) 
			}) 
		} 
	} 

	//启动侦听指定端口 
	lsnr.Start(5868) 
} 
``` 

### TCP客户端用法 

``` golang 
func main() { 
	//创建 AesTcpClient
	cli := networker.AesTcpClient{}

	//连接服务端请求认证
	if !cli.Login("127.0.0.1", 5868, "admin", "admin", 3000) {
		fmt.Println("Failed to authorize")
		return
	}

	go func() {
		//新建请求命令对象
		cmd := networker.AesCmd{
			Data: nil,
			IsOK: true,
			Msg:  “”,
		}

		for {
			//命令对象序列化
			cmd.Msg = "Now is " + time.Now().Format("15:04:05")
			jstr, err := json.Marshal(cmd)
			if nil != err {
				fmt.Println(err)
			}

			//发送请求命令并等待结果
			pac := cli.SendJsonAndWait(networker.GetNexPacSN(), networker.Cmd_Test, string(jstr), nil, 3000)
			if nil != pac {
				fmt.Println("cli got answer: ", string(pac.Json))
			}

			time.Sleep(time.Second * 3)
		}
	}()
}
``` 

## UDP通讯类

UDP通讯类封装了最基本的收发操作。通讯内容明文传输。具体用法参考 main.go 中的 UdpDemo 代码。