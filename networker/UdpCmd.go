package networker

type UdpCmd[T any] struct {
	Cmd  int
	IsOK bool
	Data T
}

type ServerInfo struct {
	ServerName     string
	ServerPort     uint16
	UploadFilePort uint16
}

type UdpCmdEnum uint16

const (
	SearchServer = iota
)
