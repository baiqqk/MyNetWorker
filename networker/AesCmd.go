package networker

import (
	"encoding/json"
	"fmt"
)

type CmdType uint16

// 命令大分类（13比特位）
const (
	Cmd_Basic = 0 >> 3
	Cmd_User  = 256 >> 3
)

// 命令细分类（3比特位）
const (
	Cmd_Hearbeat = iota | (Cmd_Basic << 3)
	Cmd_GetPubKey
	Cmd_GetPrivateKey
	Cmd_GetUserNamePwd
	Cmd_AuthorizeResult
	Cmd_Test

	Cmd_SaveUser   = Cmd_User << 3
	Cmd_DeleteUser = Cmd_SaveUser + 1
	Cmd_QueryUser  = Cmd_SaveUser + 2
)

type AesCmd struct {
	// Cmd  int    `json:"cmd"`
	Data any    `json:"data"`
	IsOK bool   `json:"isok"`
	Msg  string `json:"msg"`
}

func (cmd *AesCmd) ToJson() string {
	jdata, err := json.Marshal(cmd)
	if nil != err {
		fmt.Println("FurisonCmd.ToJson 异常", err)
		return ""
	}

	return string(jdata)
}
