package networker

import (
	"encoding/json"
	"fmt"
)

type CmdType int32

const (
	Cmd_Hearbeat = iota
	Cmd_GetPubKey
	Cmd_GetPrivateKey
	Cmd_GetUserNamePwd
	Cmd_AuthorizeResult
	Cmd_Test
)

type EccCmd struct {
	Cmd  int    `json:"cmd"`
	Data any    `json:"data"`
	IsOK bool   `json:"isok"`
	Msg  string `json:"msg"`
}

func (cmd *EccCmd) ToJson() string {
	jdata, err := json.Marshal(cmd)
	if nil != err {
		fmt.Println("FurisonCmd.ToJson 异常", err)
		return ""
	}

	return string(jdata)
}
