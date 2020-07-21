package utils

import (
	"fmt"
	"github.com/bwmarrin/snowflake"
)
var node *snowflake.Node
func init() {
	var err error
	node, err = snowflake.NewNode(1)
	if err!=nil {
		fmt.Println("snow new node err",err)
	}
}

func GetSnowID()  string{
	id := node.Generate()
	return GetString(id)
}