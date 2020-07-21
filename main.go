package main

import (
	"ceshi_grcp/pb"
	"ceshi_grcp/utils"
	"context"
	"fmt"
	"google.golang.org/grpc"
	"time"
)

var ctx = context.Background()

func main() {
	conn, err := grpc.Dial("192.168.169.14:17722", grpc.WithInsecure())
	if err != nil {
		fmt.Println("grpc.Dial err")
		return
	}

	VideoFilter(conn)

}


func VideoFilter(conn *grpc.ClientConn) {
	client := pb.NewVideoFilterServiceClient(conn)
	res, err := client.VideoFilter(ctx, &pb.VideoFilterReq{
		UserId:    "123",
		Videos:    []string{"1", "2", "3"},
		Timestamp: time.Now().Unix(),
	})
	if err != nil {
		fmt.Println("cilent.VideoFilter err:", err.Error())
		return
	}
	fmt.Println(utils.ToJson(res))
}
