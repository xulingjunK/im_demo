package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

// Encode 编码：4字节大端长度头 + 消息体
func Encode(body []byte) []byte {
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(body)))
	return append(header, body...)
}

// Decode 解码：读取完整数据包，自动处理粘包拆包
func Decode(r io.Reader) ([]byte, error) {
	headerBuf := make([]byte, 4)
	_, err := io.ReadFull(r, headerBuf)
	if err != nil {
		return nil, err
	}
	bodyLen := binary.BigEndian.Uint32(headerBuf)
	if bodyLen > 4096 {
		return nil, io.ErrShortBuffer
	}
	bodyBuf := make([]byte, bodyLen)
	_, err = io.ReadFull(r, bodyBuf)
	return bodyBuf, err
}

func main() {
	conn, err := net.Dial("tcp", "127.0.0.1:8080")
	if err != nil {
		fmt.Println("连接服务失败：", err)
		return
	}
	defer conn.Close()
	fmt.Println("✅ 成功连接IM服务")

	reader := bufio.NewReader(os.Stdin)

	// 认证循环，失败可重试
	for {
		fmt.Println("请选择：1注册账号  2登录账号")
		fmt.Print("输入选择(1/2) > ")
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		fmt.Print("用户名 > ")
		user, _ := reader.ReadString('\n')
		user = strings.TrimSpace(user)

		fmt.Print("密码 > ")
		pass, _ := reader.ReadString('\n')
		pass = strings.TrimSpace(pass)

		// 把1/2转为 register / login
		var action string
		if choice == "1" {
			action = "register"
		} else if choice == "2" {
			action = "login"
		} else {
			fmt.Println("❌ 只能输入1或者2")
			continue
		}

		cmd := fmt.Sprintf("%s|%s|%s", action, user, pass)
		_, err = conn.Write(Encode([]byte(cmd)))
		if err != nil {
			fmt.Println("发送失败", err)
			return
		}

		respBody, err := Decode(conn)
		if err != nil {
			fmt.Printf("读取服务响应失败：%v\n", err)
			continue
		}
		respMsg := string(respBody)
		fmt.Println(respMsg)

		// ========== 修改判断：注册成功 或者 登录成功，都跳出循环 ==========
		if strings.Contains(respMsg, "注册成功") || strings.Contains(respMsg, "登录成功") {
			break
		}
	}

	// 接收消息协程
	go func() {
		for {
			body, err := Decode(conn)
			if err != nil {
				fmt.Println("\n⚠️ 服务端连接断开")
				os.Exit(0)
			}
			fmt.Printf("%s\n", string(body))
		}
	}()

	// 聊天输入循环
	fmt.Println("=== 开始聊天，输入文字回车发送 ===")
	chatReader := bufio.NewReader(os.Stdin)
	for {
		text, _ := chatReader.ReadString('\n')
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		_, err := conn.Write(Encode([]byte(text)))
		if err != nil {
			fmt.Println("消息发送失败")
			break
		}
	}
}
