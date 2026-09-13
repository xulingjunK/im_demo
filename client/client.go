package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

func Encode(body []byte) []byte {
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(body)))
	return append(header, body...)
}

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

	for {
		fmt.Println("请选择：1注册账号  2登录账号  3找回密码")
		fmt.Print("输入选择(1/2/3) > ")
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		if choice == "3" {
			fmt.Println("\n=====密码找回=====")
			fmt.Println("第一步：查询密保问题")
			fmt.Print("要找回的用户名 > ")
			user, _ := reader.ReadString('\n')
			user = strings.TrimSpace(user)
			cmdGetSec := fmt.Sprintf("getsecq|%s", user)
			_, err = conn.Write(Encode([]byte(cmdGetSec)))
			if err != nil {
				fmt.Println("发送失败", err)
				return
			}
			respBody, err := Decode(conn)
			if err != nil {
				fmt.Printf("读取响应失败：%v\n", err)
				continue
			}
			fmt.Println(string(respBody))
			respMsg := string(respBody)
			if !strings.Contains(respMsg, "❌") {
				fmt.Print("密保答案 > ")
				ans, _ := reader.ReadString('\n')
				ans = strings.TrimSpace(ans)
				fmt.Print("设置新密码 > ")
				newPass, _ := reader.ReadString('\n')
				newPass = strings.TrimSpace(newPass)
				cmdReset := fmt.Sprintf("resetpwd|%s|%s|%s", user, ans, newPass)
				_, err = conn.Write(Encode([]byte(cmdReset)))
				if err != nil {
					fmt.Println("发送失败", err)
					return
				}
				respReset, err := Decode(conn)
				if err != nil {
					fmt.Printf("读取响应失败：%v\n", err)
					continue
				}
				fmt.Println(string(respReset))
			}
			fmt.Println("找回密码流程结束，返回主菜单\n")
			continue
		}

		fmt.Print("用户名 > ")
		user, _ := reader.ReadString('\n')
		user = strings.TrimSpace(user)
		fmt.Print("密码 > ")
		pass, _ := reader.ReadString('\n')
		pass = strings.TrimSpace(pass)

		var action string
		if choice == "1" {
			action = "register"
		} else if choice == "2" {
			action = "login"
		} else {
			fmt.Println("❌ 只能输入1、2或者3")
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
			fmt.Printf("读取响应失败：%v\n", err)
			continue
		}
		respMsg := string(respBody)
		fmt.Println(respMsg)
		if strings.Contains(respMsg, "注册成功") || strings.Contains(respMsg, "登录成功") {
			break
		}
	}

	// 共享的最后收到pong时间
	var lastPongAt = time.Now()

	// 接收消息协程
	go func() {
		for {
			body, err := Decode(conn)
			if err != nil {
				fmt.Println("\n⚠️ 连接断开")
				os.Exit(0)
			}
			msg := string(body)
			// 收到pong更新心跳时间，不打印
			if msg == "pong" {
				lastPongAt = time.Now()
				continue
			}
			fmt.Printf("%s\n", msg)
		}
	}()

	// 心跳协程
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			// 超过10s没收到pong，判定连接失效
			if time.Since(lastPongAt) > 10*time.Second {
				fmt.Println("\n⚠️ 心跳超时，连接断开")
				conn.Close()
				os.Exit(0)
				return
			}
			// 仅给本次ping设置1秒写超时
			_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
			_, err := conn.Write(Encode([]byte("ping")))
			// 【关键修复】发完ping立刻清除写超时，否则后续聊天消息会被这个超时影响
			_ = conn.SetWriteDeadline(time.Time{})
			if err != nil {
				return
			}
		}
	}()

	fmt.Println("\n=====聊天开始=====")
	fmt.Println("指令：")
	fmt.Println("addfriend|xxx      添加好友xxx")
	fmt.Println("pendinglist        查看收到的好友申请")
	fmt.Println("acceptfriend|xxx   同意好友申请")
	fmt.Println("rejectfriend|xxx   拒绝好友申请")
	fmt.Println("friendlist         查看好友列表")
	fmt.Println("delfriend|xxx      删除好友")
	fmt.Println("setsecq|问题|答案  设置密保（用于找回密码！）")
	fmt.Println("@xxx 消息内容      私聊好友（离线自动存消息）")
	fmt.Println("直接打字 = 公共广播")
	fmt.Println("======================")

	chatReader := bufio.NewReader(os.Stdin)
	for {
		text, _ := chatReader.ReadString('\n')
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		_, err := conn.Write(Encode([]byte(text)))
		if err != nil {
			fmt.Println("消息发送失败:", err)
			break
		}
	}
}
