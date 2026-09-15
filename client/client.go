package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
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

func extractMsgId(text string) string {
	if strings.Contains(text, "msgId:") {
		parts := strings.Split(text, "msgId:")
		if len(parts) >= 2 {
			rest := parts[1]
			idx := strings.IndexAny(rest, "\n ")
			if idx > 0 {
				return rest[:idx]
			}
			return rest
		}
	}
	return ""
}

func clearScreen() {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	} else {
		cmd = exec.Command("clear")
	}
	cmd.Stdout = os.Stdout
	_ = cmd.Run()
}

func printMenu() {
	fmt.Println("====================== IM 聊天 ======================")
	fmt.Println("【指令】")
	fmt.Println("addfriend|xxx     添加好友xxx")
	fmt.Println("pendinglist       查看收到的好友申请")
	fmt.Println("acceptfriend|xxx  同意好友申请")
	fmt.Println("rejectfriend|xxx  拒绝好友申请")
	fmt.Println("friendlist        查看好友列表")
	fmt.Println("delfriend|xxx     删除好友")
	fmt.Println("setsecq|问题|答案 设置密保（用于找回密码！）")
	fmt.Println("@xxx 消息内容     私聊好友（离线自动存消息）")
	fmt.Println("recall|msgId      撤回私聊消息")
	fmt.Println("history|xxx       查看和xxx好友历史聊天记录")
	fmt.Println("直接打字 = 公共广播")
	fmt.Println("====================================================")
}

// 重绘整个界面：清屏 + 打印菜单 + 打印所有消息 + 输入提示符
func redraw(msgList []string) {
	clearScreen()
	printMenu()
	for _, m := range msgList {
		fmt.Println(m)
	}
	fmt.Print("> ")
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

	// ===== 登录/注册/找回密码 =====
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
			_, err = conn.Write(Encode([]byte("getsecq|" + user)))
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
			if !strings.Contains(string(respBody), "❌") {
				fmt.Print("密保答案 > ")
				ans, _ := reader.ReadString('\n')
				ans = strings.TrimSpace(ans)
				fmt.Print("设置新密码 > ")
				newPass, _ := reader.ReadString('\n')
				newPass = strings.TrimSpace(newPass)
				_, err = conn.Write(Encode([]byte("resetpwd|" + user + "|" + ans + "|" + newPass)))
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

		_, err = conn.Write(Encode([]byte(action + "|" + user + "|" + pass)))
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

	var lastPongAt = time.Now()
	var msgList []string // 内存缓存所有消息

	// ===== 接收消息协程 =====
	go func() {
		for {
			body, err := Decode(conn)
			if err != nil {
				msgList = append(msgList, "\n⚠️ 连接断开")
				redraw(msgList)
				os.Exit(0)
			}
			msg := string(body)
			if msg == "pong" {
				lastPongAt = time.Now()
				continue
			}
			// 撤回通知：找到对应msgId，替换消息内容
			if strings.HasPrefix(msg, "🔔 一条消息被撤回 msgId:") {
				var recallMsgId string
				_, _ = fmt.Sscanf(msg, "🔔 一条消息被撤回 msgId:%s", &recallMsgId)
				// 遍历内存消息列表，替换内容
				for i := range msgList {
					mid := extractMsgId(msgList[i])
					if mid == recallMsgId {
						msgList[i] = fmt.Sprintf("【消息已撤回】msgId:%s", recallMsgId)
						break
					}
				}
				redraw(msgList)
				continue
			}
			// 普通消息追加到列表并重绘
			msgList = append(msgList, msg)
			redraw(msgList)
		}
	}()

	// ===== 心跳协程 =====
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if time.Since(lastPongAt) > 10*time.Second {
				msgList = append(msgList, "\n⚠️ 心跳超时，连接断开")
				redraw(msgList)
				conn.Close()
				os.Exit(0)
				return
			}
			_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
			_, err := conn.Write(Encode([]byte("ping")))
			_ = conn.SetWriteDeadline(time.Time{})
			if err != nil {
				return
			}
		}
	}()

	// ===== 主输入循环 =====
	chatReader := bufio.NewReader(os.Stdin)
	for {
		text, _ := chatReader.ReadString('\n')
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		_, err := conn.Write(Encode([]byte(text)))
		if err != nil {
			msgList = append(msgList, "消息发送失败:"+err.Error())
			redraw(msgList)
			break
		}
	}
}
