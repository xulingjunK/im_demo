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
	"sync"
	"time"
)

const (
	serverAddr        = "127.0.0.1:8080"
	maxPacketSize     = 4096
	heartbeatInterval = 3 * time.Second
	heartbeatTimeout  = 10 * time.Second
)

// =========================
// TCP 数据包
// =========================

func Encode(body []byte) []byte {
	header := make([]byte, 4)

	binary.BigEndian.PutUint32(
		header,
		uint32(len(body)),
	)

	return append(header, body...)
}

func Decode(r io.Reader) ([]byte, error) {

	headerBuf := make([]byte, 4)

	_, err := io.ReadFull(
		r,
		headerBuf,
	)

	if err != nil {
		return nil, err
	}

	bodyLen := binary.BigEndian.Uint32(headerBuf)

	if bodyLen > maxPacketSize {
		return nil, io.ErrShortBuffer
	}

	bodyBuf := make([]byte, bodyLen)

	_, err = io.ReadFull(
		r,
		bodyBuf,
	)

	if err != nil {
		return nil, err
	}

	return bodyBuf, nil
}

// =========================
// 消息 ID 提取
// =========================

func extractMsgId(text string) string {
	index := strings.Index(text, "msgId:")

	if index == -1 {
		return ""
	}

	rest := text[index+len("msgId:"):]

	// 按空白字符分割
	fields := strings.Fields(rest)

	if len(fields) == 0 {
		return ""
	}

	return fields[0]
}

// =========================
// 清屏
// =========================

func clearScreen() {

	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		cmd = exec.Command(
			"cmd",
			"/c",
			"cls",
		)
	} else {
		cmd = exec.Command(
			"clear",
		)
	}

	cmd.Stdout = os.Stdout

	_ = cmd.Run()
}

// =========================
// 菜单
// =========================

func printMenu() {

	fmt.Println(
		"====================== IM 聊天 ======================",
	)

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

	fmt.Println(
		"====================================================",
	)
}

// =========================
// 全局客户端状态
// =========================

var (
	msgMu sync.Mutex

	msgList []string

	pongMu sync.Mutex

	lastPongAt = time.Now()
)

// =========================
// 心跳时间
// =========================

func setPong() {

	pongMu.Lock()

	lastPongAt = time.Now()

	pongMu.Unlock()
}

func sincePong() time.Duration {

	pongMu.Lock()

	defer pongMu.Unlock()

	return time.Since(lastPongAt)
}

// =========================
// 添加消息
// =========================

func addMsg(msg string) {

	msgMu.Lock()

	msgList = append(
		msgList,
		msg,
	)

	// redraw 必须在锁里面读取 msgList
	redrawLocked()

	msgMu.Unlock()
}

// =========================
// 重绘
// =========================

// redrawLocked 要求调用者已经持有 msgMu
func redrawLocked() {

	clearScreen()

	printMenu()

	for _, m := range msgList {
		fmt.Println(m)
	}

	fmt.Print("> ")
}

// =========================
// 重绘安全封装
// =========================

func redraw() {

	msgMu.Lock()

	redrawLocked()

	msgMu.Unlock()
}

// =========================
// 发送消息
// =========================

func sendPacket(conn net.Conn, msg string) error {

	// 防止 Write 无限阻塞
	_ = conn.SetWriteDeadline(
		time.Now().Add(2 * time.Second),
	)

	_, err := conn.Write(
		Encode([]byte(msg)),
	)

	// 恢复无限等待
	_ = conn.SetWriteDeadline(time.Time{})

	return err
}

// =========================
// 登录阶段读取响应
// 自动跳过 pong
// =========================

func readAuthResp(conn net.Conn) (string, bool) {

	for {

		body, err := Decode(conn)

		if err != nil {

			fmt.Printf(
				"读取响应失败：%v\n",
				err,
			)

			return "", false
		}

		msg := string(body)

		if msg == "pong" {

			setPong()

			continue
		}

		return msg, true
	}
}

// =========================
// 登录阶段心跳
// =========================

func startAuthKeepAlive(
	conn net.Conn,
	stop <-chan struct{},
) {

	go func() {

		ticker := time.NewTicker(
			heartbeatInterval,
		)

		defer ticker.Stop()

		for {

			select {

			case <-stop:
				return

			case <-ticker.C:

				err := sendPacket(
					conn,
					"ping",
				)

				if err != nil {
					return
				}
			}
		}
	}()
}

// =========================
// 认证流程
// =========================

func authFlow(
	conn net.Conn,
	reader *bufio.Reader,
) bool {

	for {

		fmt.Println(
			"请选择：1注册账号  2登录账号  3找回密码",
		)

		fmt.Print(
			"输入选择(1/2/3) > ",
		)

		choice, err :=
			reader.ReadString('\n')

		if err != nil {
			return false
		}

		choice = strings.TrimSpace(
			choice,
		)

		// =========================
		// 找回密码
		// =========================

		if choice == "3" {

			fmt.Println(
				"\n=====密码找回=====",
			)

			fmt.Println(
				"第一步：查询密保问题",
			)

			fmt.Print(
				"要找回的用户名 > ",
			)

			user, err :=
				reader.ReadString('\n')

			if err != nil {
				return false
			}

			user = strings.TrimSpace(user)

			if user == "" {

				fmt.Println(
					"❌ 用户名不能为空",
				)

				continue
			}

			err = sendPacket(
				conn,
				"getsecq|"+user,
			)

			if err != nil {

				fmt.Println(
					"发送失败：",
					err,
				)

				return false
			}

			respBody, ok :=
				readAuthResp(conn)

			if !ok {
				return false
			}

			fmt.Println(respBody)

			if strings.Contains(
				respBody,
				"❌",
			) {
				continue
			}

			fmt.Print(
				"密保答案 > ",
			)

			ans, err :=
				reader.ReadString('\n')

			if err != nil {
				return false
			}

			ans = strings.TrimSpace(ans)

			fmt.Print(
				"设置新密码 > ",
			)

			newPass, err :=
				reader.ReadString('\n')

			if err != nil {
				return false
			}

			newPass = strings.TrimSpace(newPass)

			if ans == "" ||
				newPass == "" {

				fmt.Println(
					"❌ 密保答案和新密码不能为空",
				)

				continue
			}

			if strings.Contains(
				ans,
				"|",
			) {

				fmt.Println(
					"❌ 密保答案不能包含 |",
				)

				continue
			}

			if len(newPass) < 3 {

				fmt.Println(
					"❌ 新密码至少3位",
				)

				continue
			}

			err = sendPacket(
				conn,
				"resetpwd|"+
					user+
					"|"+
					ans+
					"|"+
					newPass,
			)

			if err != nil {

				fmt.Println(
					"发送失败：",
					err,
				)

				return false
			}

			respReset, ok :=
				readAuthResp(conn)

			if !ok {
				return false
			}

			fmt.Println(
				respReset,
			)

			fmt.Println(
				"找回密码流程结束，返回主菜单\n",
			)

			continue
		}

		// =========================
		// 注册 / 登录
		// =========================

		if choice != "1" &&
			choice != "2" {

			fmt.Println(
				"❌ 只能输入1、2或者3",
			)

			continue
		}

		fmt.Print(
			"用户名 > ",
		)

		user, err :=
			reader.ReadString('\n')

		if err != nil {
			return false
		}

		user = strings.TrimSpace(user)

		fmt.Print(
			"密码 > ",
		)

		pass, err :=
			reader.ReadString('\n')

		if err != nil {
			return false
		}

		pass = strings.TrimSpace(pass)

		if user == "" ||
			pass == "" {

			fmt.Println(
				"❌ 用户名和密码不能为空",
			)

			continue
		}

		if strings.ContainsAny(
			user,
			" |\r\n\t",
		) {

			fmt.Println(
				"❌ 用户名不能包含空格、| 或换行符",
			)

			continue
		}

		if len(pass) < 3 {

			fmt.Println(
				"❌ 密码至少3位",
			)

			continue
		}

		var action string

		if choice == "1" {
			action = "register"
		} else {
			action = "login"
		}

		err = sendPacket(
			conn,
			action+"|"+user+"|"+pass,
		)

		if err != nil {

			fmt.Println(
				"发送失败：",
				err,
			)

			return false
		}

		respMsg, ok :=
			readAuthResp(conn)

		if !ok {
			return false
		}

		fmt.Println(
			respMsg,
		)

		if strings.Contains(
			respMsg,
			"注册成功",
		) ||
			strings.Contains(
				respMsg,
				"登录成功",
			) {

			return true
		}
	}
}

// =========================
// 接收消息
// =========================

func startReader(conn net.Conn) {

	go func() {

		for {

			body, err :=
				Decode(conn)

			if err != nil {

				addMsg(
					"\n⚠️ 连接断开",
				)

				return
			}

			msg := string(body)

			// =========================
			// pong
			// =========================

			if msg == "pong" {

				setPong()

				continue
			}

			// =========================
			// 撤回通知
			// =========================

			if strings.HasPrefix(
				msg,
				"🔔 一条消息被撤回 msgId:",
			) {

				recallMsgId :=
					extractMsgId(msg)

				if recallMsgId == "" {

					addMsg(
						"⚠️ 收到非法撤回通知",
					)

					continue
				}

				msgMu.Lock()

				for i := range msgList {

					mid :=
						extractMsgId(
							msgList[i],
						)

					if mid == recallMsgId {

						msgList[i] =
							fmt.Sprintf(
								"【消息已撤回】msgId:%s",
								recallMsgId,
							)

						break
					}
				}

				redrawLocked()

				msgMu.Unlock()

				continue
			}

			// =========================
			// 普通消息
			// =========================

			addMsg(msg)
		}
	}()
}

// =========================
// 心跳
// =========================

func startHeartbeat(
	conn net.Conn,
) {

	go func() {

		ticker := time.NewTicker(
			heartbeatInterval,
		)

		defer ticker.Stop()

		for range ticker.C {

			// 超过10秒没收到 pong
			if sincePong() >
				heartbeatTimeout {

				addMsg(
					"\n⚠️ 心跳超时，连接断开",
				)

				_ = conn.Close()

				return
			}

			err := sendPacket(
				conn,
				"ping",
			)

			if err != nil {

				addMsg(
					"\n⚠️ 心跳发送失败，连接断开",
				)

				_ = conn.Close()

				return
			}
		}
	}()
}

// =========================
// 主程序
// =========================

func main() {

	fmt.Println(
		"正在连接 IM 服务...",
	)

	conn, err :=
		net.Dial(
			"tcp",
			serverAddr,
		)

	if err != nil {

		fmt.Println(
			"连接服务失败：",
			err,
		)

		return
	}

	defer conn.Close()

	fmt.Println(
		"✅ 成功连接IM服务",
	)

	// 整个程序只创建一个 Reader
	reader :=
		bufio.NewReader(
			os.Stdin,
		)

	// =========================
	// 登录阶段心跳
	// =========================

	stopAuthKeepAlive :=
		make(chan struct{})

	startAuthKeepAlive(
		conn,
		stopAuthKeepAlive,
	)

	// =========================
	// 登录
	// =========================

	if !authFlow(
		conn,
		reader,
	) {

		close(
			stopAuthKeepAlive,
		)

		fmt.Println(
			"⚠️ 认证失败或连接断开",
		)

		return
	}

	close(
		stopAuthKeepAlive,
	)

	// =========================
	// 登录成功后重新计算心跳时间
	// =========================

	setPong()

	// =========================
	// 初始界面
	// =========================

	msgMu.Lock()

	redrawLocked()

	msgMu.Unlock()

	// =========================
	// 启动接收消息
	// =========================

	startReader(conn)

	// =========================
	// 启动正式心跳
	// =========================

	startHeartbeat(conn)

	// =========================
	// 主输入循环
	// =========================

	for {

		text, err :=
			reader.ReadString('\n')

		if err != nil {

			fmt.Println(
				"\n⚠️ 输入读取失败：",
				err,
			)

			return
		}

		text =
			strings.TrimSpace(text)

		if text == "" {
			continue
		}

		err = sendPacket(
			conn,
			text,
		)

		if err != nil {

			addMsg(
				"消息发送失败：" + err.Error(),
			)

			return
		}
	}
}
