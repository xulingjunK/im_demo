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
	serverAddr         = "127.0.0.1:8080"
	maxPacketSize      = 4096
	heartbeatInterval  = 3 * time.Second
	heartbeatTimeout   = 10 * time.Second
	maxDisplayMessages = 200
	maxNicknameLen     = 20
	minPasswordLen     = 3
	maxPasswordLen     = 128
	accountIDLength    = 10
)

// =========================
// TCP 数据包
// =========================

func Encode(body []byte) []byte {
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(body)))
	return append(header, body...)
}

func Decode(r io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	bodyLen := binary.BigEndian.Uint32(header)
	if bodyLen > maxPacketSize {
		return nil, fmt.Errorf(
			"packet too large: %d > %d",
			bodyLen,
			maxPacketSize,
		)
	}

	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}

	return body, nil
}

func extractMsgID(text string) string {
	index := strings.Index(text, "msgId:")
	if index == -1 {
		return ""
	}

	rest := text[index+len("msgId:"):]
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
		cmd = exec.Command("cmd", "/c", "cls")
	} else {
		cmd = exec.Command("clear")
	}

	cmd.Stdout = os.Stdout
	_ = cmd.Run()
}

// =========================
// 菜单
// =========================

func printMenu() {
	fmt.Println("====================== IM 聊天 ======================")

	fmt.Println("【账号】")
	fmt.Println("profile                  查看当前账号和昵称")
	fmt.Println("changenick               修改昵称")
	fmt.Println("changepwd                修改密码")
	fmt.Println()

	fmt.Println("【好友】")
	fmt.Println("addfriend                添加好友（可选择ID或昵称）")
	fmt.Println("pendinglist              查看收到的好友申请")
	fmt.Println("acceptfriend|账号ID     同意好友申请")
	fmt.Println("rejectfriend|账号ID     拒绝好友申请")
	fmt.Println("friendlist               查看好友列表")
	fmt.Println("delfriend|账号ID        删除好友")
	fmt.Println("setsecq|问题|答案        设置密保")
	fmt.Println()

	fmt.Println("【聊天】")
	fmt.Println("@昵称 消息内容           私聊好友")
	fmt.Println("recall|msgId             撤回私聊消息")
	fmt.Println("history                  查看私聊历史记录（全部/精准检索）")
	fmt.Println("history|账号ID|all       查看与好友的全部私聊记录")
	fmt.Println("history|账号ID|time|开始|结束  按时间精准查询")
	fmt.Println("history|账号ID|msgid|ID  按消息ID精准查询")
	fmt.Println("直接打字                 公共广播")

	fmt.Println("====================================================")
}

// =========================
// 全局状态
// =========================

var (
	msgMu sync.Mutex

	msgList []string

	pongMu sync.Mutex

	lastPongAt = time.Now()

	writeMu sync.Mutex
)

// =========================
// 心跳
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
// 消息显示
// =========================

func redraw() {
	msgMu.Lock()
	messages := append([]string(nil), msgList...)
	msgMu.Unlock()

	clearScreen()
	printMenu()

	for _, msg := range messages {
		fmt.Println(msg)
	}

	fmt.Print("> ")
}

func addMsg(msg string) {
	msgMu.Lock()

	msgList = append(msgList, msg)

	if len(msgList) > maxDisplayMessages {
		msgList = msgList[len(msgList)-maxDisplayMessages:]
	}

	msgMu.Unlock()

	redraw()
}

// =========================
// 发送
// =========================

func sendPacket(conn net.Conn, msg string) error {
	writeMu.Lock()
	defer writeMu.Unlock()

	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	defer conn.SetWriteDeadline(time.Time{})

	_, err := conn.Write(Encode([]byte(msg)))
	return err
}

// =========================
// 输入校验
// =========================

func readLine(reader *bufio.Reader, prompt string) (string, error) {
	fmt.Print(prompt)

	text, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(text), nil
}

func validAccountIDLocal(accountID string) bool {
	if len(accountID) != accountIDLength {
		return false
	}

	if accountID == "0000000000" {
		return false
	}

	for _, ch := range accountID {
		if ch < '0' || ch > '9' {
			return false
		}
	}

	return true
}

func validNicknameLocal(nickname string) error {
	nickname = strings.TrimSpace(nickname)

	if nickname == "" {
		return fmt.Errorf("昵称不能为空")
	}

	if len([]rune(nickname)) > maxNicknameLen {
		return fmt.Errorf("昵称不能超过%d个字符", maxNicknameLen)
	}

	if strings.ContainsAny(nickname, "|\r\n\t") {
		return fmt.Errorf("昵称不能包含 | 或换行符")
	}

	return nil
}

func validPasswordLocal(password string) error {
	if password == "" {
		return fmt.Errorf("密码不能为空")
	}

	if len(password) < minPasswordLen {
		return fmt.Errorf("密码至少%d位", minPasswordLen)
	}

	if len(password) > maxPasswordLen {
		return fmt.Errorf("密码不能超过%d个字符", maxPasswordLen)
	}

	if strings.ContainsAny(password, "|\r\n\t") {
		return fmt.Errorf("密码不能包含 | 或换行符")
	}

	return nil
}

func validSecurityAnswerLocal(answer string) bool {
	return strings.TrimSpace(answer) != "" &&
		!strings.ContainsAny(answer, "|\r\n\t")
}

// =========================
// 登录阶段读取
// =========================

func readAuthResp(conn net.Conn) (string, bool) {
	for {
		body, err := Decode(conn)
		if err != nil {
			fmt.Printf("读取响应失败：%v\n", err)
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
		ticker := time.NewTicker(heartbeatInterval)
		defer ticker.Stop()

		for {
			select {
			case <-stop:
				return

			case <-ticker.C:
				if err := sendPacket(conn, "ping"); err != nil {
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
		fmt.Println()
		fmt.Println("请选择：1 注册账号  2 登录账号  3 找回密码")

		choice, err := readLine(
			reader,
			"输入选择(1/2/3) > ",
		)
		if err != nil {
			return false
		}

		switch choice {
		case "1":
			if registerFlow(conn, reader) {
				return true
			}

		case "2":
			if loginFlow(conn, reader) {
				return true
			}

		case "3":
			if !resetPasswordFlow(conn, reader) {
				// 找回密码失败或者用户主动返回时继续主菜单。
			}

		default:
			fmt.Println("❌ 只能输入1、2或者3")
		}
	}
}

func registerFlow(
	conn net.Conn,
	reader *bufio.Reader,
) bool {
	fmt.Println("\n===== 注册账号 =====")

	nickname, err := readLine(reader, "昵称 > ")
	if err != nil {
		return false
	}

	if err := validNicknameLocal(nickname); err != nil {
		fmt.Println("❌", err)
		return false
	}

	password, err := readLine(reader, "密码 > ")
	if err != nil {
		return false
	}

	if err := validPasswordLocal(password); err != nil {
		fmt.Println("❌", err)
		return false
	}

	if err := sendPacket(
		conn,
		"register|"+nickname+"|"+password,
	); err != nil {
		fmt.Println("发送失败：", err)
		return false
	}

	resp, ok := readAuthResp(conn)
	if !ok {
		return false
	}

	fmt.Println(resp)

	return strings.Contains(resp, "注册成功")
}

func loginFlow(
	conn net.Conn,
	reader *bufio.Reader,
) bool {
	fmt.Println("\n===== 登录账号 =====")

	accountID, err := readLine(
		reader,
		"10位账号ID > ",
	)
	if err != nil {
		return false
	}

	if !validAccountIDLocal(accountID) {
		fmt.Println("❌ 账号ID必须是10位数字")
		return false
	}

	password, err := readLine(reader, "密码 > ")
	if err != nil {
		return false
	}

	if err := validPasswordLocal(password); err != nil {
		fmt.Println("❌", err)
		return false
	}

	if err := sendPacket(
		conn,
		"login|"+accountID+"|"+password,
	); err != nil {
		fmt.Println("发送失败：", err)
		return false
	}

	resp, ok := readAuthResp(conn)
	if !ok {
		return false
	}

	fmt.Println(resp)

	return strings.Contains(resp, "登录成功")
}

func resetPasswordFlow(
	conn net.Conn,
	reader *bufio.Reader,
) bool {
	fmt.Println("\n===== 密码找回 =====")

	accountID, err := readLine(
		reader,
		"账号ID > ",
	)
	if err != nil {
		return false
	}

	if !validAccountIDLocal(accountID) {
		fmt.Println("❌ 账号ID必须是10位数字")
		return false
	}

	if err := sendPacket(
		conn,
		"getsecq|"+accountID,
	); err != nil {
		fmt.Println("发送失败：", err)
		return false
	}

	resp, ok := readAuthResp(conn)
	if !ok {
		return false
	}

	fmt.Println(resp)

	if strings.Contains(resp, "❌") {
		return false
	}

	answer, err := readLine(
		reader,
		"密保答案 > ",
	)
	if err != nil {
		return false
	}

	if !validSecurityAnswerLocal(answer) {
		fmt.Println("❌ 密保答案不能为空，且不能包含 | 或换行符")
		return false
	}

	newPassword, err := readLine(
		reader,
		"新密码 > ",
	)
	if err != nil {
		return false
	}

	if err := validPasswordLocal(newPassword); err != nil {
		fmt.Println("❌", err)
		return false
	}

	if err := sendPacket(
		conn,
		"resetpwd|"+accountID+"|"+answer+"|"+newPassword,
	); err != nil {
		fmt.Println("发送失败：", err)
		return false
	}

	resp, ok = readAuthResp(conn)
	if !ok {
		return false
	}

	fmt.Println(resp)
	fmt.Println("密码找回流程结束，返回主菜单")

	return false
}

// =========================
// 已登录本地命令
// =========================

func handleLocalCommand(
	conn net.Conn,
	reader *bufio.Reader,
	text string,
) (handled bool, shouldExit bool) {
	switch text {
	case "addfriend":
		fmt.Println("===== 添加好友 =====")
		method, err := readLine(
			reader,
			"选择添加方式（1=账号ID，2=昵称） > ",
		)
		if err != nil {
			return true, true
		}

		switch method {
		case "1":
			targetID, err := readLine(reader, "好友账号ID > ")
			if err != nil {
				return true, true
			}
			if !validAccountIDLocal(targetID) {
				addMsg("❌ 账号ID必须是10位数字，且不能为0000000000")
				return true, false
			}

			if err := sendPacket(
				conn,
				"addfriend|id|"+targetID,
			); err != nil {
				addMsg("❌ 添加好友请求发送失败：" + err.Error())
				return true, true
			}
			return true, false

		case "2":
			targetNickname, err := readLine(reader, "好友昵称 > ")
			if err != nil {
				return true, true
			}
			if err := validNicknameLocal(targetNickname); err != nil {
				addMsg("❌ " + err.Error())
				return true, false
			}

			if err := sendPacket(
				conn,
				"addfriend|nick|"+targetNickname,
			); err != nil {
				addMsg("❌ 添加好友请求发送失败：" + err.Error())
				return true, true
			}
			return true, false

		default:
			addMsg("❌ 只能输入1或2")
			return true, false
		}

	case "changenick":
		newNickname, err := readLine(
			reader,
			"新昵称 > ",
		)
		if err != nil {
			return true, true
		}

		if err := validNicknameLocal(newNickname); err != nil {
			addMsg("❌ " + err.Error())
			return true, false
		}

		if err := sendPacket(
			conn,
			"changenick|"+newNickname,
		); err != nil {
			addMsg("❌ 修改昵称请求发送失败：" + err.Error())
			return true, true
		}

		return true, false

	case "history":
		fmt.Println("===== 私聊历史记录 =====")
		targetID, err := readLine(reader, "好友账号ID > ")
		if err != nil {
			return true, true
		}
		if !validAccountIDLocal(targetID) {
			addMsg("❌ 账号ID必须是10位数字，且不能为0000000000")
			return true, false
		}

		fmt.Println("请选择查询方式：")
		fmt.Println("1. 全部查看")
		fmt.Println("2. 按时间精准查询")
		fmt.Println("3. 按消息ID精准查询")

		method, err := readLine(reader, "选择(1/2/3) > ")
		if err != nil {
			return true, true
		}

		switch method {
		case "1":
			if err := sendPacket(conn, "history|"+targetID+"|all"); err != nil {
				addMsg("❌ 历史记录查询发送失败：" + err.Error())
				return true, true
			}

		case "2":
			startTime, err := readLine(reader, "开始日期（YYYY-MM-DD）> ")
			if err != nil {
				return true, true
			}
			endTime, err := readLine(reader, "结束日期（YYYY-MM-DD）> ")
			if err != nil {
				return true, true
			}
			if err := sendPacket(
				conn,
				"history|"+targetID+"|time|"+startTime+"|"+endTime,
			); err != nil {
				addMsg("❌ 历史记录查询发送失败：" + err.Error())
				return true, true
			}

		case "3":
			msgID, err := readLine(reader, "消息ID > ")
			if err != nil {
				return true, true
			}
			if msgID == "" {
				addMsg("❌ 消息ID不能为空")
				return true, false
			}
			if err := sendPacket(
				conn,
				"history|"+targetID+"|msgid|"+msgID,
			); err != nil {
				addMsg("❌ 历史记录查询发送失败：" + err.Error())
				return true, true
			}

		default:
			addMsg("❌ 只能输入1、2或3")
		}
		return true, false

	case "changepwd":
		oldPassword, err := readLine(
			reader,
			"旧密码 > ",
		)
		if err != nil {
			return true, true
		}

		newPassword, err := readLine(
			reader,
			"新密码 > ",
		)
		if err != nil {
			return true, true
		}

		if err := validPasswordLocal(oldPassword); err != nil {
			addMsg("❌ 旧密码：" + err.Error())
			return true, false
		}

		if err := validPasswordLocal(newPassword); err != nil {
			addMsg("❌ 新密码：" + err.Error())
			return true, false
		}

		if err := sendPacket(
			conn,
			"changepwd|"+oldPassword+"|"+newPassword,
		); err != nil {
			addMsg("❌ 修改密码请求发送失败：" + err.Error())
			return true, true
		}

		return true, false
	}

	return false, false
}

// =========================
// 接收消息
// =========================

func startReader(conn net.Conn) {
	go func() {
		for {
			body, err := Decode(conn)
			if err != nil {
				addMsg("\n⚠️ 连接断开")
				return
			}

			msg := string(body)

			if msg == "pong" {
				setPong()
				continue
			}

			if strings.HasPrefix(
				msg,
				"🔔 一条消息被撤回 msgId:",
			) {
				recallMsgID := extractMsgID(msg)

				if recallMsgID == "" {
					addMsg("⚠️ 收到非法撤回通知")
					continue
				}

				msgMu.Lock()

				for i := range msgList {
					if extractMsgID(msgList[i]) == recallMsgID {
						msgList[i] = fmt.Sprintf(
							"【消息已撤回】msgId:%s",
							recallMsgID,
						)
						break
					}
				}

				msgMu.Unlock()

				redraw()
				continue
			}

			addMsg(msg)
		}
	}()
}

// =========================
// 正式心跳
// =========================

func startHeartbeat(conn net.Conn) {
	go func() {
		ticker := time.NewTicker(heartbeatInterval)
		defer ticker.Stop()

		for range ticker.C {
			if sincePong() > heartbeatTimeout {
				addMsg("\n⚠️ 心跳超时，连接断开")
				_ = conn.Close()
				return
			}

			if err := sendPacket(conn, "ping"); err != nil {
				addMsg("\n⚠️ 心跳发送失败，连接断开")
				_ = conn.Close()
				return
			}
		}
	}()
}

// =========================
// main
// =========================

func main() {
	fmt.Println("正在连接 IM 服务...")

	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		fmt.Println("连接服务失败：", err)
		return
	}
	defer conn.Close()

	fmt.Println("✅ 成功连接 IM 服务")

	reader := bufio.NewReader(os.Stdin)

	stopAuthKeepAlive := make(chan struct{})
	startAuthKeepAlive(conn, stopAuthKeepAlive)

	if !authFlow(conn, reader) {
		close(stopAuthKeepAlive)
		fmt.Println("⚠️ 认证失败或连接断开")
		return
	}

	close(stopAuthKeepAlive)
	setPong()

	redraw()
	startReader(conn)
	startHeartbeat(conn)

	for {
		text, err := readLine(reader, "")
		if err != nil {
			fmt.Println("\n⚠️ 输入读取失败：", err)
			return
		}

		if text == "" {
			continue
		}

		if handled, shouldExit := handleLocalCommand(
			conn,
			reader,
			text,
		); handled {
			if shouldExit {
				return
			}
			continue
		}

		if err := sendPacket(conn, text); err != nil {
			addMsg("消息发送失败：" + err.Error())
			return
		}
	}
}
