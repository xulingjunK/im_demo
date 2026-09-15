package main

import (
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

const (
	heartbeatTimeout = 10 * time.Second // 10秒无数据则踢下线
	scanInterval     = 2 * time.Second  // 多久扫描一次连接
)

type ClientSession struct {
	conn         net.Conn
	username     string
	lastActiveAt time.Time
}

var (
	sessions = make(map[net.Conn]*ClientSession)
	mu       sync.Mutex
	db       *sql.DB
)

func Encode(body []byte) []byte {
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(body)))
	return append(header, body...)
}

// Decode 增加读超时参数，解决半开连接永久阻塞
func Decode(r io.Reader, timeout time.Duration) ([]byte, error) {
	if conn, ok := r.(net.Conn); ok {
		conn.SetReadDeadline(time.Now().Add(timeout))
	}
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

// startHeartbeatChecker 心跳检测增加写超时，防止Write阻塞
func startHeartbeatChecker() {
	ticker := time.NewTicker(scanInterval)
	defer ticker.Stop()
	for range ticker.C {
		mu.Lock()
		var toClose []net.Conn
		now := time.Now()
		for _, sess := range sessions {
			if now.Sub(sess.lastActiveAt) > heartbeatTimeout {
				toClose = append(toClose, sess.conn)
			}
		}
		mu.Unlock()
		for _, c := range toClose {
			log.Println("⚠️ 连接心跳超时，关闭", c.RemoteAddr())
			_ = c.SetWriteDeadline(time.Now().Add(1 * time.Second))
			_, _ = c.Write(Encode([]byte("⚠️ 心跳超时，连接断开")))
			_ = c.Close()
		}
	}
}

func initDB() error {
	var err error
	db, err = sql.Open("sqlite", "./im.db")
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	createSQL := `
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    security_question TEXT,
    security_answer TEXT
);
CREATE TABLE IF NOT EXISTS friends (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userA TEXT NOT NULL,
    userB TEXT NOT NULL,
    UNIQUE(userA,userB)
);
CREATE TABLE IF NOT EXISTS pending_friend (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fromUser TEXT NOT NULL,
    toUser TEXT NOT NULL,
    createTime DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(fromUser,toUser)
);
CREATE TABLE IF NOT EXISTS private_msg (
    msg_id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT NOT NULL,
    receiver TEXT NOT NULL,
    content TEXT NOT NULL,
    status INTEGER DEFAULT 0, --0正常，1已撤回
    createTime DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_read INTEGER DEFAULT 0, --0未读 1已读
    FOREIGN KEY(sender) REFERENCES users(username),
    FOREIGN KEY(receiver) REFERENCES users(username)
);
CREATE INDEX IF NOT EXISTS idx_private_sender ON private_msg(sender);
CREATE INDEX IF NOT EXISTS idx_private_receiver ON private_msg(receiver);
`
	_, err = db.Exec(createSQL)
	return err
}

func hashPassword(pwd string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
	return string(hash), err
}

func checkPassword(username, pwd string) (bool, error) {
	var hashPwd string
	row := db.QueryRow("SELECT password FROM users WHERE username=?", username)
	err := row.Scan(&hashPwd)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	err = bcrypt.CompareHashAndPassword([]byte(hashPwd), []byte(pwd))
	if err != nil {
		return false, nil
	}
	return true, nil
}

func registerUser(username, pwd string) error {
	hash, err := hashPassword(pwd)
	if err != nil {
		return err
	}
	_, err = db.Exec("INSERT INTO users(username,password) VALUES (?,?)", username, hash)
	return err
}

func setSecurityQuestion(username, question, answer string) error {
	ansHash, err := bcrypt.GenerateFromPassword([]byte(answer), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = db.Exec(`UPDATE users SET security_question=?, security_answer=? WHERE username=?`,
		question, string(ansHash), username)
	return err
}

func getSecurityQuestion(username string) (string, error) {
	var q string
	row := db.QueryRow(`SELECT security_question FROM users WHERE username=?`, username)
	err := row.Scan(&q)
	if err != nil {
		return "", err
	}
	return q, nil
}

func resetPasswordBySecAnswer(username, answer, newPwd string) (string, error) {
	var ansHash string
	row := db.QueryRow(`SELECT security_answer FROM users WHERE username=?`, username)
	err := row.Scan(&ansHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return "❌ 用户不存在", nil
		}
		return "", err
	}
	if ansHash == "" {
		return "❌ 该用户未设置密保，无法找回", nil
	}
	err = bcrypt.CompareHashAndPassword([]byte(ansHash), []byte(answer))
	if err != nil {
		return "❌ 密保答案错误", nil
	}
	if len(newPwd) < 3 {
		return "❌ 新密码至少3位", nil
	}
	newHash, err := hashPassword(newPwd)
	if err != nil {
		return "", err
	}
	_, err = db.Exec(`UPDATE users SET password=? WHERE username=?`, newHash, username)
	if err != nil {
		return "", err
	}
	return "✅ 密码重置成功，请使用新密码登录", nil
}

func getOnlineConn(targetName string) net.Conn {
	mu.Lock()
	defer mu.Unlock()
	for _, sess := range sessions {
		if sess.username == targetName {
			return sess.conn
		}
	}
	return nil
}

func sendSysMsg(username string, msg string) {
	conn := getOnlineConn(username)
	if conn != nil {
		_, _ = conn.Write(Encode([]byte(msg)))
	}
}

func addFriendApply(fromUser, toUser string) (string, error) {
	var exist int
	err := db.QueryRow("SELECT count(*) FROM users WHERE username=?", toUser).Scan(&exist)
	if err != nil {
		return "", err
	}
	if exist == 0 {
		return "❌ 用户不存在", nil
	}
	if fromUser == toUser {
		return "❌ 不能添加自己", nil
	}
	var isAlready int
	err = db.QueryRow(`SELECT count(*) FROM friends WHERE (userA=? AND userB=?) OR (userA=? AND userB=?)`,
		fromUser, toUser, toUser, fromUser).Scan(&isAlready)
	if err != nil {
		return "", err
	}
	if isAlready > 0 {
		return "❌ 你们已经是好友", nil
	}
	_, err = db.Exec("INSERT OR IGNORE INTO pending_friend(fromUser,toUser) VALUES (?,?)", fromUser, toUser)
	if err != nil {
		return "", err
	}
	sendSysMsg(toUser, fmt.Sprintf("📩 收到好友申请：【%s】想加你好友，输入 pendinglist 查看", fromUser))
	return fmt.Sprintf("✅ 成功向【%s】发送好友申请", toUser), nil
}

func acceptFriend(acceptUser, applyUser string) (string, error) {
	tx, err := db.Begin()
	if err != nil {
		return "", err
	}
	res, err := tx.Exec(`DELETE FROM pending_friend WHERE fromUser=? AND toUser=?`, applyUser, acceptUser)
	if err != nil {
		tx.Rollback()
		return "", err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		tx.Rollback()
		return "❌ 没有这条好友申请", nil
	}
	_, err = tx.Exec(`INSERT INTO friends(userA,userB) VALUES (?,?)`, applyUser, acceptUser)
	if err != nil {
		tx.Rollback()
		return "", err
	}
	_, err = tx.Exec(`INSERT INTO friends(userA,userB) VALUES (?,?)`, acceptUser, applyUser)
	if err != nil {
		tx.Rollback()
		return "", err
	}
	err = tx.Commit()
	if err != nil {
		return "", err
	}
	sendSysMsg(applyUser, fmt.Sprintf("✅【%s】同意了你的好友申请！", acceptUser))
	return fmt.Sprintf("✅ 成功添加【%s】为好友", applyUser), nil
}

func rejectFriend(acceptUser, applyUser string) (string, error) {
	res, err := db.Exec(`DELETE FROM pending_friend WHERE fromUser=? AND toUser=?`, applyUser, acceptUser)
	if err != nil {
		return "", err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return "❌ 没有这条好友申请", nil
	}
	sendSysMsg(applyUser, fmt.Sprintf("❌【%s】拒绝了你的好友申请", acceptUser))
	return fmt.Sprintf("✅ 已拒绝【%s】的好友申请", applyUser), nil
}

func delFriend(userA, userB string) (string, error) {
	tx, err := db.Begin()
	if err != nil {
		return "", err
	}
	_, err = tx.Exec(`DELETE FROM friends WHERE (userA=? AND userB=?) OR (userA=? AND userB=?)`,
		userA, userB, userB, userA)
	if err != nil {
		tx.Rollback()
		return "", err
	}
	err = tx.Commit()
	if err != nil {
		return "", err
	}
	sendSysMsg(userB, fmt.Sprintf("⚠️【%s】将你删除好友", userA))
	return fmt.Sprintf("✅ 已删除好友【%s】", userB), nil
}

func getFriendList(username string) ([]string, error) {
	rows, err := db.Query(`SELECT userB FROM friends WHERE userA=?`, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []string
	for rows.Next() {
		var u string
		rows.Scan(&u)
		list = append(list, u)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return list, nil
}

func getPendingList(username string) ([]string, error) {
	rows, err := db.Query(`SELECT fromUser FROM pending_friend WHERE toUser=?`, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []string
	for rows.Next() {
		var u string
		rows.Scan(&u)
		list = append(list, u)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return list, nil
}

func isFriend(u1, u2 string) (bool, error) {
	var cnt int
	err := db.QueryRow(`SELECT count(*) FROM friends WHERE (userA=? AND userB=?) OR (userA=? AND userB=?)`,
		u1, u2, u2, u1).Scan(&cnt)
	if err != nil {
		return false, err
	}
	return cnt > 0, nil
}

// ========== 私聊消息持久化、撤回、历史记录、未读消息 ==========
// savePrivateMsg 保存私聊消息，返回msgId
func savePrivateMsg(sender, receiver, content string) (int64, error) {
	res, err := db.Exec(`INSERT INTO private_msg(sender,receiver,content) VALUES (?,?,?)`, sender, receiver, content)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// recallPrivateMsg 撤回消息，校验发送者权限
func recallPrivateMsg(msgId int64, operator string) (string, error) {
	var sender string
	err := db.QueryRow(`SELECT sender FROM private_msg WHERE msg_id=?`, msgId).Scan(&sender)
	if err != nil {
		return "❌ 消息不存在", nil
	}
	if sender != operator {
		return "❌ 只有发送者可以撤回这条消息", nil
	}
	_, err = db.Exec(`UPDATE private_msg SET status=1 WHERE msg_id=?`, msgId)
	if err != nil {
		return "", err
	}
	return "✅ 消息撤回成功", nil
}

// getChatHistory 获取两人私聊历史记录
func getChatHistory(userA, userB string) ([]string, error) {
	rows, err := db.Query(`
    SELECT msg_id,sender,content,status,createTime
    FROM private_msg
    WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?)
    ORDER BY msg_id ASC
    `, userA, userB, userB, userA)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []string
	for rows.Next() {
		var msgId int64
		var sender, content, createTime string
		var status int
		err := rows.Scan(&msgId, &sender, &content, &status, &createTime)
		if err != nil {
			return nil, err
		}
		if status == 1 {
			list = append(list, fmt.Sprintf("[%s]【%s】: 【消息已撤回】 msgId:%d", createTime, sender, msgId))
		} else {
			list = append(list, fmt.Sprintf("[%s]【%s】: %s | msgId:%d", createTime, sender, content, msgId))
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return list, nil
}

// fetchUnreadMsg 登录拉取未读私聊消息，拉取后标记已读
func fetchUnreadMsg(username string) ([]string, error) {
	rows, err := db.Query(`
    SELECT msg_id,sender,content,status,createTime
    FROM private_msg
    WHERE receiver=? AND is_read=0
    ORDER BY msg_id ASC
    `, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var msgs []string
	var msgIds []int64
	for rows.Next() {
		var msgId int64
		var sender, content, createTime string
		var status int
		err := rows.Scan(&msgId, &sender, &content, &status, &createTime)
		if err != nil {
			return nil, err
		}
		msgIds = append(msgIds, msgId)
		if status == 1 {
			msgs = append(msgs, fmt.Sprintf("【离线消息 %s】【%s】:【消息已撤回】msgId:%d", createTime, sender, msgId))
		} else {
			msgs = append(msgs, fmt.Sprintf("【离线消息 %s】【%s】: %s | msgId:%d", createTime, sender, content, msgId))
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	// 批量标记为已读
	for _, mid := range msgIds {
		_, _ = db.Exec(`UPDATE private_msg SET is_read=1 WHERE msg_id=?`, mid)
	}
	return msgs, nil
}

func startChatLoop(conn net.Conn, username string) {
	// 登录拉取未读私聊消息
	unreadMsgs, err := fetchUnreadMsg(username)
	if err == nil && len(unreadMsgs) > 0 {
		for _, m := range unreadMsgs {
			_, _ = conn.Write(Encode([]byte(m)))
		}
	}
	for {
		body, err := Decode(conn, heartbeatTimeout)
		if err != nil {
			log.Println(username, "读取消息失败：", err)
			return
		}
		content := strings.TrimSpace(string(body))
		// 更新活跃时间
		mu.Lock()
		if sess, ok := sessions[conn]; ok {
			sess.lastActiveAt = time.Now()
		}
		mu.Unlock()
		if content == "" {
			continue
		}
		var resp string
		switch {
		case content == "ping":
			_, _ = conn.Write(Encode([]byte("pong")))
			continue
		case strings.HasPrefix(content, "addfriend|"):
			parts := strings.Split(content, "|")
			if len(parts) != 2 {
				resp = "❌ 格式错误 addfriend|用户名"
			} else {
				msg, err := addFriendApply(username, parts[1])
				if err != nil {
					resp = "❌ 数据库异常"
				} else {
					resp = msg
				}
			}
			_, _ = conn.Write(Encode([]byte(resp)))
			continue
		case content == "pendinglist":
			pending, err := getPendingList(username)
			if err != nil {
				resp = "❌ 查询申请失败"
			} else if len(pending) == 0 {
				resp = "📭 暂无待处理好友申请"
			} else {
				resp = "📩 待处理好友申请：" + strings.Join(pending, ", ")
			}
			_, _ = conn.Write(Encode([]byte(resp)))
			continue
		case strings.HasPrefix(content, "acceptfriend|"):
			parts := strings.Split(content, "|")
			if len(parts) != 2 {
				resp = "❌ 格式错误 acceptfriend|申请人"
			} else {
				msg, err := acceptFriend(username, parts[1])
				if err != nil {
					resp = "❌ 操作失败"
				} else {
					resp = msg
				}
			}
			_, _ = conn.Write(Encode([]byte(resp)))
			continue
		case strings.HasPrefix(content, "rejectfriend|"):
			parts := strings.Split(content, "|")
			if len(parts) != 2 {
				resp = "❌ 格式错误 rejectfriend|申请人"
			} else {
				msg, err := rejectFriend(username, parts[1])
				if err != nil {
					resp = "❌ 操作失败"
				} else {
					resp = msg
				}
			}
			_, _ = conn.Write(Encode([]byte(resp)))
			continue
		case content == "friendlist":
			friends, err := getFriendList(username)
			if err != nil {
				resp = "❌ 查询好友列表失败"
			} else if len(friends) == 0 {
				resp = "📋 好友列表为空"
			} else {
				resp = "📋 你的好友：" + strings.Join(friends, ", ")
			}
			_, _ = conn.Write(Encode([]byte(resp)))
			continue
		case strings.HasPrefix(content, "delfriend|"):
			parts := strings.Split(content, "|")
			if len(parts) != 2 {
				resp = "❌ 格式错误 delfriend|用户名"
			} else {
				msg, err := delFriend(username, parts[1])
				if err != nil {
					resp = "❌ 删除失败"
				} else {
					resp = msg
				}
			}
			_, _ = conn.Write(Encode([]byte(resp)))
			continue
		case strings.HasPrefix(content, "setsecq|"):
			parts := strings.Split(content, "|")
			if len(parts) != 3 {
				resp = "❌ 格式 setsecq|密保问题|密保答案"
			} else {
				err := setSecurityQuestion(username, parts[1], parts[2])
				if err != nil {
					resp = "❌ 设置密保失败"
				} else {
					resp = "✅ 密保设置成功！请牢记你的密保答案"
				}
			}
			_, _ = conn.Write(Encode([]byte(resp)))
			continue
		// 撤回私聊消息
		case strings.HasPrefix(content, "recall|"):
			parts := strings.Split(content, "|")
			if len(parts) != 2 {
				resp = "❌撤回指令格式 recall|msgId"
			} else {
				msgId, err := strconv.ParseInt(parts[1], 10, 64)
				if err != nil {
					resp = "❌ msgId必须是数字"
				} else {
					retMsg, err := recallPrivateMsg(msgId, username)
					if err != nil {
						resp = "❌撤回数据库异常"
					} else {
						resp = retMsg
						// 只有撤回成功，才推送撤回广播
						if retMsg == "✅ 消息撤回成功" {
							var receiver string
							errScan := db.QueryRow(`SELECT receiver FROM private_msg WHERE msg_id=?`, msgId).Scan(&receiver)
							if errScan == nil {
								notifyText := fmt.Sprintf("🔔 一条消息被撤回 msgId:%d", msgId)
								// 推送给接收方
								if recvConn := getOnlineConn(receiver); recvConn != nil {
									_, _ = recvConn.Write(Encode([]byte(notifyText)))
								}
								// 推送给撤回操作者本人
								if selfConn := getOnlineConn(username); selfConn != nil {
									_, _ = selfConn.Write(Encode([]byte(notifyText)))
								}
							}
						}
					}
				}
			}
			_, _ = conn.Write(Encode([]byte(resp)))
			continue
		// 查询历史聊天记录
		case strings.HasPrefix(content, "history|"):
			parts := strings.Split(content, "|")
			if len(parts) != 2 {
				resp = "❌历史记录指令格式 history|好友名"
			} else {
				target := parts[1]
				ok, err := isFriend(username, target)
				if err != nil || !ok {
					resp = "❌非好友不能查看历史记录"
				} else {
					historyList, err := getChatHistory(username, target)
					if err != nil {
						resp = "❌读取历史记录失败"
					} else if len(historyList) == 0 {
						resp = "📭暂无历史聊天记录"
					} else {
						resp = "📜历史聊天记录:\n" + strings.Join(historyList, "\n")
					}
				}
			}
			_, _ = conn.Write(Encode([]byte(resp)))
			continue
		case strings.HasPrefix(content, "@"):
			rest := content[1:]
			spaceIdx := strings.Index(rest, " ")
			if spaceIdx == -1 {
				resp = "❌ 私聊格式：@用户名 消息"
				_, _ = conn.Write(Encode([]byte(resp)))
				continue
			}
			targetName := rest[:spaceIdx]
			chatMsg := rest[spaceIdx+1:]
			ok, err := isFriend(username, targetName)
			if err != nil || !ok {
				resp = "❌ 非好友不能私聊"
				_, _ = conn.Write(Encode([]byte(resp)))
				continue
			}
			// 保存私聊消息入库拿到msgId
			msgId, err := savePrivateMsg(username, targetName, chatMsg)
			if err != nil {
				resp = "❌ 保存消息失败"
			} else {
				privateMsg := fmt.Sprintf("【私聊 %s->%s】%s | msgId:%d", username, targetName, chatMsg, msgId)
				log.Println(privateMsg)
				targetConn := getOnlineConn(targetName)
				if targetConn == nil {
					resp = fmt.Sprintf("💤【%s】离线，消息已保存，上线自动推送, msgId:%d", targetName, msgId)
				} else {
					// 发给接收方
					_, writeErr := targetConn.Write(Encode([]byte(privateMsg)))
					if writeErr != nil {
						resp = fmt.Sprintf("❌ 发给【%s】失败", targetName)
					} else {
						resp = fmt.Sprintf("✅私聊发送成功 msgId:%d", msgId)
					}
				}
				// ========== 修复：把消息回显给发送者自己 ==========
				_, _ = conn.Write(Encode([]byte(privateMsg)))
			}
			_, _ = conn.Write(Encode([]byte(resp)))
			continue
		}
		// 公共频道广播消息（不入库，不可撤回）
		msg := fmt.Sprintf("【公共】【%s】: %s", username, content)
		log.Println("公共消息：", msg)
		mu.Lock()
		var conns []net.Conn
		for c := range sessions {
			conns = append(conns, c)
		}
		mu.Unlock()
		pkt := Encode([]byte(msg))
		for _, c := range conns {
			_, writeErr := c.Write(pkt)
			if writeErr != nil {
				log.Printf("转发失败 %v", writeErr)
			}
		}
	}
}

func handleConn(conn net.Conn) {
	mu.Lock()
	sess := &ClientSession{
		conn:         conn,
		username:     "",
		lastActiveAt: time.Now(),
	}
	sessions[conn] = sess
	mu.Unlock()
	defer func() {
		mu.Lock()
		delete(sessions, conn)
		mu.Unlock()
		conn.Close()
		log.Println("客户端断开：", conn.RemoteAddr())
	}()

	for {
		body, err := Decode(conn, heartbeatTimeout)
		if err != nil {
			log.Println("读取认证失败", err)
			return
		}
		raw := strings.TrimSpace(string(body))
		// 认证阶段更新心跳
		mu.Lock()
		sess.lastActiveAt = time.Now()
		mu.Unlock()
		parts := strings.Split(raw, "|")
		var resp string
		if len(parts) >= 1 {
			switch parts[0] {
			case "getsecq":
				if len(parts) != 2 {
					resp = "❌ 格式 getsecq|用户名"
				} else {
					q, err := getSecurityQuestion(parts[1])
					if err != nil {
						resp = "❌ 查询失败，用户不存在或未设置密保"
					} else {
						resp = fmt.Sprintf("❓密保问题：%s", q)
					}
				}
				_, _ = conn.Write(Encode([]byte(resp)))
				continue
			case "resetpwd":
				if len(parts) != 4 {
					resp = "❌ 格式 resetpwd|用户名|密保答案|新密码"
				} else {
					msg, err := resetPasswordBySecAnswer(parts[1], parts[2], parts[3])
					if err != nil {
						resp = "❌ 重置失败，数据库异常"
					} else {
						resp = msg
					}
				}
				_, _ = conn.Write(Encode([]byte(resp)))
				continue
			}
		}

		if len(parts) != 3 {
			resp = "❌ 格式：register|user|pass 或 login|user|pass，找回密码可用 getsecq|xxx / resetpwd|user|答案|新密码"
			_, _ = conn.Write(Encode([]byte(resp)))
			continue
		}
		action, username, pwd := parts[0], parts[1], parts[2]
		if strings.Contains(username, " ") {
			resp = "❌ 用户名不能带空格"
			_, _ = conn.Write(Encode([]byte(resp)))
			continue
		}
		if username == "" || pwd == "" {
			resp = "❌ 用户名密码不能为空"
			_, _ = conn.Write(Encode([]byte(resp)))
			continue
		}
		if len(pwd) < 3 {
			resp = "❌ 密码至少3位"
			_, _ = conn.Write(Encode([]byte(resp)))
			continue
		}
		var loginSuccess bool
		if action == "register" {
			err := registerUser(username, pwd)
			if err != nil {
				resp = "❌ 注册失败，用户名已存在"
				_, _ = conn.Write(Encode([]byte(resp)))
				continue
			}
			resp = "✅ 注册成功，自动登录"
			_, _ = conn.Write(Encode([]byte(resp)))
			loginSuccess = true
		} else if action == "login" {
			ok, err := checkPassword(username, pwd)
			if err != nil {
				resp = "❌ 服务内部错误"
				_, _ = conn.Write(Encode([]byte(resp)))
				continue
			}
			if !ok {
				resp = "❌ 用户或密码错误"
				_, _ = conn.Write(Encode([]byte(resp)))
				continue
			}
			loginSuccess = true
		} else {
			resp = "❌ 只能 register / login"
			_, _ = conn.Write(Encode([]byte(resp)))
			continue
		}
		if loginSuccess {
			mu.Lock()
			// 单点登录踢旧连接
			var oldConn net.Conn
			for c, s := range sessions {
				if s.username == username {
					oldConn = c
					delete(sessions, c)
					break
				}
			}
			if oldConn != nil {
				_ = oldConn.SetWriteDeadline(time.Now().Add(1 * time.Second))
				_, _ = oldConn.Write(Encode([]byte("⚠️你的账号在其他设备登录，你已被踢下线！")))
				_ = oldConn.Close()
				log.Printf("【%s】旧连接被踢下线", username)
			}
			sess.username = username
			sessions[conn] = sess
			mu.Unlock()
			// 只返回登录成功，不再下发指令列表
			helpText := `✅登录成功！`
			_, _ = conn.Write(Encode([]byte(helpText)))
			log.Printf("【%s】上线 %s", username, conn.RemoteAddr())
			startChatLoop(conn, username)
			return
		}
	}
}

func main() {
	err := initDB()
	if err != nil {
		log.Fatal("数据库初始化失败", err)
	}
	defer db.Close()
	log.Println("✅ SQLite IM数据库加载成功")
	go startHeartbeatChecker()
	listener, err := net.Listen("tcp", "0.0.0.0:8080")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	log.Println("IM服务启动 0.0.0.0:8080")
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Accept失败：", err)
			continue
		}
		log.Println("新客户端待认证", conn.RemoteAddr())
		go handleConn(conn)
	}
}
