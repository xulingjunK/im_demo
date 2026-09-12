package main

import (
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite" // 纯Go sqlite驱动，无CGO
)

var (
	clients = make(map[net.Conn]string) // conn -> username
	mu      sync.Mutex
	db      *sql.DB
)

// Encode 编码：4字节大端长度头 + 消息体
func Encode(body []byte) []byte {
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(body)))
	return append(header, body...)
}

// Decode 解码：读取完整数据包，自动处理粘包拆包
func Decode(r io.Reader) ([]byte, error) {
	// 读取4字节长度头
	headerBuf := make([]byte, 4)
	_, err := io.ReadFull(r, headerBuf)
	if err != nil {
		return nil, err
	}
	bodyLen := binary.BigEndian.Uint32(headerBuf)
	// 安全限制，防止超大包攻击
	if bodyLen > 4096 {
		return nil, io.ErrShortBuffer
	}
	// 读取消息体
	bodyBuf := make([]byte, bodyLen)
	_, err = io.ReadFull(r, bodyBuf)
	return bodyBuf, err
}

// 初始化SQLite嵌入式数据库
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
		password TEXT NOT NULL
	);`
	_, err = db.Exec(createSQL)
	return err
}

// bcrypt加密密码
func hashPassword(pwd string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
	return string(hash), err
}

// 校验账号密码
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

// 注册用户写入SQLite
func registerUser(username, pwd string) error {
	hash, err := hashPassword(pwd)
	if err != nil {
		return err
	}
	_, err = db.Exec("INSERT INTO users(username,password) VALUES (?,?)", username, hash)
	return err
}

func startChatLoop(conn net.Conn, username string) {
	for {
		body, err := Decode(conn)
		if err != nil {
			log.Println(username, "读取聊天消息失败：", err)
			return
		}
		content := strings.TrimSpace(string(body))
		msg := fmt.Sprintf("【%s】: %s", username, content)
		log.Println("收到消息：", msg)

		// 缩小锁范围：只拷贝map，网络IO放到锁外（高并发优化）
		mu.Lock()
		var conns []net.Conn
		for c := range clients {
			conns = append(conns, c)
		}
		mu.Unlock()

		sendPacket := Encode([]byte(msg))
		for _, c := range conns {
			_, writeErr := c.Write(sendPacket)
			if writeErr != nil {
				log.Printf("转发给 %s 失败: %v", c.RemoteAddr(), writeErr)
			}
		}
	}
}

func handleConn(conn net.Conn) {
	defer func() {
		mu.Lock()
		delete(clients, conn)
		mu.Unlock()
		conn.Close()
		log.Println("客户端断开：", conn.RemoteAddr())
	}()

	// ========== 认证循环：失败可以重试，不关闭连接 ==========
	for {
		body, err := Decode(conn)
		if err != nil {
			log.Println("读取认证信息失败", err)
			return
		}
		raw := strings.TrimSpace(string(body))
		parts := strings.Split(raw, "|")
		if len(parts) != 3 {
			resp := "❌ 格式错误！指令格式：register|user|pass 或 login|user|pass，请重新输入"
			_, _ = conn.Write(Encode([]byte(resp)))
			continue
		}
		action, username, pwd := parts[0], parts[1], parts[2]

		// ========= 新增：用户名不能带空格 =========
		if strings.Contains(username, " ") {
			resp := "❌ 用户名不能包含空格，请重新输入"
			_, _ = conn.Write(Encode([]byte(resp)))
			continue
		}

		// 简单参数校验
		if username == "" || pwd == "" {
			resp := "❌ 用户名和密码不能为空，请重新输入"
			_, _ = conn.Write(Encode([]byte(resp)))
			continue
		}
		if len(pwd) < 3 {
			resp := "❌ 密码至少3位，请重新输入"
			_, _ = conn.Write(Encode([]byte(resp)))
			continue
		}

		var loginSuccess bool
		if action == "register" {
			err := registerUser(username, pwd)
			if err != nil {
				resp := "❌ 注册失败！用户名已存在，请重新输入"
				_, _ = conn.Write(Encode([]byte(resp)))
				continue // 继续循环，等待客户端再次提交认证，不退出
			}
			resp := "✅ 注册成功，自动登录"
			_, _ = conn.Write(Encode([]byte(resp)))
			loginSuccess = true
		} else if action == "login" {
			ok, err := checkPassword(username, pwd)
			if err != nil {
				log.Println("校验错误：", err)
				resp := "❌ 服务内部错误，请重新输入"
				_, _ = conn.Write(Encode([]byte(resp)))
				continue
			}
			if !ok {
				resp := "❌ 用户名或密码错误，请重新输入"
				_, _ = conn.Write(Encode([]byte(resp)))
				continue // 登录失败，继续认证循环，重试
			}
			loginSuccess = true
		} else {
			resp := "❌ 无效指令，只能 register 或 login，请重新输入"
			_, _ = conn.Write(Encode([]byte(resp)))
			continue
		}

		if loginSuccess {
			mu.Lock()
			clients[conn] = username
			mu.Unlock()
			resp := fmt.Sprintf("✅【%s】登录成功，可以聊天！", username)
			_, _ = conn.Write(Encode([]byte(resp)))
			log.Printf("【%s】上线 %s", username, conn.RemoteAddr())
			// 进入聊天循环，跳出认证循环
			startChatLoop(conn, username)
			return
		}
	}
}

func main() {
	err := initDB()
	if err != nil {
		log.Fatal("SQLite数据库初始化失败：", err)
	}
	defer db.Close()
	log.Println("✅ SQLite嵌入式数据库加载成功，数据库文件：im.db")
	// 监听 0.0.0.0:8080，支持局域网访问
	listener, err := net.Listen("tcp", "0.0.0.0:8080")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	log.Println("IM服务启动，监听 0.0.0.0:8080")
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("接受连接失败：", err)
			continue
		}
		log.Println("新客户端待认证：", conn.RemoteAddr())
		go handleConn(conn)
	}
}
