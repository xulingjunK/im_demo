package main

import (
	"database/sql"
	"encoding/binary"
	"errors"
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
	serverAddr       = "0.0.0.0:8080"
	maxPacketSize    = 4096
	heartbeatTimeout = 10 * time.Second
	scanInterval     = 2 * time.Second
	writeTimeout     = 2 * time.Second
	minPasswordLen   = 3
	maxPasswordLen   = 128
	maxNicknameLen   = 20
	accountIDLength  = 10
	firstAccountID   = int64(1)
	maxAccountNumber = int64(9999999999)
)

// =========================
// Session
// =========================

type ClientSession struct {
	conn         net.Conn
	accountID    string
	nickname     string
	lastActiveAt time.Time
	writeMu      sync.Mutex
}

var (
	sessions    = make(map[net.Conn]*ClientSession)
	onlineUsers = make(map[string]*ClientSession)
	sessionMu   sync.RWMutex
	registerMu  sync.Mutex // 单进程内串行分配账号ID，避免 SQLite 事务竞争
	db          *sql.DB
)

// =========================
// TCP 数据包
// =========================

func Encode(body []byte) []byte {
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(body)))
	return append(header, body...)
}

func Decode(r io.Reader, timeout time.Duration) ([]byte, error) {
	if conn, ok := r.(net.Conn); ok && timeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	bodyLen := binary.BigEndian.Uint32(header)
	if bodyLen > maxPacketSize {
		return nil, fmt.Errorf("packet too large: %d > %d", bodyLen, maxPacketSize)
	}

	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}

	return body, nil
}

func writeSession(sess *ClientSession, msg string) error {
	if sess == nil || sess.conn == nil {
		return errors.New("invalid session")
	}

	sess.writeMu.Lock()
	defer sess.writeMu.Unlock()

	_ = sess.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	defer sess.conn.SetWriteDeadline(time.Time{})

	_, err := sess.conn.Write(Encode([]byte(msg)))
	return err
}

// =========================
// Session 管理
// =========================

func touchSession(conn net.Conn) {
	sessionMu.Lock()
	if sess, ok := sessions[conn]; ok {
		sess.lastActiveAt = time.Now()
	}
	sessionMu.Unlock()
}

func getOnlineSession(accountID string) *ClientSession {
	sessionMu.RLock()
	sess := onlineUsers[accountID]
	sessionMu.RUnlock()
	return sess
}

func snapshotOnlineSessions() []*ClientSession {
	sessionMu.RLock()
	defer sessionMu.RUnlock()

	list := make([]*ClientSession, 0, len(onlineUsers))
	for _, sess := range onlineUsers {
		list = append(list, sess)
	}
	return list
}

func removeSession(sess *ClientSession) {
	if sess == nil {
		return
	}

	sessionMu.Lock()

	if current, ok := sessions[sess.conn]; ok && current == sess {
		delete(sessions, sess.conn)
	}

	if sess.accountID != "" {
		if current, ok := onlineUsers[sess.accountID]; ok && current == sess {
			delete(onlineUsers, sess.accountID)
		}
	}

	sessionMu.Unlock()

	_ = sess.conn.Close()
}

func loginSession(sess *ClientSession, accountID, nickname string) {
	var oldSession *ClientSession

	sessionMu.Lock()

	if existing, ok := onlineUsers[accountID]; ok && existing != sess {
		oldSession = existing

		if current, ok := sessions[existing.conn]; ok && current == existing {
			delete(sessions, existing.conn)
		}

		delete(onlineUsers, accountID)
	}

	sess.accountID = accountID
	sess.nickname = nickname
	sess.lastActiveAt = time.Now()

	sessions[sess.conn] = sess
	onlineUsers[accountID] = sess

	sessionMu.Unlock()

	if oldSession != nil {
		_ = writeSession(oldSession, "⚠️你的账号在其他设备登录，你已被踢下线！")
		_ = oldSession.conn.Close()
		log.Printf("【%s】旧连接被踢下线", accountID)
	}
}

func sendSysMsg(accountID, msg string) {
	sess := getOnlineSession(accountID)
	if sess == nil {
		return
	}

	if err := writeSession(sess, msg); err != nil {
		log.Printf("发送系统消息给【%s】失败：%v", accountID, err)
	}
}

func broadcast(msg string) {
	for _, sess := range snapshotOnlineSessions() {
		if err := writeSession(sess, msg); err != nil {
			log.Printf("公共消息发送给【%s】失败：%v", sess.accountID, err)
		}
	}
}

// =========================
// 心跳检测
// =========================

func startHeartbeatChecker() {
	ticker := time.NewTicker(scanInterval)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		var expired []*ClientSession

		sessionMu.RLock()
		for _, sess := range sessions {
			if now.Sub(sess.lastActiveAt) > heartbeatTimeout {
				expired = append(expired, sess)
			}
		}
		sessionMu.RUnlock()

		for _, sess := range expired {
			sessionMu.RLock()
			current, exists := sessions[sess.conn]
			sessionMu.RUnlock()

			if !exists || current != sess {
				continue
			}

			log.Printf(
				"⚠️ 【%s】心跳超时，关闭 %s",
				displayAccount(sess),
				sess.conn.RemoteAddr(),
			)

			_ = writeSession(sess, "⚠️ 心跳超时，连接断开")
			removeSession(sess)
		}
	}
}

// =========================
// 数据库初始化与迁移
// =========================

func initDB() error {
	var err error

	db, err = sql.Open("sqlite", "./im.db")
	if err != nil {
		return err
	}

	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)

	if _, err = db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		return err
	}

	if _, err = db.Exec(`PRAGMA busy_timeout = 5000`); err != nil {
		return err
	}

	ready, err := newSchemaExists()
	if err != nil {
		return err
	}

	if !ready {
		oldSchema, err := legacySchemaExists()
		if err != nil {
			return err
		}

		if oldSchema {
			log.Println("检测到旧版数据库，开始迁移账号体系...")
			if err := migrateLegacyDB(); err != nil {
				return err
			}
			log.Println("✅ 旧版数据库迁移完成")
		} else {
			if err := createNewSchema(); err != nil {
				return err
			}
		}
	}

	if err := ensureIndexes(); err != nil {
		return err
	}

	if err := ensureSequence(); err != nil {
		return err
	}

	return nil
}

func tableExists(table string) (bool, error) {
	var count int
	err := db.QueryRow(
		`SELECT COUNT(*)
		 FROM sqlite_master
		 WHERE type='table' AND name=?`,
		table,
	).Scan(&count)
	return count > 0, err
}

func newSchemaExists() (bool, error) {
	exists, err := tableExists("users")
	if err != nil || !exists {
		return false, err
	}

	var count int
	err = db.QueryRow(`
		SELECT COUNT(*)
		FROM pragma_table_info('users')
		WHERE name='account_id'
	`).Scan(&count)

	return count > 0, err
}

func legacySchemaExists() (bool, error) {
	exists, err := tableExists("users")
	if err != nil {
		return false, err
	}
	if !exists {
		return false, nil
	}

	var count int
	err = db.QueryRow(`
		SELECT COUNT(*)
		FROM pragma_table_info('users')
		WHERE name='username'
	`).Scan(&count)

	return count > 0, err
}

func createNewSchema() error {
	schema := `
CREATE TABLE IF NOT EXISTS users (
    account_id TEXT PRIMARY KEY
        CHECK(length(account_id)=10),
    nickname TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password TEXT NOT NULL,
    security_question TEXT,
    security_answer TEXT
);

CREATE TABLE IF NOT EXISTS friends (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userA TEXT NOT NULL,
    userB TEXT NOT NULL,
    UNIQUE(userA,userB),
    FOREIGN KEY(userA) REFERENCES users(account_id) ON DELETE CASCADE,
    FOREIGN KEY(userB) REFERENCES users(account_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS pending_friend (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fromUser TEXT NOT NULL,
    toUser TEXT NOT NULL,
    createTime DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(fromUser,toUser),
    FOREIGN KEY(fromUser) REFERENCES users(account_id) ON DELETE CASCADE,
    FOREIGN KEY(toUser) REFERENCES users(account_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS private_msg (
    msg_id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT NOT NULL,
    receiver TEXT NOT NULL,
    content TEXT NOT NULL,
    status INTEGER NOT NULL DEFAULT 0,
    createTime DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_read INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(sender) REFERENCES users(account_id) ON DELETE CASCADE,
    FOREIGN KEY(receiver) REFERENCES users(account_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS account_sequence (
    id INTEGER PRIMARY KEY CHECK(id=1),
    next_id INTEGER NOT NULL
);
`
	if _, err := db.Exec(schema); err != nil {
		return err
	}
	return nil
}

func ensureIndexes() error {
	indexes := `
CREATE INDEX IF NOT EXISTS idx_private_sender ON private_msg(sender);
CREATE INDEX IF NOT EXISTS idx_private_receiver ON private_msg(receiver);
CREATE INDEX IF NOT EXISTS idx_private_receiver_read ON private_msg(receiver,is_read);
CREATE INDEX IF NOT EXISTS idx_friends_userA ON friends(userA);
CREATE INDEX IF NOT EXISTS idx_friends_userB ON friends(userB);
CREATE INDEX IF NOT EXISTS idx_pending_toUser ON pending_friend(toUser);
`
	_, err := db.Exec(indexes)
	return err
}

func ensureSequence() error {
	exists, err := tableExists("account_sequence")
	if err != nil {
		return err
	}
	if !exists {
		if _, err := db.Exec(`
			CREATE TABLE account_sequence (
				id INTEGER PRIMARY KEY CHECK(id=1),
				next_id INTEGER NOT NULL
			)
		`); err != nil {
			return err
		}
	}

	var count int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM account_sequence WHERE id=1`,
	).Scan(&count); err != nil {
		return err
	}

	if count == 0 {
		var maxID int64
		if err := db.QueryRow(`
			SELECT COALESCE(MAX(CAST(account_id AS INTEGER)),0)
			FROM users
		`).Scan(&maxID); err != nil {
			return err
		}

		nextID := maxID + 1
		if nextID < firstAccountID {
			nextID = firstAccountID
		}

		_, err := db.Exec(
			`INSERT INTO account_sequence(id,next_id) VALUES(1,?)`,
			nextID,
		)
		return err
	}

	return nil
}

func migrateLegacyDB() error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	const (
		usersNew      = "users_new"
		friendsNew    = "friends_new"
		pendingNew    = "pending_friend_new"
		privateMsgNew = "private_msg_new"
		sequenceNew   = "account_sequence_new"
	)

	_, err = tx.Exec(`
CREATE TABLE users_new (
    account_id TEXT PRIMARY KEY CHECK(length(account_id)=10),
    nickname TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password TEXT NOT NULL,
    security_question TEXT,
    security_answer TEXT
);

CREATE TABLE friends_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userA TEXT NOT NULL,
    userB TEXT NOT NULL,
    UNIQUE(userA,userB),
    FOREIGN KEY(userA) REFERENCES users_new(account_id) ON DELETE CASCADE,
    FOREIGN KEY(userB) REFERENCES users_new(account_id) ON DELETE CASCADE
);

CREATE TABLE pending_friend_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fromUser TEXT NOT NULL,
    toUser TEXT NOT NULL,
    createTime DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(fromUser,toUser),
    FOREIGN KEY(fromUser) REFERENCES users_new(account_id) ON DELETE CASCADE,
    FOREIGN KEY(toUser) REFERENCES users_new(account_id) ON DELETE CASCADE
);

CREATE TABLE private_msg_new (
    msg_id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT NOT NULL,
    receiver TEXT NOT NULL,
    content TEXT NOT NULL,
    status INTEGER NOT NULL DEFAULT 0,
    createTime DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_read INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(sender) REFERENCES users_new(account_id) ON DELETE CASCADE,
    FOREIGN KEY(receiver) REFERENCES users_new(account_id) ON DELETE CASCADE
);

CREATE TABLE account_sequence_new (
    id INTEGER PRIMARY KEY CHECK(id=1),
    next_id INTEGER NOT NULL
);`)
	if err != nil {
		return err
	}

	// 检查旧 users 表是否有 nickname 列。
	var nicknameColumnCount int
	if err := tx.QueryRow(`
		SELECT COUNT(*)
		FROM pragma_table_info('users')
		WHERE name='nickname'
	`).Scan(&nicknameColumnCount); err != nil {
		return err
	}

	userQuery := `SELECT username,password,nickname,security_question,security_answer FROM users ORDER BY id ASC`
	if nicknameColumnCount == 0 {
		userQuery = `SELECT username,password,NULL,security_question,security_answer FROM users ORDER BY id ASC`
	}

	type legacyUser struct {
		oldUsername string
		password    string
		nickname    sql.NullString
		question    sql.NullString
		answer      sql.NullString
	}

	rows, err := tx.Query(userQuery)
	if err != nil {
		return err
	}
	defer rows.Close()

	var users []legacyUser
	usedNicknames := make(map[string]struct{})
	nextID := firstAccountID

	for rows.Next() {
		var u legacyUser
		if err := rows.Scan(
			&u.oldUsername,
			&u.password,
			&u.nickname,
			&u.question,
			&u.answer,
		); err != nil {
			return err
		}

		if nextID > maxAccountNumber {
			return errors.New("旧数据库用户数量超过10位账号ID可表示范围")
		}

		accountID := fmt.Sprintf("%010d", nextID)
		nextID++

		nickname := strings.TrimSpace(u.nickname.String)
		if nickname == "" || len([]rune(nickname)) > maxNicknameLen ||
			strings.ContainsAny(nickname, "|\r\n\t") || hasNickname(usedNicknames, nickname) {
			nickname = makeLegacyNickname(accountID, usedNicknames)
		}
		usedNicknames[normalizeNicknameKey(nickname)] = struct{}{}

		if _, err := tx.Exec(`
			INSERT INTO users_new(
				account_id,nickname,password,security_question,security_answer
			) VALUES(?,?,?,?,?)`,
			accountID,
			nickname,
			u.password,
			nullableString(u.question),
			nullableString(u.answer),
		); err != nil {
			return err
		}

		users = append(users, u)
	}

	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	userMap := make(map[string]string, len(users))
	for i, u := range users {
		userMap[u.oldUsername] = fmt.Sprintf("%010d", firstAccountID+int64(i))
	}

	// 迁移好友关系。
	if exists, err := tableExistsTx(tx, "friends"); err != nil {
		return err
	} else if exists {
		frows, err := tx.Query(`SELECT userA,userB FROM friends`)
		if err != nil {
			return err
		}

		for frows.Next() {
			var oldA, oldB string
			if err := frows.Scan(&oldA, &oldB); err != nil {
				frows.Close()
				return err
			}
			newA, okA := userMap[oldA]
			newB, okB := userMap[oldB]
			if okA && okB && newA != newB {
				if _, err := tx.Exec(
					`INSERT OR IGNORE INTO friends_new(userA,userB) VALUES(?,?)`,
					newA, newB,
				); err != nil {
					frows.Close()
					return err
				}
			}
		}
		if err := frows.Err(); err != nil {
			frows.Close()
			return err
		}
		frows.Close()
	}

	// 迁移好友申请。
	if exists, err := tableExistsTx(tx, "pending_friend"); err != nil {
		return err
	} else if exists {
		prows, err := tx.Query(`SELECT fromUser,toUser,createTime FROM pending_friend`)
		if err != nil {
			return err
		}

		for prows.Next() {
			var oldFrom, oldTo, createTime string
			if err := prows.Scan(&oldFrom, &oldTo, &createTime); err != nil {
				prows.Close()
				return err
			}
			newFrom, okFrom := userMap[oldFrom]
			newTo, okTo := userMap[oldTo]
			if okFrom && okTo && newFrom != newTo {
				if _, err := tx.Exec(`
					INSERT OR IGNORE INTO pending_friend_new(fromUser,toUser,createTime)
					VALUES(?,?,?)`,
					newFrom, newTo, createTime,
				); err != nil {
					prows.Close()
					return err
				}
			}
		}
		if err := prows.Err(); err != nil {
			prows.Close()
			return err
		}
		prows.Close()
	}

	// 迁移私聊消息。
	if exists, err := tableExistsTx(tx, "private_msg"); err != nil {
		return err
	} else if exists {
		mrows, err := tx.Query(`
			SELECT msg_id,sender,receiver,content,status,createTime,is_read
			FROM private_msg
			ORDER BY msg_id ASC`)
		if err != nil {
			return err
		}

		for mrows.Next() {
			var msgID int64
			var oldSender, oldReceiver, content, createTime string
			var status, isRead int

			if err := mrows.Scan(
				&msgID,
				&oldSender,
				&oldReceiver,
				&content,
				&status,
				&createTime,
				&isRead,
			); err != nil {
				mrows.Close()
				return err
			}

			newSender, okSender := userMap[oldSender]
			newReceiver, okReceiver := userMap[oldReceiver]
			if !okSender || !okReceiver {
				continue
			}

			if _, err := tx.Exec(`
				INSERT INTO private_msg_new(
					msg_id,sender,receiver,content,status,createTime,is_read
				) VALUES(?,?,?,?,?,?,?)`,
				msgID,
				newSender,
				newReceiver,
				content,
				status,
				createTime,
				isRead,
			); err != nil {
				mrows.Close()
				return err
			}
		}

		if err := mrows.Err(); err != nil {
			mrows.Close()
			return err
		}
		mrows.Close()
	}

	if _, err := tx.Exec(
		`INSERT INTO account_sequence_new(id,next_id) VALUES(1,?)`,
		nextID,
	); err != nil {
		return err
	}

	// 先删除旧表，再把新表换成正式名称。
	for _, table := range []string{
		"private_msg",
		"pending_friend",
		"friends",
		"users",
	} {
		exists, err := tableExistsTx(tx, table)
		if err != nil {
			return err
		}
		if exists {
			if _, err := tx.Exec(`DROP TABLE ` + table); err != nil {
				return err
			}
		}
	}

	for _, pair := range [][2]string{
		{"users_new", "users"},
		{"friends_new", "friends"},
		{"pending_friend_new", "pending_friend"},
		{"private_msg_new", "private_msg"},
		{"account_sequence_new", "account_sequence"},
	} {
		if _, err := tx.Exec(`ALTER TABLE ` + pair[0] + ` RENAME TO ` + pair[1]); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func tableExistsTx(tx *sql.Tx, table string) (bool, error) {
	var count int
	err := tx.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`,
		table,
	).Scan(&count)
	return count > 0, err
}

func nullableString(v sql.NullString) interface{} {
	if v.Valid {
		return v.String
	}
	return nil
}

func normalizeNicknameKey(nickname string) string {
	return strings.ToLower(strings.TrimSpace(nickname))
}

func hasNickname(used map[string]struct{}, nickname string) bool {
	_, ok := used[normalizeNicknameKey(nickname)]
	return ok
}

func makeLegacyNickname(accountID string, used map[string]struct{}) string {
	base := "用户" + accountID
	if !hasNickname(used, base) {
		return base
	}

	for i := 1; ; i++ {
		candidate := fmt.Sprintf("用户%s_%d", accountID, i)
		if len([]rune(candidate)) > maxNicknameLen {
			runes := []rune(candidate)
			candidate = string(runes[:maxNicknameLen])
		}
		if !hasNickname(used, candidate) {
			return candidate
		}
	}
}

// =========================
// 账号与昵称
// =========================

func validateAccountID(accountID string) error {
	if len(accountID) != accountIDLength {
		return errors.New("账号ID必须是10位数字")
	}

	for _, ch := range accountID {
		if ch < '0' || ch > '9' {
			return errors.New("账号ID必须全部为数字")
		}
	}

	if accountID == "0000000000" {
		return errors.New("账号ID无效")
	}

	n, err := strconv.ParseInt(accountID, 10, 64)
	if err != nil || n < firstAccountID || n > maxAccountNumber {
		return errors.New("账号ID超出有效范围")
	}

	return nil
}

func validateNickname(nickname string) error {
	nickname = strings.TrimSpace(nickname)

	if nickname == "" {
		return errors.New("昵称不能为空")
	}

	if len([]rune(nickname)) > maxNicknameLen {
		return fmt.Errorf("昵称不能超过%d个字符", maxNicknameLen)
	}

	if strings.ContainsAny(nickname, "|\r\n\t") {
		return errors.New("昵称不能包含 | 或换行符")
	}

	return nil
}

func validatePassword(password string) error {
	if password == "" {
		return errors.New("密码不能为空")
	}

	if len(password) < minPasswordLen {
		return fmt.Errorf("密码至少%d位", minPasswordLen)
	}

	if len(password) > maxPasswordLen {
		return fmt.Errorf("密码不能超过%d个字符", maxPasswordLen)
	}

	if strings.ContainsAny(password, "|\r\n\t") {
		return errors.New("密码不能包含 | 或换行符")
	}

	return nil
}

func generateAccountIDTx(tx *sql.Tx) (string, error) {
	if _, err := tx.Exec(
		`UPDATE account_sequence SET next_id=next_id+1 WHERE id=1`,
	); err != nil {
		return "", err
	}

	var number int64
	if err := tx.QueryRow(
		`SELECT next_id-1 FROM account_sequence WHERE id=1`,
	).Scan(&number); err != nil {
		return "", err
	}

	if number < firstAccountID || number > maxAccountNumber {
		return "", errors.New("账号ID已达到10位数字上限")
	}

	return fmt.Sprintf("%010d", number), nil
}

func nicknameExistsTx(tx *sql.Tx, nickname, excludeAccountID string) (bool, error) {
	var count int

	query := `
		SELECT COUNT(*)
		FROM users
		WHERE nickname=? COLLATE NOCASE
	`
	args := []interface{}{nickname}

	if excludeAccountID != "" {
		query += ` AND account_id<>?`
		args = append(args, excludeAccountID)
	}

	if err := tx.QueryRow(query, args...).Scan(&count); err != nil {
		return false, err
	}

	return count > 0, nil
}

func registerUser(nickname, password string) (string, error) {
	registerMu.Lock()
	defer registerMu.Unlock()

	nickname = strings.TrimSpace(nickname)

	if err := validateNickname(nickname); err != nil {
		return "", err
	}

	if err := validatePassword(password); err != nil {
		return "", err
	}

	hash, err := hashPassword(password)
	if err != nil {
		return "", err
	}

	tx, err := db.Begin()
	if err != nil {
		return "", err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	exists, err := nicknameExistsTx(tx, nickname, "")
	if err != nil {
		return "", err
	}
	if exists {
		return "", errors.New("昵称已被其他用户使用")
	}

	accountID, err := generateAccountIDTx(tx)
	if err != nil {
		return "", err
	}

	if _, err := tx.Exec(`
		INSERT INTO users(account_id,nickname,password)
		VALUES(?,?,?)`,
		accountID,
		nickname,
		hash,
	); err != nil {
		return "", err
	}

	if err := tx.Commit(); err != nil {
		return "", err
	}

	return accountID, nil
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)
	return string(hash), err
}

func checkPassword(accountID, password string) (bool, error) {
	var hash string

	err := db.QueryRow(
		`SELECT password FROM users WHERE account_id=?`,
		accountID,
	).Scan(&hash)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}

	return bcrypt.CompareHashAndPassword(
		[]byte(hash),
		[]byte(password),
	) == nil, nil
}

func getUserProfile(accountID string) (string, string, error) {
	var nickname string

	err := db.QueryRow(
		`SELECT nickname FROM users WHERE account_id=?`,
		accountID,
	).Scan(&nickname)

	if err != nil {
		return "", "", err
	}

	return accountID, nickname, nil
}

func getNickname(accountID string) (string, error) {
	var nickname string
	err := db.QueryRow(
		`SELECT nickname FROM users WHERE account_id=?`,
		accountID,
	).Scan(&nickname)

	if err != nil {
		return "", err
	}

	return nickname, nil
}

// resolvePrivateTarget 根据“昵称 + 空格 + 消息”解析私聊目标。
// 数据库内部仍使用 account_id，客户端输入层只使用昵称。
// 由于昵称允许包含空格，因此匹配所有好友并选择最长的昵称前缀，避免歧义。
func resolvePrivateTarget(accountID, text string) (UserInfo, string, error) {
	friends, err := getFriendList(accountID)
	if err != nil {
		return UserInfo{}, "", err
	}

	var target UserInfo
	bestLen := -1

	for _, friend := range friends {
		if !strings.HasPrefix(text, friend.Nickname) {
			continue
		}

		rest := text[len(friend.Nickname):]
		if len(rest) == 0 || (rest[0] != ' ' && rest[0] != '\t') {
			continue
		}

		if len(friend.Nickname) > bestLen {
			target = friend
			bestLen = len(friend.Nickname)
		}
	}

	if bestLen == -1 {
		return UserInfo{}, "", errors.New("未找到对应昵称的好友")
	}

	message := strings.TrimSpace(text[bestLen:])
	if message == "" {
		return UserInfo{}, "", errors.New("私聊消息不能为空")
	}

	return target, message, nil
}

func changeNickname(accountID, nickname string) error {
	nickname = strings.TrimSpace(nickname)

	if err := validateNickname(nickname); err != nil {
		return err
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	exists, err := nicknameExistsTx(tx, nickname, accountID)
	if err != nil {
		return err
	}
	if exists {
		return errors.New("昵称已被其他用户使用")
	}

	result, err := tx.Exec(
		`UPDATE users SET nickname=? WHERE account_id=?`,
		nickname,
		accountID,
	)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return errors.New("昵称已被其他用户使用")
		}
		return err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return errors.New("账号不存在")
	}

	return tx.Commit()
}

func changePassword(accountID, oldPassword, newPassword string) error {
	if err := validatePassword(oldPassword); err != nil {
		return err
	}
	if err := validatePassword(newPassword); err != nil {
		return err
	}

	ok, err := checkPassword(accountID, oldPassword)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("旧密码错误")
	}

	newHash, err := hashPassword(newPassword)
	if err != nil {
		return err
	}

	_, err = db.Exec(
		`UPDATE users SET password=? WHERE account_id=?`,
		newHash,
		accountID,
	)
	return err
}

// =========================
// 密保 / 找回密码
// =========================

func setSecurityQuestion(accountID, question, answer string) error {
	question = strings.TrimSpace(question)
	answer = strings.TrimSpace(answer)

	if question == "" {
		return errors.New("密保问题不能为空")
	}
	if answer == "" {
		return errors.New("密保答案不能为空")
	}

	if strings.ContainsAny(question, "|\r\n\t") ||
		strings.ContainsAny(answer, "|\r\n\t") {
		return errors.New("密保问题和答案不能包含 | 或换行符")
	}

	ansHash, err := bcrypt.GenerateFromPassword(
		[]byte(answer),
		bcrypt.DefaultCost,
	)
	if err != nil {
		return err
	}

	result, err := db.Exec(`
		UPDATE users
		SET security_question=?, security_answer=?
		WHERE account_id=?`,
		question,
		string(ansHash),
		accountID,
	)
	if err != nil {
		return err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return errors.New("账号不存在")
	}

	return nil
}

func getSecurityQuestion(accountID string) (string, error) {
	var question string

	err := db.QueryRow(`
		SELECT security_question
		FROM users
		WHERE account_id=?`,
		accountID,
	).Scan(&question)

	if err != nil {
		return "", err
	}

	if strings.TrimSpace(question) == "" {
		return "", errors.New("未设置密保")
	}

	return question, nil
}

func resetPasswordBySecAnswer(
	accountID,
	answer,
	newPassword string,
) error {
	if err := validatePassword(newPassword); err != nil {
		return err
	}

	var answerHash string
	err := db.QueryRow(`
		SELECT security_answer
		FROM users
		WHERE account_id=?`,
		accountID,
	).Scan(&answerHash)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("账号不存在")
		}
		return err
	}

	if answerHash == "" {
		return errors.New("该账号未设置密保，无法找回")
	}

	if bcrypt.CompareHashAndPassword(
		[]byte(answerHash),
		[]byte(answer),
	) != nil {
		return errors.New("密保答案错误")
	}

	newHash, err := hashPassword(newPassword)
	if err != nil {
		return err
	}

	_, err = db.Exec(
		`UPDATE users SET password=? WHERE account_id=?`,
		newHash,
		accountID,
	)
	return err
}

// =========================
// 好友
// =========================

// findAccountByNickname 根据全局唯一昵称查找账号ID。
func findAccountByNickname(nickname string) (string, error) {
	nickname = strings.TrimSpace(nickname)
	if err := validateNickname(nickname); err != nil {
		return "", err
	}

	var accountID string
	err := db.QueryRow(
		`SELECT account_id
		 FROM users
		 WHERE nickname=? COLLATE NOCASE`,
		nickname,
	).Scan(&accountID)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", errors.New("未找到该昵称对应的用户")
		}
		return "", err
	}

	return accountID, nil
}

func addFriendApply(fromID, toID string) error {
	toID = strings.TrimSpace(toID)

	if err := validateAccountID(toID); err != nil {
		return err
	}

	if fromID == toID {
		return errors.New("不能添加自己")
	}

	var count int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM users WHERE account_id=?`,
		toID,
	).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		return errors.New("账号不存在")
	}

	if err := db.QueryRow(`
		SELECT COUNT(*)
		FROM friends
		WHERE (userA=? AND userB=?)
		   OR (userA=? AND userB=?)`,
		fromID, toID, toID, fromID,
	).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return errors.New("你们已经是好友")
	}

	if err := db.QueryRow(`
		SELECT COUNT(*)
		FROM pending_friend
		WHERE fromUser=? AND toUser=?`,
		toID, fromID,
	).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return errors.New("对方已经向你发过好友申请，请输入 pendinglist 查看")
	}

	_, err := db.Exec(`
		INSERT OR IGNORE INTO pending_friend(fromUser,toUser)
		VALUES(?,?)`,
		fromID, toID,
	)
	if err != nil {
		return err
	}

	nickname, _ := getNickname(fromID)
	sendSysMsg(
		toID,
		fmt.Sprintf(
			"📩 收到好友申请：【%s】（%s）想加你好友，输入 pendinglist 查看",
			nickname,
			fromID,
		),
	)

	return nil
}

func acceptFriend(acceptID, applyID string) error {
	applyID = strings.TrimSpace(applyID)

	if err := validateAccountID(applyID); err != nil {
		return err
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	result, err := tx.Exec(`
		DELETE FROM pending_friend
		WHERE fromUser=? AND toUser=?`,
		applyID, acceptID,
	)
	if err != nil {
		return err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return errors.New("没有这条好友申请")
	}

	if _, err := tx.Exec(`
		INSERT OR IGNORE INTO friends(userA,userB)
		VALUES(?,?)`,
		applyID, acceptID,
	); err != nil {
		return err
	}

	if _, err := tx.Exec(`
		INSERT OR IGNORE INTO friends(userA,userB)
		VALUES(?,?)`,
		acceptID, applyID,
	); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	acceptNickname, _ := getNickname(acceptID)
	sendSysMsg(
		applyID,
		fmt.Sprintf("✅【%s】（%s）同意了你的好友申请！", acceptNickname, acceptID),
	)

	return nil
}

func rejectFriend(acceptID, applyID string) error {
	result, err := db.Exec(`
		DELETE FROM pending_friend
		WHERE fromUser=? AND toUser=?`,
		applyID, acceptID,
	)
	if err != nil {
		return err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return errors.New("没有这条好友申请")
	}

	acceptNickname, _ := getNickname(acceptID)
	sendSysMsg(
		applyID,
		fmt.Sprintf("❌【%s】（%s）拒绝了你的好友申请", acceptNickname, acceptID),
	)

	return nil
}

func delFriend(userA, userB string) error {
	userB = strings.TrimSpace(userB)

	if err := validateAccountID(userB); err != nil {
		return err
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	result, err := tx.Exec(`
		DELETE FROM friends
		WHERE (userA=? AND userB=?)
		   OR (userA=? AND userB=?)`,
		userA, userB, userB, userA,
	)
	if err != nil {
		return err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return errors.New("你们目前不是好友")
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	nickname, _ := getNickname(userA)
	sendSysMsg(
		userB,
		fmt.Sprintf("⚠️【%s】（%s）将你删除好友", nickname, userA),
	)

	return nil
}

type UserInfo struct {
	AccountID string
	Nickname  string
}

func getFriendList(accountID string) ([]UserInfo, error) {
	rows, err := db.Query(`
		SELECT u.account_id,u.nickname
		FROM friends f
		JOIN users u ON u.account_id=f.userB
		WHERE f.userA=?
		ORDER BY u.nickname COLLATE NOCASE`,
		accountID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []UserInfo

	for rows.Next() {
		var user UserInfo
		if err := rows.Scan(&user.AccountID, &user.Nickname); err != nil {
			return nil, err
		}
		list = append(list, user)
	}

	return list, rows.Err()
}

func getPendingList(accountID string) ([]UserInfo, error) {
	rows, err := db.Query(`
		SELECT u.account_id,u.nickname
		FROM pending_friend p
		JOIN users u ON u.account_id=p.fromUser
		WHERE p.toUser=?
		ORDER BY p.createTime ASC`,
		accountID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []UserInfo

	for rows.Next() {
		var user UserInfo
		if err := rows.Scan(&user.AccountID, &user.Nickname); err != nil {
			return nil, err
		}
		list = append(list, user)
	}

	return list, rows.Err()
}

func isFriend(userA, userB string) (bool, error) {
	var count int

	err := db.QueryRow(`
		SELECT COUNT(*)
		FROM friends
		WHERE (userA=? AND userB=?)
		   OR (userA=? AND userB=?)`,
		userA, userB, userB, userA,
	).Scan(&count)

	return count > 0, err
}

// =========================
// 私聊消息
// =========================

func savePrivateMsg(sender, receiver, content string) (int64, error) {
	result, err := db.Exec(`
		INSERT INTO private_msg(sender,receiver,content)
		VALUES(?,?,?)`,
		sender, receiver, content,
	)
	if err != nil {
		return 0, err
	}

	return result.LastInsertId()
}

func recallPrivateMsg(msgID int64, operator string) (string, error) {
	var receiver string

	err := db.QueryRow(`
		SELECT receiver
		FROM private_msg
		WHERE msg_id=? AND sender=?`,
		msgID, operator,
	).Scan(&receiver)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", errors.New("消息不存在、不是你发送的消息或已经撤回")
		}
		return "", err
	}

	result, err := db.Exec(`
		UPDATE private_msg
		SET status=1
		WHERE msg_id=? AND sender=? AND status=0`,
		msgID, operator,
	)
	if err != nil {
		return "", err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return "", err
	}
	if affected == 0 {
		return "", errors.New("消息不存在或已经撤回")
	}

	return receiver, nil
}

func formatMessage(
	createTime,
	displayName,
	content string,
	status int,
	msgID int64,
	offline bool,
) string {
	prefix := "[" + createTime + "]"
	if offline {
		prefix = "【离线消息 " + createTime + "】"
	}

	if status == 1 {
		return fmt.Sprintf(
			"%s【%s】:【消息已撤回】 msgId:%d",
			prefix,
			displayName,
			msgID,
		)
	}

	return fmt.Sprintf(
		"%s【%s】: %s | msgId:%d",
		prefix,
		displayName,
		content,
		msgID,
	)
}

// historyQueryMode 表示聊天记录查询方式。
const (
	historyAll     = "all"
	historyByTime  = "time"
	historyByMsgID = "msgid"
)

// getChatHistory 根据查询条件读取两人的私聊记录。
func getChatHistory(userA, userB, mode string, args ...interface{}) ([]string, error) {
	query := `
		SELECT p.msg_id,
		       COALESCE(NULLIF(u.nickname,''), p.sender),
		       p.content,
		       p.status,
		       p.createTime
		FROM private_msg p
		LEFT JOIN users u ON u.account_id=p.sender
		WHERE ((p.sender=? AND p.receiver=?)
		    OR (p.sender=? AND p.receiver=?))`
	params := []interface{}{userA, userB, userB, userA}

	switch mode {
	case historyAll:
	case historyByTime:
		if len(args) != 2 {
			return nil, errors.New("时间查询参数错误")
		}
		startTime, ok1 := args[0].(string)
		endTime, ok2 := args[1].(string)
		if !ok1 || !ok2 {
			return nil, errors.New("时间查询参数错误")
		}
		query += ` AND p.createTime>=? AND p.createTime<=?`
		params = append(params, startTime, endTime)
	case historyByMsgID:
		if len(args) != 1 {
			return nil, errors.New("消息ID查询参数错误")
		}
		msgID, ok := args[0].(int64)
		if !ok || msgID <= 0 {
			return nil, errors.New("msgId必须是正整数")
		}
		query += ` AND p.msg_id=?`
		params = append(params, msgID)
	default:
		return nil, errors.New("未知的历史记录查询方式")
	}

	query += ` ORDER BY p.msg_id ASC`

	rows, err := db.Query(query, params...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []string
	for rows.Next() {
		var (
			msgID                int64
			displayName, content string
			status               int
			createTime           string
		)
		if err := rows.Scan(&msgID, &displayName, &content, &status, &createTime); err != nil {
			return nil, err
		}
		list = append(list, formatMessage(
			createTime, displayName, content, status, msgID, false,
		))
	}
	return list, rows.Err()
}

// sendHistoryResult 将历史记录分包发送，避免超过 TCP 单包 4096 字节限制。
func sendHistoryResult(sess *ClientSession, title string, history []string) error {
	if len(history) == 0 {
		return writeSession(sess, title+"\n📭 暂无符合条件的聊天记录")
	}

	const chunkLimit = 3500

	if err := writeSession(
		sess,
		fmt.Sprintf("%s\n📚 共找到 %d 条记录：", title, len(history)),
	); err != nil {
		return err
	}

	var builder strings.Builder
	flush := func() error {
		if builder.Len() == 0 {
			return nil
		}
		msg := "📜 " + builder.String()
		builder.Reset()
		return writeSession(sess, msg)
	}

	for _, line := range history {
		if len([]byte(line)) > chunkLimit {
			if err := flush(); err != nil {
				return err
			}
			runes := []rune(line)
			for len(runes) > 0 {
				end, size := 0, 0
				for end < len(runes) {
					n := len([]byte(string(runes[end])))
					if size+n > chunkLimit {
						break
					}
					size += n
					end++
				}
				if end == 0 {
					end = 1
				}
				if err := writeSession(sess, "📜 "+string(runes[:end])); err != nil {
					return err
				}
				runes = runes[end:]
			}
			continue
		}

		if builder.Len() > 0 && builder.Len()+1+len([]byte(line)) > chunkLimit {
			if err := flush(); err != nil {
				return err
			}
		}
		if builder.Len() > 0 {
			builder.WriteByte('\n')
		}
		builder.WriteString(line)
	}
	return flush()
}

func fetchUnreadMsg(accountID string) ([]string, error) {
	rows, err := db.Query(`
		SELECT p.msg_id,
		       COALESCE(NULLIF(u.nickname,''), p.sender),
		       p.content,
		       p.status,
		       p.createTime
		FROM private_msg p
		LEFT JOIN users u ON u.account_id=p.sender
		WHERE p.receiver=? AND p.is_read=0
		ORDER BY p.msg_id ASC`,
		accountID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type unread struct {
		msgID       int64
		displayName string
		content     string
		status      int
		createTime  string
	}

	var pending []unread
	for rows.Next() {
		var m unread
		if err := rows.Scan(
			&m.msgID,
			&m.displayName,
			&m.content,
			&m.status,
			&m.createTime,
		); err != nil {
			return nil, err
		}
		pending = append(pending, m)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	msgs := make([]string, 0, len(pending))
	for _, m := range pending {
		msgs = append(
			msgs,
			formatMessage(
				m.createTime,
				m.displayName,
				m.content,
				m.status,
				m.msgID,
				true,
			),
		)
	}

	if len(pending) > 0 {
		tx, err := db.Begin()
		if err != nil {
			return nil, err
		}

		for _, m := range pending {
			if _, err := tx.Exec(
				`UPDATE private_msg SET is_read=1 WHERE msg_id=?`,
				m.msgID,
			); err != nil {
				_ = tx.Rollback()
				return nil, err
			}
		}

		if err := tx.Commit(); err != nil {
			return nil, err
		}
	}

	return msgs, nil
}

// =========================
// 显示与公共广播
// =========================

func displayAccount(sess *ClientSession) string {
	if sess == nil {
		return "未登录"
	}

	sessionMu.RLock()
	accountID := sess.accountID
	nickname := sess.nickname
	sessionMu.RUnlock()

	if accountID == "" {
		return "未登录"
	}

	return fmt.Sprintf("%s(%s)", nickname, accountID)
}

// =========================
// 已登录命令
// =========================

func startChatLoop(sess *ClientSession) {
	accountID := sess.accountID

	unreadMsgs, err := fetchUnreadMsg(accountID)
	if err != nil {
		log.Printf("【%s】读取离线消息失败：%v", accountID, err)
	} else {
		for _, msg := range unreadMsgs {
			if err := writeSession(sess, msg); err != nil {
				log.Printf("【%s】发送离线消息失败：%v", accountID, err)
				return
			}
		}
	}

	for {
		body, err := Decode(sess.conn, heartbeatTimeout)
		if err != nil {
			log.Printf("【%s】读取消息失败：%v", accountID, err)
			return
		}

		touchSession(sess.conn)

		content := strings.TrimSpace(string(body))
		if content == "" {
			continue
		}

		var resp string

		switch {
		case content == "ping":
			if err := writeSession(sess, "pong"); err != nil {
				return
			}
			continue

		case content == "profile":
			_, nickname, err := getUserProfile(accountID)
			if err != nil {
				resp = "❌ 读取个人资料失败"
			} else {
				resp = fmt.Sprintf(
					"👤 账号ID：%s\n🏷️ 昵称：%s",
					accountID,
					nickname,
				)
			}

		case content == "changenick":
			resp = "❌ 格式：changenick|新昵称"

		case strings.HasPrefix(content, "changenick|"):
			parts := strings.SplitN(content, "|", 2)
			if len(parts) != 2 {
				resp = "❌ 格式：changenick|新昵称"
				break
			}

			newNickname := strings.TrimSpace(parts[1])
			if err := changeNickname(accountID, newNickname); err != nil {
				if strings.Contains(err.Error(), "昵称已被其他用户使用") {
					resp = "❌ 昵称已被其他用户使用"
				} else {
					resp = "❌ 修改昵称失败：" + err.Error()
				}
				break
			}

			sessionMu.Lock()
			if current, ok := sessions[sess.conn]; ok && current == sess {
				sess.nickname = newNickname
			}
			sessionMu.Unlock()

			resp = fmt.Sprintf(
				"✅ 昵称修改成功：%s",
				newNickname,
			)

		case content == "changepwd":
			resp = "❌ 格式：changepwd|旧密码|新密码"

		case strings.HasPrefix(content, "changepwd|"):
			parts := strings.Split(content, "|")
			if len(parts) != 3 {
				resp = "❌ 格式：changepwd|旧密码|新密码"
				break
			}

			if err := changePassword(
				accountID,
				parts[1],
				parts[2],
			); err != nil {
				resp = "❌ 修改密码失败：" + err.Error()
			} else {
				resp = "✅ 密码修改成功，请牢记新密码"
			}

		case content == "addfriend":
			resp = "❌ 格式：addfriend|id|账号ID 或 addfriend|nick|昵称"

		case strings.HasPrefix(content, "addfriend|"):
			parts := strings.SplitN(content, "|", 3)
			if len(parts) != 3 {
				resp = "❌ 格式：addfriend|id|账号ID 或 addfriend|nick|昵称"
				break
			}

			mode := strings.ToLower(strings.TrimSpace(parts[1]))
			target := strings.TrimSpace(parts[2])
			var targetID string

			switch mode {
			case "id":
				targetID = target
				if err := validateAccountID(targetID); err != nil {
					resp = "❌ " + err.Error()
					break
				}

			case "nick":
				resolvedID, err := findAccountByNickname(target)
				if err != nil {
					resp = "❌ 添加好友失败：" + err.Error()
					break
				}
				targetID = resolvedID

			default:
				resp = "❌ 添加方式只能是 id 或 nick"
				break
			}

			if targetID == "" {
				break
			}

			if err := addFriendApply(accountID, targetID); err != nil {
				resp = "❌ 添加好友失败：" + err.Error()
			} else {
				targetNick, err := getNickname(targetID)
				if err != nil {
					resp = "✅ 已发送好友申请"
				} else {
					resp = fmt.Sprintf(
						"✅ 已向【%s】（%s）发送好友申请",
						targetNick,
						targetID,
					)
				}
			}

		case content == "pendinglist":
			pending, err := getPendingList(accountID)
			if err != nil {
				resp = "❌ 查询申请失败"
			} else if len(pending) == 0 {
				resp = "📭 暂无待处理好友申请"
			} else {
				lines := make([]string, 0, len(pending))
				for _, user := range pending {
					lines = append(
						lines,
						fmt.Sprintf("【%s】%s", user.AccountID, user.Nickname),
					)
				}
				resp = "📩 待处理好友申请：\n" + strings.Join(lines, "\n")
			}

		case strings.HasPrefix(content, "acceptfriend|"):
			parts := strings.Split(content, "|")
			if len(parts) != 2 {
				resp = "❌ 格式：acceptfriend|账号ID"
				break
			}

			if err := acceptFriend(accountID, parts[1]); err != nil {
				resp = "❌ 同意失败：" + err.Error()
			} else {
				nick, _ := getNickname(parts[1])
				resp = fmt.Sprintf(
					"✅ 已添加【%s】（%s）为好友",
					nick,
					parts[1],
				)
			}

		case strings.HasPrefix(content, "rejectfriend|"):
			parts := strings.Split(content, "|")
			if len(parts) != 2 {
				resp = "❌ 格式：rejectfriend|账号ID"
				break
			}

			if err := rejectFriend(accountID, parts[1]); err != nil {
				resp = "❌ 拒绝失败：" + err.Error()
			} else {
				nick, _ := getNickname(parts[1])
				resp = fmt.Sprintf(
					"✅ 已拒绝【%s】（%s）的好友申请",
					nick,
					parts[1],
				)
			}

		case content == "friendlist":
			friends, err := getFriendList(accountID)
			if err != nil {
				resp = "❌ 查询好友列表失败"
			} else if len(friends) == 0 {
				resp = "📋 好友列表为空"
			} else {
				lines := make([]string, 0, len(friends))
				for _, user := range friends {
					lines = append(
						lines,
						fmt.Sprintf("【%s】%s", user.AccountID, user.Nickname),
					)
				}
				resp = "📋 我的好友：\n" + strings.Join(lines, "\n")
			}

		case strings.HasPrefix(content, "delfriend|"):
			parts := strings.Split(content, "|")
			if len(parts) != 2 {
				resp = "❌ 格式：delfriend|账号ID"
				break
			}

			if err := delFriend(accountID, parts[1]); err != nil {
				resp = "❌ 删除好友失败：" + err.Error()
			} else {
				nick, _ := getNickname(parts[1])
				resp = fmt.Sprintf(
					"✅ 已删除好友【%s】（%s）",
					nick,
					parts[1],
				)
			}

		case strings.HasPrefix(content, "setsecq|"):
			parts := strings.Split(content, "|")
			if len(parts) != 3 {
				resp = "❌ 格式：setsecq|问题|答案"
				break
			}

			if err := setSecurityQuestion(
				accountID,
				parts[1],
				parts[2],
			); err != nil {
				resp = "❌ 设置密保失败：" + err.Error()
			} else {
				resp = "✅ 密保设置成功！请牢记你的密保答案"
			}

		case strings.HasPrefix(content, "recall|"):
			parts := strings.Split(content, "|")
			if len(parts) != 2 {
				resp = "❌ 格式：recall|msgId"
				break
			}

			msgID, err := strconv.ParseInt(parts[1], 10, 64)
			if err != nil || msgID <= 0 {
				resp = "❌ msgId必须是正整数"
				break
			}

			receiver, err := recallPrivateMsg(msgID, accountID)
			if err != nil {
				resp = "❌ " + err.Error()
				break
			}

			notifyText := fmt.Sprintf(
				"🔔 一条消息被撤回 msgId:%d",
				msgID,
			)

			sendSysMsg(receiver, notifyText)
			_ = writeSession(sess, notifyText)

			resp = "✅ 消息撤回成功"

		case content == "history":
			resp = "❌ 格式：history|好友账号ID|all / history|好友账号ID|time|开始日期|结束日期 / history|好友账号ID|msgid|消息ID"

		case strings.HasPrefix(content, "history|"):
			parts := strings.Split(content, "|")
			if len(parts) < 3 {
				resp = "❌ 格式：history|好友账号ID|all / history|好友账号ID|time|开始日期|结束日期 / history|好友账号ID|msgid|消息ID"
				break
			}

			targetID := strings.TrimSpace(parts[1])
			mode := strings.ToLower(strings.TrimSpace(parts[2]))

			if err := validateAccountID(targetID); err != nil {
				resp = "❌ " + err.Error()
				break
			}
			if targetID == accountID {
				resp = "❌ 不能查询自己的私聊记录"
				break
			}

			ok, err := isFriend(accountID, targetID)
			if err != nil {
				resp = "❌ 查询好友关系失败"
				break
			}
			if !ok {
				resp = "❌ 非好友不能查看历史记录"
				break
			}

			var history []string
			var title string

			switch mode {
			case historyAll:
				if len(parts) != 3 {
					resp = "❌ 全部查询格式：history|好友账号ID|all"
					break
				}
				history, err = getChatHistory(accountID, targetID, historyAll)
				title = "📜 全部私聊历史记录"

			case historyByTime:
				if len(parts) != 5 {
					resp = "❌ 日期查询格式：history|好友账号ID|time|开始日期|结束日期"
					break
				}

				startDate := strings.TrimSpace(parts[3])
				endDate := strings.TrimSpace(parts[4])

				startTime, startErr := time.Parse("2006-01-02", startDate)
				if startErr != nil {
					resp = "❌ 开始日期格式错误，应为：YYYY-MM-DD"
					break
				}

				endTime, endErr := time.Parse("2006-01-02", endDate)
				if endErr != nil {
					resp = "❌ 结束日期格式错误，应为：YYYY-MM-DD"
					break
				}

				if startTime.After(endTime) {
					resp = "❌ 开始日期不能晚于结束日期"
					break
				}

				startTimeText := startDate + " 00:00:00"
				endTimeText := endDate + " 23:59:59"

				history, err = getChatHistory(
					accountID, targetID, historyByTime, startTimeText, endTimeText,
				)
				title = fmt.Sprintf("📜 日期范围：%s ~ %s", startDate, endDate)

			case historyByMsgID:
				if len(parts) != 4 {
					resp = "❌ 消息ID查询格式：history|好友账号ID|msgid|消息ID"
					break
				}
				msgID, parseErr := strconv.ParseInt(strings.TrimSpace(parts[3]), 10, 64)
				if parseErr != nil || msgID <= 0 {
					resp = "❌ msgId必须是正整数"
					break
				}

				history, err = getChatHistory(
					accountID, targetID, historyByMsgID, msgID,
				)
				title = fmt.Sprintf("📜 消息ID：%d", msgID)

			default:
				resp = "❌ 查询方式只能是 all、time 或 msgid"
				break
			}

			if resp != "" {
				break
			}
			if err != nil {
				resp = "❌ 读取历史聊天记录失败：" + err.Error()
				break
			}
			if err := sendHistoryResult(sess, title, history); err != nil {
				log.Printf("【%s】发送历史聊天记录失败：%v", accountID, err)
				return
			}
			continue

		case strings.HasPrefix(content, "@"):
			rest := strings.TrimSpace(content[1:])
			target, chatMsg, err := resolvePrivateTarget(accountID, rest)
			if err != nil {
				if strings.Contains(err.Error(), "未找到对应昵称") {
					resp = "❌ 未找到对应昵称的好友，请先查看 friendlist"
				} else {
					resp = "❌ " + err.Error()
				}
				break
			}

			targetID := target.AccountID
			targetNickname := target.Nickname

			msgID, err := savePrivateMsg(
				accountID,
				targetID,
				chatMsg,
			)
			if err != nil {
				resp = "❌ 保存消息失败"
				break
			}

			senderNickname := sess.nickname

			receiverMsg := fmt.Sprintf(
				"【私聊】【%s】: %s | msgId:%d",
				senderNickname,
				chatMsg,
				msgID,
			)

			senderMsg := fmt.Sprintf(
				"【私聊→%s】【%s】: %s | msgId:%d",
				targetNickname,
				senderNickname,
				chatMsg,
				msgID,
			)

			targetSession := getOnlineSession(targetID)
			if targetSession == nil {
				resp = fmt.Sprintf(
					"💤【%s】（%s）离线，消息已保存，上线自动推送，msgId:%d",
					targetNickname,
					targetID,
					msgID,
				)
			} else if err := writeSession(targetSession, receiverMsg); err != nil {
				resp = fmt.Sprintf(
					"❌ 发给【%s】失败，消息已保存",
					targetNickname,
				)
			} else {
				resp = fmt.Sprintf(
					"✅ 私聊发送成功 msgId:%d",
					msgID,
				)
			}

			if err := writeSession(sess, senderMsg); err != nil {
				log.Printf("【%s】回显私聊消息失败：%v", accountID, err)
			}

		default:
			// 保留原有公共广播：任何登录用户都可以直接输入消息。
			msg := fmt.Sprintf(
				"【公共】【%s】: %s",
				sess.nickname,
				content,
			)

			log.Printf(
				"公共消息【%s(%s)】：%s",
				sess.nickname,
				accountID,
				content,
			)

			broadcast(msg)
			continue
		}

		if resp != "" {
			if err := writeSession(sess, resp); err != nil {
				log.Printf("【%s】发送响应失败：%v", accountID, err)
				return
			}
		}
	}
}

// =========================
// 认证
// =========================

func handleConn(conn net.Conn) {
	sess := &ClientSession{
		conn:         conn,
		lastActiveAt: time.Now(),
	}

	sessionMu.Lock()
	sessions[conn] = sess
	sessionMu.Unlock()

	defer func() {
		removeSession(sess)
		log.Printf("客户端断开：%s", conn.RemoteAddr())
	}()

	for {
		body, err := Decode(conn, heartbeatTimeout)
		if err != nil {
			log.Printf(
				"读取认证失败 %s：%v",
				conn.RemoteAddr(),
				err,
			)
			return
		}

		touchSession(conn)

		raw := strings.TrimSpace(string(body))
		if raw == "" {
			continue
		}

		parts := strings.Split(raw, "|")
		if len(parts) == 0 {
			continue
		}

		switch parts[0] {
		case "ping":
			if err := writeSession(sess, "pong"); err != nil {
				return
			}
			continue

		case "getsecq":
			var resp string

			if len(parts) != 2 {
				resp = "❌ 格式：getsecq|账号ID"
			} else if err := validateAccountID(parts[1]); err != nil {
				resp = "❌ " + err.Error()
			} else {
				question, err := getSecurityQuestion(parts[1])
				if err != nil {
					resp = "❌ 查询失败：账号不存在或未设置密保"
				} else {
					resp = "❓密保问题：" + question
				}
			}

			if err := writeSession(sess, resp); err != nil {
				return
			}
			continue

		case "resetpwd":
			var resp string

			if len(parts) != 4 {
				resp = "❌ 格式：resetpwd|账号ID|密保答案|新密码"
			} else if err := validateAccountID(parts[1]); err != nil {
				resp = "❌ " + err.Error()
			} else if strings.ContainsAny(parts[2], "|\r\n\t") {
				resp = "❌ 密保答案不能包含 | 或换行符"
			} else if err := resetPasswordBySecAnswer(
				parts[1],
				parts[2],
				parts[3],
			); err != nil {
				resp = "❌ 密码重置失败：" + err.Error()
			} else {
				resp = "✅ 密码重置成功，请使用新密码登录"
			}

			if err := writeSession(sess, resp); err != nil {
				return
			}
			continue
		}

		if len(parts) != 3 {
			if err := writeSession(
				sess,
				"❌ 格式：register|昵称|密码 或 login|账号ID|密码；找回密码使用 getsecq|账号ID / resetpwd|账号ID|答案|新密码",
			); err != nil {
				return
			}
			continue
		}

		action := parts[0]

		switch action {
		case "register":
			accountID, err := registerUser(parts[1], parts[2])
			if err != nil {
				var resp string

				if strings.Contains(err.Error(), "昵称已被其他用户使用") {
					resp = "❌ 昵称已被其他用户使用"
				} else {
					resp = "❌ 注册失败：" + err.Error()
				}

				if writeErr := writeSession(sess, resp); writeErr != nil {
					return
				}
				continue
			}

			nickname, err := getNickname(accountID)
			if err != nil {
				if writeErr := writeSession(
					sess,
					"❌ 注册成功，但读取账号信息失败，请重新登录",
				); writeErr != nil {
					return
				}
				continue
			}

			loginSession(sess, accountID, nickname)

			resp := fmt.Sprintf(
				"✅ 注册成功！\n账号ID：%s\n昵称：%s\n请牢记你的10位账号ID，账号ID不可修改。",
				accountID,
				nickname,
			)

			if err := writeSession(sess, resp); err != nil {
				return
			}

			log.Printf(
				"【%s】【%s】注册并登录成功 %s",
				nickname,
				accountID,
				conn.RemoteAddr(),
			)

			startChatLoop(sess)
			return

		case "login":
			accountID := strings.TrimSpace(parts[1])

			if err := validateAccountID(accountID); err != nil {
				if err := writeSession(sess, "❌ "+err.Error()); err != nil {
					return
				}
				continue
			}

			if err := validatePassword(parts[2]); err != nil {
				if err := writeSession(sess, "❌ "+err.Error()); err != nil {
					return
				}
				continue
			}

			ok, err := checkPassword(accountID, parts[2])
			if err != nil {
				log.Printf("【%s】登录数据库异常：%v", accountID, err)
				if err := writeSession(sess, "❌ 服务内部错误"); err != nil {
					return
				}
				continue
			}

			if !ok {
				if err := writeSession(sess, "❌ 账号ID或密码错误"); err != nil {
					return
				}
				continue
			}

			nickname, err := getNickname(accountID)
			if err != nil {
				if err := writeSession(sess, "❌ 读取账号信息失败"); err != nil {
					return
				}
				continue
			}

			loginSession(sess, accountID, nickname)

			resp := fmt.Sprintf(
				"✅ 登录成功！\n账号ID：%s\n昵称：%s",
				accountID,
				nickname,
			)

			if err := writeSession(sess, resp); err != nil {
				return
			}

			log.Printf(
				"【%s】【%s】上线 %s",
				nickname,
				accountID,
				conn.RemoteAddr(),
			)

			startChatLoop(sess)
			return

		default:
			if err := writeSession(
				sess,
				"❌ 只能使用 register 或 login",
			); err != nil {
				return
			}
		}
	}
}

// =========================
// main
// =========================

func main() {
	if err := initDB(); err != nil {
		log.Fatal("数据库初始化失败：", err)
	}
	defer db.Close()

	log.Println("✅ SQLite IM 数据库加载成功")

	go startHeartbeatChecker()

	listener, err := net.Listen("tcp", serverAddr)
	if err != nil {
		log.Fatal("监听失败：", err)
	}
	defer listener.Close()

	log.Println("✅ IM 服务启动", serverAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Accept失败：", err)
			continue
		}

		log.Println("新客户端待认证：", conn.RemoteAddr())
		go handleConn(conn)
	}
}
