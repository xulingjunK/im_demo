# README.md

```markdown
# im-chat-server

基于 Golang 原生 TCP 开发的即时通讯服务，实现自定义二进制消息协议、账号注册登录、密码加密存储、多客户端在线广播聊天。

## 项目特性

- **自定义 TCP 消息协议**：`4字节大端长度头 + 消息体`，自动处理 TCP 粘包、拆包，限制单包最大 4096 字节防止超大包攻击
- **账号认证系统**：SQLite 嵌入式数据库存储用户，密码采用 bcrypt 哈希加密，不保存明文；支持注册/登录，认证失败可重试
- **并发模型**：每客户端单独 Goroutine 处理 IO，`sync.Mutex` 维护在线用户集合，锁内只拷贝连接列表、网络 IO 放锁外，优化并发性能
- **消息广播**：用户发送消息，服务端转发给所有在线客户端

## 技术栈

- 语言：Golang
- 网络：原生 TCP Socket
- 并发：Goroutine + sync.Mutex
- 存储：SQLite（modernc.org/sqlite，纯 Go 无 CGO）
- 密码安全：bcrypt 哈希加密
- 版本管理：Git + GitHub SSH

## 项目结构

```
im-chat-server
├── client
│   └── main.go      # 控制台客户端，注册登录、收发消息
├── server
│   └── main.go      # IM 服务端，协议编解码、账号校验、消息广播
├── go.mod
├── go.sum
├── .gitignore
└── README.md
```

## 运行方式

### 1. 拉取依赖

```bash
go mod tidy
```

### 2. 启动服务端（终端 1）

```bash
cd server
go run main.go
```

监听 `0.0.0.0:8080`，自动创建 `im.db` SQLite 数据库文件。

### 3. 启动客户端（新开多个终端模拟多用户）

```bash
cd client
go run main.go
```

- 输入 `1` 注册新账号，输入用户名密码
- 输入 `2` 登录已有账号
- 登录成功后，输入消息回车即可群发

## 后续迭代计划

- [ ] 增加心跳包 + 断线重连
- [ ] 扩展协议，支持私聊/群聊两种消息类型
- [ ] 聊天记录写入 SQLite 持久化
- [ ] 接入大模型 API，实现 AI 自动对话
- [ ] 消息改用 Protobuf 序列化
```

---

## 配套 .gitignore（如果还没有）

```gitignore
*.exe
im.db
*.db
*.db-journal
go.work
.idea/
.vscode/
```

## 配套 go.mod

```go
module im-chat-server

go 1.22

require (
	golang.org/x/crypto v0.26.0
	modernc.org/sqlite v1.32.0
)
```

---
