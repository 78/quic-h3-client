# HTTP/3 Client Pure Python Implementation

一个从零实现的 QUIC/HTTP/3 轻型客户端（仅进行 API HTTP 请求），学习研究用。

## 📋 目录

- [项目简介](#项目简介)
- [已实现功能](#已实现功能)
- [未实现功能](#未实现功能)
- [快速开始](#快速开始)
- [项目结构](#项目结构)
- [注意事项](#注意事项)

---

## 项目简介

这是一个完全从零实现的 HTTP/3 客户端，遵循以下标准：
- **RFC 9000**: QUIC: A UDP-Based Multiplexed and Secure Transport
- **RFC 9001**: Using TLS to Secure QUIC
- **RFC 9002**: QUIC Loss Detection and Congestion Control
- **RFC 9114**: HTTP/3
- **RFC 9204**: QPACK: Header Compression for HTTP/3

### 设计目标

- ✅ 轻量级实现，适合嵌入式设备
- ✅ 支持 TLS 1.3 加密和 0-RTT 会话恢复
- ✅ 完整的丢包检测和重传机制
- ✅ QPACK 头部压缩（静态表 + 动态表解码）
- ✅ 多流并发请求

### 适用场景

- 需要快速连接建立的场景（0-RTT）
- 学习和研究 QUIC/HTTP/3 协议

---

## ✅ 已实现功能

### QUIC 协议层

#### 连接管理
- ✅ **连接建立**: Initial → Handshake → 1-RTT 完整流程
- ✅ **TLS 1.3 加密**: 
  - AEAD-GCM-128/256 加密
  - X25519 密钥交换
  - 证书验证
- ✅ **0-RTT 会话恢复**: Session Ticket 支持，加速后续连接
- ✅ **Key Update**: RFC 9001 Section 6，支持 1-RTT 密钥轮换
  - 主动发起密钥更新（`initiate_key_update()`）
  - 处理对端发起的密钥更新
  - Key Phase bit 正确设置和检测
  - 过渡期密钥管理（支持新旧密钥并存）
- ✅ **优雅关闭**: CONNECTION_CLOSE 帧处理
- ✅ **Stateless Reset**: 检测和处理无状态重置包
- ✅ **Connection ID 管理**: 
  - NEW_CONNECTION_ID 帧发送和接收
  - RETIRE_CONNECTION_ID 帧处理（自动和手动）
  - 根据 `retire_prior_to` 自动退休旧连接 ID
- ✅ **路径验证**: 
  - PATH_CHALLENGE (0x1a) 帧发送和接收
  - PATH_RESPONSE (0x1b) 帧自动响应
  - 主动路径验证 API (`send_path_challenge()`, `validate_path_async()`)
  - 支持网络切换场景的路径探测

#### 流控制
- ✅ **连接级流控**: MAX_DATA 帧
- ✅ **流级流控**: MAX_STREAM_DATA 帧
- ✅ **流限制**: MAX_STREAMS_BIDI/UNI 帧

#### 丢包检测与恢复
- ✅ **RTT 估算**: 基于 RFC 9002 的 RTT 平滑算法
- ✅ **丢包检测**: 
  - 时间阈值检测（9/8 × RTT）
  - 包数阈值检测（3 个包）
- ✅ **PTO 探测**: Probe Timeout 机制，防止连接卡死
- ✅ **ACK 处理**: 发送和接收 ACK 帧
- ✅ **帧重传**: CRYPTO 和 STREAM 帧自动重传

#### 拥塞控制
- ✅ **CWND 窗口管理**: 基于 RFC 9002 的拥塞窗口控制
- ✅ **Slow Start**: 慢启动算法，初始窗口 14720 字节（10 × MTU）
- ✅ **Congestion Avoidance**: 拥塞避免阶段线性增长
- ✅ **AIMD**: 加性增乘性减算法（NewReno 风格）
- ✅ **Recovery 状态**: 丢包时的拥塞恢复机制
- ✅ **Persistent Congestion**: 持续拥塞检测和窗口重置

#### 帧类型支持
- ✅ PADDING (0x00)
- ✅ PING (0x01)
- ✅ ACK (0x02)
- ✅ CRYPTO (0x06)
- ✅ NEW_TOKEN (0x07)
- ✅ STREAM (0x08-0x0f)
- ✅ MAX_DATA (0x10)
- ✅ MAX_STREAM_DATA (0x11)
- ✅ MAX_STREAMS_BIDI (0x12)
- ✅ MAX_STREAMS_UNI (0x13)
- ✅ NEW_CONNECTION_ID (0x18)
- ✅ RETIRE_CONNECTION_ID (0x19)
- ✅ PATH_CHALLENGE (0x1a)
- ✅ PATH_RESPONSE (0x1b)
- ✅ CONNECTION_CLOSE (0x1c)
- ✅ CONNECTION_CLOSE_APP (0x1d)
- ✅ HANDSHAKE_DONE (0x1e)
- ✅ DATAGRAM (0x30/0x31) - RFC 9221 扩展

#### DATAGRAM 扩展 (RFC 9221)
- ✅ **max_datagram_frame_size**: Transport Parameter 协商
- ✅ **DATAGRAM 帧**: 发送和接收不可靠数据报
- ✅ **可配置支持**: 通过 `enable_datagram` 参数启用
- ✅ **异步接收**: `recv_datagram()` 异步 API

### HTTP/3 协议层

#### 流管理
- ✅ **Control Stream**: 初始化和 SETTINGS 交换
- ✅ **QPACK Encoder Stream**: 接收服务器动态表更新
- ✅ **QPACK Decoder Stream**: 发送解码指令
- ✅ **请求流**: 双向流，支持并发请求

#### QPACK 头部压缩
- ✅ **静态表编码**: 发送请求时使用静态表索引
- ✅ **静态表解码**: 解码响应头中的静态表引用
- ✅ **动态表解码**: 完整支持服务器动态表更新和解码
- ✅ **Huffman 解码**: 响应头中的 Huffman 编码解码
- ✅ **Section Acknowledgment**: 发送解码确认

#### HTTP/3 帧
- ✅ **HEADERS (0x01)**: 请求/响应头
- ✅ **DATA (0x00)**: 请求/响应体
- ✅ **SETTINGS (0x04)**: 协议设置
- ✅ **GOAWAY (0x07)**: 优雅关闭流程（RFC 9114 Section 5.2）
- ✅ **MAX_PUSH_ID (0x0d)**: 推送 ID 限制

#### 功能特性
- ✅ **并发请求**: 单连接多流并发
- ✅ **流重组**: 处理乱序到达的数据
- ✅ **优雅关闭**: GOAWAY 帧支持，完整的 graceful shutdown API
- ✅ **Wireshark 支持**: SSLKEYLOGFILE 格式密钥日志

---

## ❌ 未实现功能

### 高优先级（建议实现）

---

### 中优先级（可选实现）

#### 🟡 高级拥塞控制算法
- ❌ **Cubic**: 基于立方函数的拥塞控制算法
- ❌ **BBR**: Google 的基于带宽和 RTT 的拥塞控制算法

**当前状态**: 已实现基于 RFC 9002 的 NewReno 风格拥塞控制（Slow Start + AIMD）

**影响**: 在某些网络环境下，高级算法可能提供更好的性能

---

### 低优先级（可选实现）

#### 🟢 Server Push
- ❌ **PUSH_PROMISE (0x05)**: 推送承诺帧处理
- ❌ **Push Stream**: 推送流处理

**当前状态**: 仅定义常量，无实际处理逻辑。MAX_PUSH_ID 设置为 0，明确禁用 Server Push。

**说明**: 虽然 HTTP/3 (RFC 9114) 协议层面仍然支持 Server Push，但在实际应用中已经很少使用：
- 服务器难以准确判断客户端需要哪些资源，容易浪费带宽
- 主流浏览器和客户端实现已经很少支持或默认禁用此功能
- 现代 Web 开发更倾向于使用其他优化技术（如预加载、预连接等）

**影响**: 无法接收服务器推送资源（实际应用中通常不需要）


#### 🟢 QPACK 动态表编码
- ❌ **客户端动态表**: 使用动态表压缩请求头
- ❌ **动态表管理**: 插入、复制、容量设置

**当前状态**: 只用静态表 + 字面量

**影响**: 请求头压缩率不够高（但对嵌入式设备影响小）

#### 🟢 Huffman 编码
- ❌ **请求头 Huffman 编码**: 发送请求时压缩字符串

**当前状态**: 只有解码，编码用原始字符串

**影响**: 对嵌入式设备影响很小
- API 请求头通常很短，Huffman 压缩收益有限（可能只节省几个字节）
- 编码需要额外的 CPU 和内存开销，收益不明显
- 2Mbps 带宽对 API 请求已足够
- 解码已实现，不影响接收服务器响应

#### 🟢 ECN 支持
- ❌ **ACK_ECN (0x03)**: 显式拥塞通知

**影响**: 无法利用 ECN 信号优化传输

---

### 扩展功能（可选）

#### ✅ DATAGRAM 帧 (已实现)
- ✅ **RFC 9221**: DATAGRAM 扩展支持
- ✅ `max_datagram_frame_size` Transport Parameter 协商
- ✅ 发送和接收 DATAGRAM 帧 (0x30/0x31)
- ✅ 异步接收 API (`recv_datagram()`, `recv_datagram_nowait()`)

**用途**: WebRTC、实时游戏等低延迟场景

**用法**:
```python
# 创建连接时启用 DATAGRAM
client = QuicConnection("example.com", 443, enable_datagram=True)

# 检查是否可用
if client.datagram_available:
    # 发送数据报
    client.send_datagram(b"Hello!")
    
    # 异步接收数据报
    data = await client.recv_datagram(timeout=5.0)
```

#### ⚪ WebTransport
- ❌ **WebTransport over HTTP/3**: 双向流传输

**当前状态**: EXTENDED_CONNECT 设置已改为 0（嵌入式设备不需要）

---

## 🚀 快速开始

### 安装依赖

```bash
pip install -r requirements.txt
```

### 基本使用

```bash
# 单个请求
python main.py api.tenclass.net

# 指定路径和端口
python main.py cloudflare-quic.com -p 443 --path /

# 并发请求
python main.py -c api.tenclass.net --paths /health /api/status

# 0-RTT 模式（首次连接保存会话）
python main.py api.tenclass.net -s session.json

# 使用保存的会话（0-RTT）
python main.py api.tenclass.net -s session.json
```

### 代码示例

```python
import asyncio
from client import QuicConnection

async def main():
    client = QuicConnection("api.example.com", 443, debug=True)
    await client.connect()
    
    # 发送 GET 请求
    response = await client.request("GET", "/api/data")
    print(f"Status: {response['status']}")
    print(f"Body: {response['body']}")
    
    # 优雅关闭连接
    await client.graceful_shutdown()

asyncio.run(main())
```

---

## 📁 项目结构

```
http3-client/
├── client/              # QUIC 客户端核心实现（组件化架构）
│   ├── connection.py    # 主协调器：连接管理、数据包处理、UDP 协议封装
│   ├── crypto_manager.py # 密钥派生、加密/解密、Key Update
│   ├── flow_controller.py # 流控：MAX_DATA、MAX_STREAM_DATA
│   ├── ack_manager.py   # ACK 帧生成和跟踪
│   ├── frame_processor.py # 帧解析和分发
│   ├── h3_handler.py    # HTTP/3 协议层：QPACK、请求/响应处理
│   └── loss_detection.py # 丢包检测、PTO、拥塞控制
├── quic/                # QUIC 协议实现
│   ├── crypto/          # 加密相关
│   ├── frames/          # 帧构建和解析
│   └── packets/         # 数据包构建和解析
├── h3/                  # HTTP/3 协议实现
│   ├── frames.py        # HTTP/3 帧处理
│   ├── qpack.py         # QPACK 头部压缩
│   └── streams.py       # 流管理
├── tls/                 # TLS 1.3 实现
│   ├── handshake.py     # TLS 握手
│   └── session.py       # 会话管理
├── utils/               # 工具函数
│   └── keylog.py        # Wireshark 密钥日志
└── main.py              # 主入口
```

---

## ⚠️ 注意事项

### 嵌入式设备限制

1. **EXTENDED_CONNECT**: 已设置为 0，不支持 WebTransport
2. **带宽限制**: 针对 2Mbps 环境优化
3. **内存占用**: 动态表容量限制为 4096 字节
4. **并发流**: 默认限制较低，适合简单 API 请求
5. **Server Push**: MAX_PUSH_ID 设置为 0，明确禁用服务器推送（实际应用中已很少使用）

### 已知限制

1. **连接迁移**: 已支持 PATH_CHALLENGE/PATH_RESPONSE 路径验证，但网络切换时可能需要手动重建 socket
2. **无 Server Push**: MAX_PUSH_ID 设置为 0，不支持服务器推送（符合实际应用趋势）
3. **QPACK 编码**: 只使用静态表，压缩率有限
4. **拥塞控制算法**: 使用基础的 NewReno 算法，未实现 Cubic/BBR 等高级算法

### 调试功能

- 启用 `debug=True` 查看详细日志
- 使用 `-k` 参数生成密钥日志文件，可在 Wireshark 中解密流量
- 支持 SSLKEYLOGFILE 环境变量

### 性能建议

- 对于嵌入式设备，建议：
  - 使用 0-RTT 会话恢复减少握手时间
  - 限制并发流数量
  - 适当调整流控窗口大小
  - 监控 RTT 和丢包率

---

## 📚 参考标准

- [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html): QUIC: A UDP-Based Multiplexed and Secure Transport
- [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html): Using TLS to Secure QUIC
- [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002.html): QUIC Loss Detection and Congestion Control
- [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114.html): HTTP/3
- [RFC 9204](https://www.rfc-editor.org/rfc/rfc9204.html): QPACK: Header Compression for HTTP/3
- [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html): An Unreliable Datagram Extension to QUIC

---

## 📝 更新日志

### 最新更新
- ✅ 实现 DATAGRAM 扩展（RFC 9221）
  - 添加 `max_datagram_frame_size` Transport Parameter
  - 支持发送 DATAGRAM 帧 (0x30/0x31)
  - 支持接收 DATAGRAM 帧并通过回调处理
  - 添加 `send_datagram()` 方法发送不可靠数据报
  - 添加 `recv_datagram()` 和 `recv_datagram_nowait()` 接收 API
  - 添加 `datagram_available` 和 `max_datagram_size` 属性
  - 通过 `enable_datagram=True` 参数启用
- ✅ 实现 PATH_CHALLENGE 和 PATH_RESPONSE（RFC 9000 Section 19.17-19.18）
  - 支持发送和接收 PATH_CHALLENGE (0x1a) 帧
  - 自动响应服务器发送的 PATH_CHALLENGE，发送 PATH_RESPONSE (0x1b) 帧
  - 实现 `send_path_challenge()` 方法主动发送路径挑战
  - 实现 `validate_path_async()` 方法进行异步路径验证
  - 支持网络切换场景的路径探测和验证
  - 在 `--chat` 测试中添加路径验证测试（10 秒等待期）
- ✅ 实现 GOAWAY（RFC 9114 Section 5.2）
  - 支持发送和接收 GOAWAY 帧
  - 实现 `send_goaway()` 方法发送 GOAWAY 帧
  - 实现 `graceful_shutdown()` 方法进行完整的优雅关闭流程
  - 收到 GOAWAY 后正确处理流 ID 限制
  - 支持等待待处理请求完成后再关闭连接
- ✅ 实现 RETIRE_CONNECTION_ID（RFC 9000 Section 19.16）
  - 支持发送和接收 RETIRE_CONNECTION_ID 帧
  - 根据 NEW_CONNECTION_ID 的 `retire_prior_to` 自动退休旧连接 ID
  - 正确处理对端发起的连接 ID 退休请求
  - 添加测试函数 `test_retire_connection_id()` 和 `--test-retire-cid` 参数
- ✅ 实现 Key Update（RFC 9001 Section 6）
  - 支持主动发起 1-RTT 密钥轮换
  - 支持处理对端发起的密钥更新
  - Key Phase bit 正确设置和检测
  - 过渡期密钥管理，确保数据包正确解密
- ✅ 实现拥塞控制（Slow Start + Congestion Avoidance + AIMD）
- ✅ 实现 Stateless Reset 检测和处理
- ✅ 完善 QPACK 动态表解码
- ✅ 优化流重组逻辑

---

## 📄 许可证

本项目仅供学习和研究使用。

