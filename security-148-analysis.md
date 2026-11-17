# STUN 消息对象复用与认证属性切片别名风险分析（task/148）

- 分析对象：`github.com/pion/stun/v5`（当前工作树，分支 `task/148`，HEAD `ae23685`）
- 分析方法：数据流走读 + 基于公开 API 的可运行复现（复现代码位于仓库外的隔离目录 `/srv/fb2/mei8085/tasks/148/repro/`，未改动库代码）
- 结论摘要：**库自身的标准对象复用路径（`Reset`/`Build`/`Decode`/`ReadFrom`/`Start` 发送）不存在跨消息认证材料残留**；但 `Message` 的零拷贝设计使所有 `RawAttribute.Value` 与文本型 Getter 的返回值都别名（alias）内部 `Raw` 缓冲区，**一旦调用方把这些切片保留到消息对象生命周期之外并复用该 `Message`，保留的切片会被后续消息静默改写（真实的调用方状态污染），且把旧 `RawAttribute` 重新 `AddTo` 到新消息会把旧认证材料带上线路**。该行为符合 `Message` 类型文档声明的使用约束，属于"约束被违反时的后果"，而非库内部的隔离失效。

---

## 1. 数据模型：别名从哪里来

### 1.1 核心结构

`Message` 同时持有"线路字节"和"属性视图"两份状态（`message.go:90-98`）：

```go
type Message struct {
    Type          MessageType
    Length        uint32
    TransactionID [TransactionIDSize]byte
    Attributes    Attributes   // []RawAttribute
    Raw           []byte       // 唯一的字节存储
    ...
}
```

`RawAttribute.Value` 是 `[]byte`（`attributes.go:197-201`）。两条构造路径都让 `Value` **不拥有自己的内存**，而是指向 `Raw` 的子切片：

**编码路径 `Message.Add`（`message.go:197-249`）**：在 `m.Raw` 内就地划分 TLV 空间，`value := buf[attributeHeaderSize:]` 是 `m.Raw` 的子切片，入参 `val` 被 `copy` 进该区域后，存入 `m.Attributes` 的 `attr.Value` 指向的仍是 `m.Raw`（`message.go:216-228, 247`）。注释明确写道"Value of attribute is copied to internal buffer"——复制的是**字节**，不是**所有权**。

**解码路径 `Message.Decode`（`message.go:411-500`）**：`attr.Value = b[:aL]`（`message.go:467`），其中 `b` 由 `buf[messageHeaderSize:fullSize]` 切出，而 `buf := m.Raw`（`message.go:413, 441`）。每个解码出的属性值都是 `m.Raw` 的别名。

### 1.2 Getter 把别名直接交给调用方

- `Message.Get(t)` 返回 `RawAttribute.Value` 本身（`attributes.go:242-249`）；`Attributes.Get` 返回的是整个 `RawAttribute` 的拷贝，但其 `Value` 切片头拷贝后仍指向同一底层数组（`attributes.go:18-26`）。
- 文本属性 Getter 直接赋值：`*v = a`（`textattrs.go:126-134`），即 `Username`/`Realm`/`Nonce`/`Software` 变量本身成为 `m.Raw` 的别名。
- `ErrorCodeAttribute.GetFrom`：`c.Reason = value[...]`（`errorcode.go:72`），同样是别名。
- 唯一的例外是 `XORMappedAddress.GetFromAs`：它把字节 XOR 解码进 `a.IP` 自己的数组（`xoraddr.go:108-124`），**不产生别名**。

### 1.3 类型文档已经声明了这个约束

`Message` 的文档注释（`message.go:84-89`）明确：

> Message, its fields, results of m.Get or any attribute a.GetFrom are valid **only until Message.Raw is not modified**.

因此别名本身是**设计内的、有文档的**零拷贝契约；风险发生在调用方违反该契约（把切片保留到下一次修改/复用之后）。本报告后续区分的是：违反契约后哪些是真实状态污染，哪些只是无害的内存复用。

---

## 2. 对象复用的数据流梳理

库内会让同一个 `Message`/缓冲区服务多个消息的入口共有五类：

| 入口 | 对 `Raw` 的处理 | 对 `Attributes` 的处理 | 位置 |
|---|---|---|---|
| `Message.Reset` + `Build` | `Raw = Raw[:0]`，保留底层数组与容量 | `Attributes = Attributes[:0]` | `message.go:174-178`、`helpers.go:39-49` |
| `Message.Encode` | `Raw = Raw[:0]` 后重写 header 与全部属性 | 先取旧切片头、清零、逐个 `Add` 后恢复 | `message.go:362-367, 340-347` |
| `Decode`（含包级 `Decode`、`Write`、`UnmarshalBinary`、`GobDecode`、`CloneTo`） | `append(m.Raw[:0], data...)`：容量够则**原地覆写**，不够则分配新数组 | `m.Attributes = m.Attributes[:0]` 后重建 | `message.go:75-82, 125-140, 411-500, 505-516` |
| `ReadFrom`（Client 读循环） | 直接读入 `Raw[:cap]`，零分配 | 同上，由 `Decode` 重建 | `message.go:382-401`、`client.go:475-498` |
| 发送侧 `Client.Start`/重传 | `t.raw = append(t.raw[:0], msg.Raw...)` **整体拷贝**；重传再 `copy` 进池化 buffer | 不使用 | `client.go:771-812, 721-723` |

关键观察：**每一条复用入口都会把 `Attributes` 截断为长度 0 并重建**，`Raw` 也被截断后整体覆写。也就是说，新消息的线路字节里不会自动包含上一条消息的任何属性——`Attributes` 层面的"逻辑状态"在每次复用点都被干净地重置了。这是判定"库内部无真实污染"的结构性依据。

---

## 3. 真实状态污染（调用方违反别名契约时）

以下五个场景全部由隔离目录中的可运行程序复现，均只使用公开 API。

### 3.1 保留的属性切片被下一条消息静默改写（活别名）

`repro/main.go` 场景 1：用 key A 构建消息并保留 `m.Get(AttrMessageIntegrity)` 的返回切片，然后对**同一个** `m` 调用 `m.Build(...)` 用 key B 重建。实测：

```
MI of msg#1 (key A): d4a7b3be1b2c5d8140f4ada42574335478ccea5b
MI of msg#2 (key B): 4c72b7cac56c33ecc159ad9cab188ad1b05a8b60
retained MI slice now: c56c33ecc159ad9cab188ad1b05a8b604c72b7ca
RETAINED SLICE MUTATED: the old MI handle now reads msg#2 bytes (live alias into m.Raw)
```

指针级检查（`repro/debug`）证实两次 `Decode` 复用同一底层数组（`sameArray=true`）。保留的 20 字节切片在重建后指向新消息的某个偏移，内容由新消息的布局决定（本例新消息更短，旧切片头部 16 字节落在新 MI 上、尾部 4 字节落在后续填充/旧字节区）。**调用方手里的"旧 HMAC"不再是旧 HMAC，也没有任何编译期或运行期提示。**

### 3.2 文本 Getter 变量被污染（含长度陈旧问题）

`repro/main.go` 场景 2：`var u stun.Username; u.GetFrom(m)` 之后复用 `m` 解码另一条数据报。实测 `u` 从 `"alice"` 变为 `"bob\x00\x00"`（`ReadFrom` 路径同样复现，输出 `"bob\x00e"`）。

污染有两种子形态：

1. **内容覆写**：新消息的属性落在同一偏移，旧变量读到新字节——跨会话/跨租户的数据串读（confidentiality/integrity of application state）。
2. **长度陈旧**：切片头的 `len` 不会随新消息更新。新属性更短时，调用方按旧长度读取，会把相邻属性的字节或缓冲区残留字节一起读出（实测末尾出现 `\x00`/`e` 等非本属主字节）。这正是 `Message` 文档警告"valid only until Raw is not modified"的具体后果。

### 3.3 容量增长导致的"陈旧快照"（另一种别名形态）

`repro/verify`：第二条消息很大（500 字节 SOFTWARE），`append(Raw[:0], ...)` 触发扩容、`Raw` 迁移到新底层数组（实测 `backing array moved=true`）。此时旧切片仍指向**旧数组**，内容保持 `"alice"` 不变。它不再跟随新消息变化，但仍是一段脱离当前消息生命周期的陈旧认证相关数据（旧 USERNAME），若被长期持有会延长敏感数据在内存中的驻留时间，且与调用方"这是当前消息属性"的直觉不符。

即别名风险有两种表现，都需要在生命周期规则里覆盖：

- **原地覆写型**（容量足够，最常见）：切片内容被新消息改写；
- **扩容脱离型**：切片成为指向旧数组的陈旧快照。

### 3.4 把旧 `RawAttribute` 重新加回新消息——旧认证材料上线路

这是与题目最直接对应的场景。保留消息 1 的 MI 属性对象，`m.Build(...)` 重建消息 2 后调用 `oldMI.AddTo(m)`（`RawAttribute.AddTo` 只是 `m.Add(a.Type, a.Value)`，`attributes.go:205-209`）。`m.Add` 会把 `a.Value` 的**当前字节**拷贝进新 `Raw`。实测两种子情况：

- **布局相同（偏移未移动）**：`repro/main.go` 场景 3，同事务 ID、同 USERNAME 重建后 `oldMI.Value` 仍指向原 HMAC 字节，新消息线路上的 MI 与消息 1 完全相同（`d4a7b3be...`），用 key A 校验通过。即新消息携带了旧认证材料，且在覆盖内容不变时会被当作合法签名接受。
- **布局移动（偏移变化）**：`repro/verify` 第 3 项，重建时插入 NONCE 使偏移改变，旧切片在 `Build` 期间已被重新解释（实测线路 MI 字段开头变成 ASCII `fresh-nonce` 的字节 `66726573682d6e6f6e6365...`）。此时用 key A 与 key B 校验**都失败**（`ErrIntegrityMismatch`），属于"故障关闭"，不会伪造出合法认证，但线路上仍然泄漏了把内部字段当 HMAC 拼出的混乱字节。

安全含义需要如实区分：HMAC 与被签名内容绑定，攻击者无法凭此把任意消息伪造成合法签名（移动布局时两端都拒绝）；真实风险是（a）应用层把陈旧/错误身份的认证材料附加到新会话，破坏认证上下文隔离；（b）混乱字节上线路造成的信息泄漏与互操作问题。**根因是调用方持有了超过消息生命周期的属性对象，而不是 `Add` 本身——`Add` 的入参拷贝契约（`message.go:194-197`）对正常短期入参是正确的。**

### 3.5 `WriteAttributes` 就地重编码的自覆写（库内可触发的别名 hazard）

`Message.WriteAttributes` 在同一 `Raw` 上先截断再逐个重写（`message.go:340-347`），而待写属性的 `Value` 本身别名 `Raw`。若前面的属性**变大**，它的新 TLV 会覆盖后面尚未重写的属性值。`repro/edge` 实测：USERNAME 从 2 字节增长到 20 字节后 `m.Encode()`，SOFTWARE 从 `"SOFTWARE"` 变成 `"XXXXXXXX"`（被 USERNAME 的新值覆盖），且 `Get` 不报错、静默返回错误数据。

触发条件较窄（需要先手工改写 `m.Attributes[i].Value` 再调用 `Encode/WriteAttributes`；正常的 `Reset`+`Add` 流程不经过这条路径），但它说明别名问题在库内部同样有表现面，建议在 `WriteAttributes` 文档中显式警告"属性值别名 Raw 时不可改变长度"，或在重编码前检测到 `Value` 落在 `Raw` 范围内时先做一次搬移。

---

## 4. 安全无害的内存复用（已验证的隔离点）

以下复用同样复用底层内存，但通过"整体拷贝/完整覆写/键隔离"保证不会把旧认证材料带进新消息或新租户，属于无害复用，不应与第 3 节混为一谈。

### 4.1 发送侧：`Client.Start` 与重传缓冲池

- `Client.Start` 把 `msg.Raw` **整体复制**进池化的 `clientTransaction.raw`（`client.go:789`），此后重传只使用该拷贝（`client.go:722` 再 `copy` 进 `bufferPool` 的缓冲）。消息对象后续被复用不影响已登记事务的线路字节；池化 buffer 每次都被 `copy` 完整覆写（`client.go:721-723`），`putClientTransaction` 还会把 `raw` 截断（`client.go:394-400`）。
- 附带观察（非别名问题）：`bufferPool` 固定 2048 字节、`copy(buff.buf[:cap], transaction.raw)` 静默截断超长消息（`client.go:687-691, 722`），这是长度处理问题，不在本报告主题内，仅记录。

### 4.2 解码侧：入口处的强制拷贝

包级 `Decode`、`Message.Write`、`UnmarshalBinary`、`GobDecode`、`CloneTo` 全部以 `append(dst.Raw[:0], src...)` 复制调用方数据（`message.go:79, 127, 506, 513`）。调用方在调用后修改自己的缓冲不会影响已解码消息；反过来，消息复用覆写的也是自己的副本。`MarshalBinary` 同样主动分配新切片而不是直接返回 `Raw`（`message.go:115-122`），避免把内部缓冲泄漏给接口消费方。

### 4.3 标准 `Reset`/`Build` 循环

`repro/main.go` 场景 5 连续三轮用不同用户名/密钥构建并校验，全部通过，`Raw` 长度随消息正确变化。`Reset` 同时截断 `Raw`、`Length`、`Attributes`（`message.go:174-178`），`Build` 先 `Reset` 再写 header（`helpers.go:39-49`），新消息的线路字节只包含本轮 setter 产生的属性。`repro/verify` 第 4 项进一步验证：消息 1 的 REALM/NONCE 在重建后的线路消息中不存在（`realm present=false nonce present=false`），**不会发生跨消息属性残留**。

### 4.4 HMAC 池与密钥材料的隔离

- `internal/hmac/pool.go` 的池化 HMAC 在键不匹配时重建实例并以 `append(k.key[:0], key...)` 复制新键（`pool.go:31-39`），命中时 `hash.Reset()` 清掉旧消息状态。池内不会把租户 A 的键或哈希状态泄漏给租户 B。
- `MessageIntegrity.AddTo` 不把长期密钥写入 `Raw`：HMAC 输出先落到 `Raw` 尾后临时空间，再**复制进独立分配的 `vBuf`**（注释明确说明是为了防止 `m.Add` 重分配期间丢失，`integrity.go:82-87`），然后才 `m.Add`。密钥本身（`MessageIntegrity` 切片）由调用方持有，从不进入消息缓冲。
- `Add` 的填充字节显式清零，"to prevent data leak from previous data"（`message.go:236-242`）——库对缓冲区残留泄漏已有针对性防御。
- `MessageIntegrity.Check` 临时改写 `Length`/header 后在返回前恢复（`integrity.go:106-126`），不留下跨调用状态（但该临时改写非并发安全，见第 5 节）。

---

## 5. 对象生命周期必须保持的隔离条件

综合上述数据流，安全复用一个 `Message` 需要同时满足以下条件。前三条是对现有文档契约的具体化，后两条是并发与重编码方面的补充。

1. **切片不过界（核心条件）**：任何 `m.Get`/`Attributes.Get`/`GetFrom` 得到的 `[]byte`、`RawAttribute`、`Username`/`Realm`/`Nonce`/`Software`/`ErrorCodeAttribute.Reason`，只允许在当前消息生命周期内、且在下一次修改 `m.Raw`（`Add`/`Build`/`Reset`/`Encode`/`Decode`/`Write`/`ReadFrom`/`UnmarshalBinary` 等）之前使用。需要跨周期保留时必须深拷贝（`append([]byte(nil), v...)`）。注意 `XORMappedAddress.IP` 是例外，它拥有自己的数组。
2. **属性对象不回流**：不要把从上一条消息取得的 `RawAttribute`（尤其 MESSAGE-INTEGRITY / MESSAGE-INTEGRITY-SHA256 / USERNAME / REALM / NONCE / USERHASH）重新 `AddTo` 到复用后的消息。新消息的认证属性必须由当前密钥在当前内容上重新计算（`MessageIntegrity.AddTo` 本身就是为这个用途设计的）。
3. **复用点必须走完整重置入口**：复用对象时使用 `Build`（内含 `Reset`）或 `Decode`/`ReadFrom`（内含 `Attributes[:0]` 重建与 `Raw` 覆写）。不要只清 `Attributes` 而不清 `Raw`，也不要在未 `Reset` 的消息上继续 `Add`——后者会把旧字节留在线路缓冲中。
4. **单 goroutine 独占**：`Add` 文档已声明 "Not goroutine-safe"（`message.go:193`）；`MessageIntegrity.AddTo`/`Check` 会临时改写 `Length` 与 header 长度字段（`integrity.go:75-80, 106-126`），`WriteAttributes` 会清空并重建 `Attributes`。一个 `Message` 在任一时刻只能有一个 goroutine 访问；`Client.readUntilClosed` 的安全依赖于 `Agent.Process` 同步派发、handler 返回后才读下一条（`client.go:475-498`、`agent.go:188-205`），自定义 handler 若把 `Event.Message` 逃逸到异步 goroutine（`agent.go:46-59` 已警告 "Do not reuse outside Handler"），就同时违反了本条与第 1 条。
5. **就地重编码不得改变别名属性的长度**：调用 `Encode`/`WriteAttributes` 前，若 `Attributes` 中的 `Value` 别名当前 `Raw`（解码或本对象 `Add` 产生的都是如此），不得替换成长度不同的切片（见 3.5）；需要改结构时改用 `Reset`+`Add` 重新构建。

---

## 6. 总体判定与建议

### 判定

- **库内部不存在真实的跨消息认证材料污染**：所有复用入口都完整重置 `Attributes` 并覆写 `Raw`，发送侧与序列化边界使用独立拷贝，HMAC 池与密钥材料有正确隔离，标准复用循环实测正确。
- **真实风险集中在调用方对别名切片的生命周期管理**：违反 `Message` 文档契约时，可发生保留切片被静默改写、文本 Getter 跨会话串读（含陈旧长度越界读）、旧认证材料被重新带上线路三类真实状态污染；其安全影响是认证上下文混淆与敏感数据驻留/泄漏，而不是 HMAC 伪造（布局变化时校验两端均失败，故障关闭）。
- **一个库内可触发的别名 hazard**：`WriteAttributes` 对别名属性的自覆写（3.5），建议补文档或加防御。

### 建议（按优先级）

1. 在 `Message` 类型文档与 `Get`/`GetFrom`  godoc 中把现有约束扩展为显式清单：列出所有别名返回点、给出深拷贝范式，并写明 `RawAttribute` 不得跨复用周期回流 `AddTo`。
2. 为 `WriteAttributes`/`Encode` 增加别名长度变化的文档警告；低成本防御是在重编码前检测属性 `Value` 是否位于 `Raw` 范围内，若是则先复制到临时缓冲再重编码。
3. 可考虑新增一个可选的 `CloneAttribute`/`GetCopy(t)` 辅助 API，降低调用方手写深拷贝的出错率。
4. （顺带）评估 `bufferPool` 2048 字节静默截断（`client.go:722`）是否需要改为长度检查并返回错误。

### 复现与验证索引

| 证据 | 路径（仓库外隔离目录） | 对应章节 |
|---|---|---|
| 五个基础场景 | `/srv/fb2/mei8085/tasks/148/repro/main.go` | 3.1、3.2、3.4、4.3 |
| 底层数组指针与 ReadFrom 别名 | `/srv/fb2/mei8085/tasks/148/repro/debug/main.go` | 3.1、3.2、3.3 |
| 扩容脱离、跨密钥 MI、无残留验证 | `/srv/fb2/mei8085/tasks/148/repro/verify/main.go` | 3.3、3.4、4.3 |
| WriteAttributes 自覆写 | `/srv/fb2/mei8085/tasks/148/repro/edge/main.go` | 3.5 |

库代码与测试在整个分析过程中未被修改，`go test ./...` 全部通过。
