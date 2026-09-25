# protocompat — Protobuf 兼容性登记服务

纯后端的 Protobuf 发布登记服务：在发布入口对**二进制线编码（WIRE）**与**JSON 映射**分别给出有依据的兼容性判断。判定完全基于 [protocompile](https://github.com/bufbuild/protocompile) 产出的完整链接描述符（含传递依赖），不扫描源码文本。

## 判定原则：无法证明 ≠ 通过

每条发现（finding）带三档严重度，报告只有全部干净时才判 `COMPATIBLE`：

| 严重度 | 含义 |
|---|---|
| `BREAKING` | 可证明不兼容（如 wire type 改变、JSON 形状改变、保留号被复用） |
| `UNKNOWN` | 无法从描述符证明安全（如 oneof 迁移、未保留就删字段、枚举零值变化）——**绝不笼统标成通过** |
| `INFO` | 可证明安全 / 纯新增 |

报告分别汇总 `wire_status` / `json_status`，整体状态取两者较差者：
`COMPATIBLE` < `REVIEW_REQUIRED`（仅有 UNKNOWN）< `BREAKING`。

## 检查项

- **字段号复用**：同号不同类型/标签 → 按矩阵定级；占用旧版本 `reserved` 的号或名 → `BREAKING`
- **保留字段删除**：删字段未保留号/名 → WIRE `UNKNOWN` + JSON `BREAKING`；保留项被删除但未复用 → `UNKNOWN`（`RESERVATION_REMOVED`）
- **类型变化**：按 wire class（varint 普通/之字、fixed32/64、长度分隔）与 JSON 表示（number / string-int / bool / string / base64 / object / array）分别定级；`string↔bytes`、`message↔bytes` 等"可能安全但无法证明"的一律 `UNKNOWN`
- **枚举默认值**：零值（proto3）/首值（proto2）变化 → `ENUM_ZERO_VALUE_CHANGED`，并对每个引用该枚举的字段路径给出 `ENUM_DEFAULT_IMPACT`；值改名 → JSON `BREAKING`；值换号 → 双维度 `BREAKING`
- **oneof 迁移**：成员进出 oneof → 双维度 `UNKNOWN`（旧数据可能多成员并存，新读者只留最后一个）
- **其他**：singular↔repeated、proto2 required 变化、显式默认值变化、扩展区间收缩、service/method 删除与签名变化

## 样例载荷验证

提交者可随版本携带样例载荷（`payloads`），服务用**新旧两套描述符**分别解析并逐字段比对：

- `encoding: "binary"`：`data` 为 base64；新 schema 解析后落入 unknown 的字段会按旧 schema 解析出字段名
- `encoding: "json"`：`data` 为 JSON 文本；解析错误带 protojson 的行列与字段名
- 分叉定位到消息/字段路径（如 `acme.doc.Doc.page_count`，`dropped_in_new` / `value_changed` / `type_changed`）
- `expect: {old_ok, new_ok}` 可声明预期，预期落空记 `UNKNOWN` 而不是静默通过

## 使用方声明

`DeclareConsumer` 登记消费方依赖的字段路径与编码（`binary`/`json`）。发布时，finding 的路径与声明路径互相包含（消息被删会命中其下所有字段声明）、且方面与编码相交时，该消费方列入报告的 `affected_consumers`。

## 布局

```
cmd/server    服务入口（DATABASE_URL、ADDR 环境变量）
cmd/devdb     内嵌 PostgreSQL + 服务，本地端到端用
cmd/regress   命令行回归案例（内嵌 testdata，内存存储）
internal/compat    判定引擎（报告模型、类型矩阵、比对、载荷验证、消费方匹配）
internal/compile   protocompile 封装：源码+依赖描述符 → 链接文件 ↔ 描述符集
internal/store     存储接口；PostgreSQL（pgx）与内存实现
internal/service   业务逻辑 + ConnectRPC 传输（JSON 编解码）
```

## API（ConnectRPC，application/json）

| 方法 | 说明 |
|---|---|
| `POST /registry.v1.Registry/Publish` | 发布版本并给出判定。`BREAKING` 且未设 `allow_breaking` 时拒绝入库（`published:false`）。**同版本不同内容返回 409，绝不覆盖**；同内容幂等返回 |
| `POST /registry.v1.Registry/Check` | 干跑判定，不落库；`base_version` 可指定基线（默认最新版） |
| `POST /registry.v1.Registry/GetVersion` | 取回某版本存储的报告与元数据 |
| `POST /registry.v1.Registry/DeclareConsumer` | 登记/更新使用方声明 |

`dependencies: [{package, version}]` 可引用已发布包，导入解析自其**存储的描述符**而非源码。

## 运行

```bash
# 回归案例（无需数据库）：嵌套导入、oneof 迁移、同名不同包、
# 版本不可变、保留号复用、枚举默认值、载荷验证、跨包依赖
go run ./cmd/regress [-v]

# 单元测试（类型判定矩阵等）
go test ./...

# 生产：PostgreSQL + 服务（启动时自动建表）
DATABASE_URL=postgres://user:pass@host:5432/registry ADDR=:8080 go run ./cmd/server

# 本地端到端：内嵌 PostgreSQL（无系统数据库时）
go run ./cmd/devdb
```

### 示例

```bash
curl -X POST localhost:8080/registry.v1.Registry/Publish \
  -H 'Content-Type: application/json' -d '{
    "package": "acme/pay", "version": "v1",
    "files": [{"path": "pay/refund.proto", "content": "syntax = \"proto3\"; ..."}]
  }'
```

## 存储 schema

- `packages(name)` — 包
- `versions(package_id, version, content_hash, owned_files, descriptor_set, report)` — 版本；`(package_id, version)` 唯一约束兜底不可变性，描述符集自包含（含 WKT 与依赖快照）
- `consumers(package_id, name, fields, encodings)` — 使用方声明

## 已知边界

- 基线默认取"最新发布版本"，不解析语义化版本号排序
- proto2 扩展（extensions）只做区间收缩检查，不比对扩展字段本身
- 跨包破坏性影响通过"在依赖包上登记使用方声明"表达，不自动级联到依赖方
