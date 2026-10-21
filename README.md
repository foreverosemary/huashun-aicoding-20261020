# Banner 指纹识别系统

使用 Go 标准库实现的被动 Banner 批量识别服务，包含独立 server、client、外置 JSON 规则和 Docker Compose 部署。不会主动连接输入中的 IP，也不会执行 Banner 内容。

## 一键运行

需要 Docker Engine / Docker Desktop 和 Docker Compose v2。

```sh
docker compose up --build
```

server 启动并通过 `/health` 实际 HTTP 探测后，client 自动读取 `samples/banners.json`，向 `http://server:8080/fingerprint` 发送请求，将 20 条结果打印到日志，然后以退出码 0 结束。server 持续运行；client 是一次性批处理任务，正常退出不是故障。

```sh
docker compose logs client
docker compose ps -a
# 更换 samples/banners.json 后重新执行识别
docker compose run --rm client
# 指定 samples 目录中的另一份文件
docker compose run --rm client -server http://server:8080 -input /data/another.json
# 检查服务器健康状态
docker compose exec server /app/server -healthcheck
# 删除本项目容器和网络，保留镜像
docker compose down
```

默认不发布任何宿主机端口。client 通过 Compose 服务名 `server` 访问服务；两个容器只加入一个 `internal: true` 的专用网络，运行期无需外网访问。自定义输入放进 `samples/`，它以只读方式挂载进 client 的 `/data/`。`rules/` 同样只读挂载，修改后执行 `docker compose restart server` 使规则重新加载。无需重新编译应用。

首次构建需拉取 Go 基础镜像。若 Docker Desktop / BuildKit 在中文路径下报告 `x-docker-expose-session-sharedkey ... non-printable ASCII`，将完整项目复制或克隆到英文路径再运行；这是构建工具的路径编码限制。

## 本地开发与接口调用

需要 Go 1.25 或以上，无第三方 Go 依赖，无数据库、无外部服务。

```sh
go test ./...
go vet ./...
go build -o bin/server ./cmd/server
go build -o bin/client ./cmd/client
go run ./cmd/server -addr :8080 -rules rules/fingerprints.json
# 在另一终端运行
go run ./cmd/client -server http://localhost:8080 -input samples/banners.json
```

Windows 编译可将输出文件名改为 `bin/server.exe` 和 `bin/client.exe`。服务也支持 `LISTEN_ADDR`、`RULES_PATH` 环境变量；client 支持 `SERVER_URL`，命令行参数优先。client 的 `-timeout` 默认 `30s`。容器健康检查针对固定的 8080 端口；更改容器监听端口时应同时调整探针。

### `GET /health`

成功返回 HTTP 200 和 `{"status":"ok"}`。只有规则成功加载、编译并开始监听后才可成功探测。

### `POST /fingerprint`

请求直接使用 JSON 数组，不使用额外包裹对象。响应保留输入顺序、IP 和端口。

```sh
curl -H 'Content-Type: application/json' --data-binary @samples/banners.json http://localhost:8080/fingerprint
```

```json
[
  {"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
  {"ip":"1.2.3.7","port":3306,"banner":"J\u0000\u0000\u0000\n8.0.32\u0000"},
  {"ip":"1.2.3.23","port":12345,"banner":"QUIT\r\n"}
]
```

```json
[
  {"ip":"1.2.3.4","port":22,"protocol":"SSH","product":"OpenSSH","version":"8.9p1","os_hint":"Ubuntu","confidence":0.95},
  {"ip":"1.2.3.7","port":3306,"protocol":"MySQL","product":"MySQL","version":"8.0.32","os_hint":"","confidence":0.9},
  {"ip":"1.2.3.23","port":12345,"protocol":"unknown","product":"","version":"","os_hint":"","confidence":0}
]
```

每条结果固定包含 `ip`、`port`、`protocol`、`product`、`version`、`os_hint`、`confidence`。未知 Banner 和空 Banner 正常返回 HTTP 200，`protocol` 为小写 `unknown`，其余识别字段为空、置信度为 0。空数组返回 `[]`。

输入 IP 必须是有效 IPv4/IPv6，port 为 1–65535 的整数。错误 JSON、无效 IP/port、无效 base64、未知请求字段或 `null` 返回 HTTP 400；超过请求/批次/单条 Banner 限制返回 HTTP 413。错误响应格式为 `{"error":"..."}`，记录索引从 0 开始；整批先校验再识别，不返回部分结果。方法错误返回 405，未知路径返回 404。client 在读取失败、请求失败或非 200 响应时向 stderr 输出原因并以非零码退出，不会伪装成成功。

### 二进制 Banner

题目中的 `\x00`、`\xa5` 是展示字节的形式，**不属于合法 JSON 转义**。低位控制字节使用 JSON 的 `\u0000`；任意原始二进制推荐使用标准 base64 的 `banner_base64` 字段，保持字节无损。两个非空字段不能同时提供。

```json
[{"ip":"1.2.3.19","port":9999,"banner_base64":"FgMBAKUBAACh"}]
```

上面对应 `16 03 01 00 a5 01 00 00 a1`，返回 `protocol: "TLS"`，不因 9999 端口而猜测软件。JSON 文本字符串经过 UTF-8 编码后参与识别；对于非 ASCII 字节的精确传输请使用 base64。

## 识别设计与扩展

规则由 `rules/fingerprints.json` 声明，程序启动时验证并编译正则。采用 Go RE2 正则实现，避免回溯型正则造成的指数级计算。引擎启动后只读，可安全并发访问。首次匹配即返回，具体产品规则位于通用协议规则之前，顺序就是优先级。

支持 SSH（OpenSSH / Dropbear）、HTTP（nginx / Apache / Jetty / Microsoft-IIS / Caddy）、MySQL 握手、MariaDB 握手、Redis（INFO、PONG、认证和命令错误）、FTP（ProFTPD / vsFTPd / Pure-FTPd / FileZilla），另有 TLS 记录特征。识别与端口无关；规则可选 `ports` 仅用于限制歧义规则的适用端口，绝不单凭端口识别。

MySQL 同时接受带四字节数据包头的握手和从协议版本字节 `0x0a` 开始的握手；NUL 作为版本字符串终止符。TLS 只能证明数据符合记录头特征，不能仅凭它断言 HTTPS。没有明确软件信息的 HTTP/SSH 仍可返回协议，产品和版本为空。FTP 不将普通 SMTP 的 `220` 欢迎语直接当作 FTP。

新增规则示例（放在 `http-generic` 前）：

```json
{"name":"http-example","pattern":"(?im)^Server:[ \\t]*Example/(?P<version>[0-9.]+)","protocol":"HTTP","product":"Example","confidence":0.9}
```

`version` 命名捕获组提取版本；`product` 命名捕获组可用于产品名动态提取。产品、协议和置信度也可直接配置。`os_rules` 单独声明 Ubuntu / Debian / CentOS / FreeBSD / Windows 提示。规则语法错误、重复名称、非法置信度等会让 server 启动失败，防止带错误配置对外宣告健康。建议每次加规则同时补充回归测试。

`confidence` 是规则证据强弱的工程评分，不是统计概率；`os_hint` 只是 Banner 中的提示。Banner 可伪造，代理可能改写头部，Redis 兼容服务可能返回同样内容，因此无法保证所有服务都能唯一识别。系统不依赖示例 IP，也不查询外部指纹库。

## 部署约束

- 多阶段构建在 Go 镜像中执行测试、编译，最终基于 `scratch`，只包含静态二进制和所需数据；不携带编译器、包管理器或 shell。
- 两个进程均以数值 UID/GID `65532:65532` 运行，只读根文件系统，移除全部 Linux capabilities，禁止提权，设置 CPU、内存和 PID 限额。
- 探针调用 server 自带 HTTP 检查命令，不依赖镜像内 curl/shell；client 依赖 `service_healthy`，不是简单的启动先后顺序。
- HTTP 设置读头、读写、空闲超时与请求头限制；请求体最多 8 MiB，每批最多 10000 条，每条文本 Banner 最多 64 KiB；base64 长度受相应编码上限约束。不会记录原始 Banner。
- SIGTERM/SIGINT 触发最长 10 秒的优雅停止，Compose 给予 15 秒退出时间。配置错误直接退出，server 由 Compose 重启策略管理。

服务定位为专用隔离网络内的批处理组件，未内置认证或 HTTPS，不应直接暴露公网。如果需要外部访问，应通过带认证、TLS 和流量限制的网关接入。client 镜像当前针对内部 HTTP 通信，未携带公共 CA 根证书。

## 验证

```sh
go test ./...
go vet ./...
go test ./internal/fingerprint -run '^$' -fuzz FuzzIdentify -fuzztime 5s
docker compose config --quiet
docker compose up --build -d
docker compose wait client
docker compose logs client
docker compose down
```

测试覆盖题目全部 20 条数据及精确产品/版本/OS 结果、非标准端口、产品通用降级、二进制/base64、Redis INFO、多种 FTP、SMTP 防误识别、损坏规则、无效请求、超限请求以及并发请求。Fuzz 测试检查任意 Banner 不导致引擎崩溃并保持结果范围。

目录：`cmd/server`、`cmd/client` 为独立程序；`internal/fingerprint` 为识别引擎；`internal/api` 为 HTTP 层；`rules` 为配置；`samples` 为合法 JSON 自测输入。构建只需 Go 标准库，无需下载第三方模块。
