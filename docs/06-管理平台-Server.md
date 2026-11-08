# 第 6 章　管理平台（Server）

## 6.1 服务划分

| 服务 | 端口（建议） | 对外 | 说明 |
|---|---|---|---|
| agent-api | 8443 | Agent | 注册、心跳、配置/规则下发、数据上报 |
| console-api | 8080 | Web/开放 API | 控制台后端 |
| alert-worker | — | 否 | Kafka 消费者 |
| web | 80/443 | 浏览器 | 静态资源（Nginx） |

agent-api 和 console-api 要**分开部署、分开鉴权**：Agent 的入口流量大，而且需要暴露给全网主机；控制台只对办公网开放。

## 6.2 后端分层（Go）

```
server/
├── cmd/{agent-api,console-api,alert-worker}/main.go
├── internal/
│   ├── conf/            # 配置加载
│   ├── server/          # HTTP/gRPC 路由、中间件（鉴权、限流、审计、recover）
│   ├── handler/         # 接口层：参数校验、DTO 转换
│   ├── service/         # 业务逻辑
│   ├── repo/            # 数据访问：mysql、clickhouse、redis、kafka
│   ├── model/           # 实体
│   ├── notify/          # 邮件/企业微信/钉钉/飞书/Webhook/Syslog
│   └── pkg/             # 公共库：签名、加解密、分页、错误码
└── migrations/          # SQL 迁移脚本（golang-migrate）
```

## 6.3 前端功能（页面清单）

| 菜单 | 页面 | 关键功能 |
|---|---|---|
| 总览 | 安全大盘 | 今日告警/阻断数、趋势图、Top 应用/类型/来源 IP、实例在线率、熔断实例数 |
| 应用 | 应用列表 / 详情 | 新建应用（生成 AppKey）、负责人、所属部门、绑定策略；详情页展示实例、告警、组件 |
| 实例 | 实例列表 | 筛选（应用/状态/版本/JDK/主机）、查看 Agent 健康指标、远程开关、卸载（attach 模式） |
| 告警 | 告警列表 / 详情 | 多维筛选；详情含请求信息、检测参数、调用栈、命中算法；研判（误报/确认/已修复）、一键加白、导出 |
| 策略 | 策略模板 | 模式（off/monitor/block）、各检测类型开关与动作、阻断页面、熔断阈值、上报采样；按应用继承覆盖 |
| 白名单 | 白名单 | URL（支持前缀/正则）+ 检测类型 + 可选参数名；生效范围；有效期 |
| 规则 | 规则版本 | 上传/发布规则包、灰度（按应用/比例）、回滚、变更对比 |
| 组件 | 组件资产 | jar 清单、命中漏洞（CVE）、受影响实例（P1） |
| 安装 | Agent 包 | 版本列表、下载、生成安装命令（主机/Docker/K8s） |
| 系统 | 用户/角色/部门、通知渠道、审计日志、系统设置、开放 API Token | |

## 6.4 数据库设计（MySQL，主要表）

```sql
-- 应用
CREATE TABLE app (
  id            BIGINT PRIMARY KEY AUTO_INCREMENT,
  name          VARCHAR(128) NOT NULL,
  env           VARCHAR(32)  NOT NULL DEFAULT 'prod',
  language      VARCHAR(16)  NOT NULL DEFAULT 'java',
  dept_id       BIGINT,
  owner         VARCHAR(64),
  app_key       CHAR(32) NOT NULL UNIQUE,
  app_secret    VARCHAR(128) NOT NULL,        -- 加密存储
  policy_id     BIGINT,
  rule_channel  VARCHAR(32) DEFAULT 'stable', -- stable / gray
  created_at    DATETIME, updated_at DATETIME,
  UNIQUE KEY uk_name_env (name, env)
);

-- Agent 实例
CREATE TABLE agent_instance (
  id             BIGINT PRIMARY KEY AUTO_INCREMENT,
  agent_id       CHAR(36) NOT NULL UNIQUE,    -- Agent 生成的 UUID
  app_id         BIGINT NOT NULL,
  hostname       VARCHAR(255), ip VARCHAR(64), pid INT,
  agent_version  VARCHAR(32), language_version VARCHAR(64),
  server_type    VARCHAR(64), server_version VARCHAR(64),
  os             VARCHAR(64), container_id VARCHAR(128), k8s_pod VARCHAR(255),
  status         TINYINT,      -- 1 在线 2 离线 3 熔断 4 已卸载
  config_version BIGINT, rules_version VARCHAR(32),
  last_heartbeat DATETIME, started_at DATETIME,
  KEY idx_app (app_id), KEY idx_hb (last_heartbeat)
);

-- 策略
CREATE TABLE policy (
  id         BIGINT PRIMARY KEY AUTO_INCREMENT,
  name       VARCHAR(128) NOT NULL,
  content    JSON NOT NULL,      -- 模式、检测开关、阈值、阻断页面、熔断参数等
  version    BIGINT NOT NULL,    -- 每次修改 +1，用于 Agent 比对
  is_default TINYINT DEFAULT 0,
  updated_by VARCHAR(64), updated_at DATETIME
);

-- 白名单
CREATE TABLE whitelist (
  id           BIGINT PRIMARY KEY AUTO_INCREMENT,
  app_id       BIGINT,            -- NULL 表示全局
  url_pattern  VARCHAR(1024) NOT NULL,
  match_type   VARCHAR(16) NOT NULL,   -- exact / prefix / regex
  check_types  VARCHAR(512) NOT NULL,  -- 逗号分隔或 'all'
  param_name   VARCHAR(255),
  expire_at    DATETIME,
  source_alarm VARCHAR(64),            -- 从哪条告警生成
  created_by   VARCHAR(64), created_at DATETIME
);

-- 规则包
CREATE TABLE rule_release (
  id          BIGINT PRIMARY KEY AUTO_INCREMENT,
  version     VARCHAR(32) NOT NULL UNIQUE,
  language    VARCHAR(16) NOT NULL,
  sha256      CHAR(64) NOT NULL,
  signature   VARCHAR(256) NOT NULL,
  storage_uri VARCHAR(512) NOT NULL,   -- 对象存储地址
  channel     VARCHAR(32) NOT NULL,    -- stable / gray
  gray_scope  JSON,
  changelog   TEXT,
  status      TINYINT,                 -- 草稿/灰度/全量/已回滚
  created_by  VARCHAR(64), created_at DATETIME
);

-- 用户、角色、部门、审计、通知渠道、Agent 安装包 等表略
```

### 告警表（ClickHouse）

```sql
CREATE TABLE rasp_alarm (
  event_time    DateTime64(3),
  event_id      String,
  app_id        UInt64,
  app_name      LowCardinality(String),
  agent_id      String,
  hostname      String,
  server_ip     String,
  attack_type   LowCardinality(String),
  algorithm     LowCardinality(String),
  action        LowCardinality(String),     -- log / block
  confidence    UInt8,
  attack_source String,                      -- 攻击来源 IP
  url           String,
  method        LowCardinality(String),
  request_id    String,
  params_json   String,                       -- 检测参数（已脱敏）
  request_json  String,                       -- 请求头/参数/body 片段（已脱敏）
  stack         String,
  reason        String,
  fingerprint   String,                       -- 聚合键：app+type+url+algorithm+sink
  status        LowCardinality(String) DEFAULT 'new'
) ENGINE = MergeTree
PARTITION BY toYYYYMMDD(event_time)
ORDER BY (app_id, event_time)
TTL toDateTime(event_time) + INTERVAL 180 DAY;
```

研判状态需要频繁更新，不适合放在 ClickHouse 中修改，建议单独放到 MySQL 的 `alarm_triage(fingerprint, status, note, operator)` 表，查询时关联。

## 6.5 关键业务逻辑

### 6.5.1 在线状态

- 心跳写 Redis：`SET rasp:hb:{agent_id} {ts} EX 120`，同时批量（每 10s）刷新 MySQL 的 `last_heartbeat`。
- scheduler 每分钟扫描超时实例，标记为离线；离线超过 7 天的自动归档。

### 6.5.2 配置合成

Agent 拿到的最终配置 = 默认策略 ⊕ 应用绑定的策略 ⊕ 应用级覆盖 ⊕ 白名单（应用 + 全局）⊕ 紧急开关。合成结果计算 hash 作为 `config_version`，结果缓存在 Redis，任一来源变更时让缓存失效。

### 6.5.3 告警聚合与降噪

- `fingerprint` 相同的告警在 5 分钟窗口内聚合，通知只发首条和计数。
- 通知按应用负责人路由；支持按等级（block 优先）和静默时段过滤。

### 6.5.4 紧急开关

- 全局/应用级 `kill_switch`，修改后写入 Redis 并递增版本；心跳响应中优先携带。
- 如果启用了推送通道，立即推送；否则在下一次心跳时生效（≤ 30s）。

## 6.6 权限模型

- RBAC：内置 超级管理员 / 安全管理员 / 安全运营 / 只读 / 开发（只能看自己负责的应用）。
- 数据权限：按部门 + 应用负责人隔离。
- 关键操作（切换阻断模式、全局开关、发布规则、加白）需要记录审计日志，可配置二次确认。
- SSO：LDAP、OIDC（对接公司统一认证）。

## 6.7 API 规范

- RESTful，前缀 `/api/v1`，JSON；统一响应 `{ "code": 0, "message": "ok", "data": {...} }`。
- 分页：`page`、`page_size`；列表响应带 `total`。
- 开放 API 使用 `Authorization: Bearer <token>`，Token 绑定角色与有效期。
- 接口文档使用 OpenAPI 3（swaggo 自动生成），文档放在 `server/api/openapi.yaml`。

主要接口示例：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | /api/v1/apps | 应用列表 |
| POST | /api/v1/apps | 新建应用 |
| GET | /api/v1/apps/{id}/instances | 应用实例 |
| PUT | /api/v1/apps/{id}/policy | 绑定/覆盖策略 |
| GET | /api/v1/alarms | 告警查询（时间、应用、类型、动作、IP、URL） |
| GET | /api/v1/alarms/{event_id} | 告警详情 |
| POST | /api/v1/alarms/{fingerprint}/triage | 研判 |
| POST | /api/v1/whitelists | 新建白名单 |
| POST | /api/v1/rules/releases | 上传规则包 |
| POST | /api/v1/rules/releases/{id}/publish | 灰度/全量发布 |
| POST | /api/v1/killswitch | 紧急开关 |

下一章：[通信协议与数据模型](07-通信协议与数据模型.md)
