# Tarjan Network Security Analysis System

## 项目简介

Tarjan Network Security Analysis System 是一个基于 Tarjan 算法的网络安全分析系统，用于分析网络拓扑结构，识别关键节点、脆弱连接和强连通分量，生成安全评估报告，帮助网络管理员发现网络中的安全隐患并提供优化建议。

## 核心功能

- **网络拓扑分析**：使用 Tarjan 算法分析网络结构，识别强连通分量、关键节点（割点）和脆弱连接（桥）
- **安全评估报告**：生成详细的安全评估报告，包括漏洞分析、安全建议和网络弹性评估
- **攻击路径模拟**：模拟从用户终端到关键服务器的攻击路径，评估网络安全风险
- **多网络类型支持**：支持企业网络、数据中心网络和校园网络的分析
- **可视化展示**：通过 Web 界面直观展示网络拓扑和分析结果
- **RESTful API**：提供 API 接口，方便集成到其他系统

## 技术栈

- **后端**：Java 17, Spring Boot 3.x
- **前端**：HTML, JavaScript, vis.js (网络可视化)
- **构建工具**：Maven
- **开发环境**：JDK 17+

## 项目结构

```
src/
├── main/
│   ├── java/com/network/security/
│   │   ├── algorithm/          # 算法实现
│   │   │   └── TarjanAlgorithm.java  # Tarjan 算法核心实现
│   │   ├── controller/         # 控制器
│   │   │   └── NetworkController.java  # 网络分析控制器
│   │   ├── service/            # 服务层
│   │   │   └── NetworkAnalysisService.java  # 网络分析服务
│   │   └── TarjanNetworkSecurityApplication.java  # 应用主类
│   └── resources/
│       ├── templates/          # 前端模板
│       │   ├── index.html      # 首页
│       │   └── analysis.html   # 分析结果页
│       └── application.properties  # 配置文件
└── test/                       # 测试代码
```

## 安装与运行

### 前置条件

- JDK 17 或更高版本
- Maven 3.6 或更高版本

### 构建项目

```bash
# 克隆项目
git clone https://github.com/yourusername/tarjan-network-security.git
cd tarjan-network-security

# 构建项目
mvn clean package
```

### 运行项目

```bash
# 运行应用
java -jar target/tarjan-network-security-1.0.0.jar

# 或使用 Maven 运行
mvn spring-boot:run
```

应用将在 `http://localhost:8080` 启动。

## 使用指南

### Web 界面使用

1. **访问首页**：打开浏览器，访问 `http://localhost:8080`
2. **查看示例网络**：首页展示了示例网络拓扑
3. **分析网络**：点击 "分析网络" 按钮，查看分析结果
4. **选择网络类型**：在分析页面可以选择不同类型的网络进行分析（企业网络、数据中心网络、校园网络）

### API 接口

#### 获取示例网络

```http
GET /api/network/sample
```

返回示例网络的拓扑结构，格式为 vis.js 兼容的 JSON。

#### 分析网络

```http
POST /api/network/analyze
Content-Type: application/json

{
  "nodes": [
    {
      "id": "FW",
      "name": "防火墙",
      "type": "firewall",
      "riskLevel": "critical",
      "x": 0,
      "y": 0
    },
    // 更多节点...
  ],
  "edges": [
    {
      "from": "FW",
      "to": "CS",
      "type": "core",
      "bidirectional": true
    },
    // 更多边...
  ]
}
```

返回网络分析结果，包括强连通分量、关键节点、脆弱连接和安全评估报告。

#### 获取特定类型网络

```http
GET /api/network/{type}
```

其中 `{type}` 可以是 `enterprise`、`datacenter` 或 `campus`，返回对应类型网络的拓扑结构。

## 算法说明

### Tarjan 算法

Tarjan 算法是一种用于寻找有向图中强连通分量的高效算法，时间复杂度为 O(V+E)，其中 V 是顶点数，E 是边数。本项目使用 Tarjan 算法：

1. **强连通分量检测**：识别网络中相互可达的节点集合
2. **关键节点（割点）检测**：识别删除后会导致网络分区的节点
3. **脆弱连接（桥）检测**：识别删除后会导致网络分区的边

### 安全评估指标

- **网络弹性**：基于关键节点数量计算，评估网络抗攻击能力
- **漏洞分析**：识别单点故障、脆弱链路和高风险设备
- **安全建议**：针对发现的问题提供具体的安全加固建议
- **攻击路径**：模拟潜在的攻击路径，评估网络安全风险

## 示例网络

项目内置了三个示例网络：

1. **企业网络**：包含防火墙、核心交换机、Web 服务器、数据库、用户终端等
2. **数据中心网络**：包含核心路由器、汇聚交换机、接入交换机、服务器和存储设备
3. **校园网络**：包含校园核心、防火墙、图书馆网络、科研楼网络、宿舍网络等

## 安全建议

基于分析结果，系统会生成以下类型的安全建议：

- **关键节点冗余**：对关键节点实施冗余部署，提高网络可靠性
- **脆弱链路加固**：对脆弱链路进行监控和加固，防止单点故障
- **网络弹性提升**：优化网络拓扑结构，提高网络整体弹性
- **网络分段**：基于强连通分量实施网络微分段，限制攻击扩散
- **访问控制**：加强关键节点和脆弱链路的访问控制策略

## 贡献指南

欢迎贡献代码和提出建议！请按照以下步骤：

1. Fork 项目
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开 Pull Request

## 许可证

本项目采用 MIT 许可证。详见 [LICENSE](LICENSE) 文件。

## 联系方式

- 项目地址：[https://github.com/yourusername/tarjan-network-security](https://github.com/yourusername/tarjan-network-security)
- 问题反馈：[GitHub Issues](https://github.com/hlbzl/tarjan-network-security/issues)

---

**注意**：本项目仅用于网络安全分析和教育目的，实际网络安全部署请结合专业安全设备和策略。
