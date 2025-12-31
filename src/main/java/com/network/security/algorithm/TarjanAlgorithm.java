package com.network.security.algorithm;

import lombok.Data;
import java.util.*;

@Data
public class TarjanAlgorithm {
    private int time = 0;
    private Map<String, Integer> disc = new HashMap<>();
    private Map<String, Integer> low = new HashMap<>();
    private Stack<String> stack = new Stack<>();
    private Set<String> inStack = new HashSet<>();
    private List<List<String>> sccs = new ArrayList<>();
    private Set<String> criticalNodes = new HashSet<>();
    private List<NetworkEdge> bridges = new ArrayList<>();
    private List<String> executionSteps = new ArrayList<>();

    // 网络拓扑
    private NetworkGraph network;

    @Data
    public static class NetworkNode {
        private String id;
        private String name;
        private String type; // firewall, switch, server, workstation, etc.
        private String riskLevel; // critical, high, medium, low
        private double x;
        private double y;
        private Map<String, String> attributes = new HashMap<>();

        public NetworkNode() {}

        public NetworkNode(String id, String name, String type, String riskLevel) {
            this.id = id;
            this.name = name;
            this.type = type;
            this.riskLevel = riskLevel;
        }
    }

    @Data
    public static class NetworkEdge {
        private String from;
        private String to;
        private String type; // core, user, server, vulnerable, etc.
        private int weight = 1;
        private boolean bidirectional = true;

        public NetworkEdge() {}

        public NetworkEdge(String from, String to, String type) {
            this.from = from;
            this.to = to;
            this.type = type;
        }
    }

    @Data
    public static class NetworkGraph {
        private List<NetworkNode> nodes = new ArrayList<>();
        private List<NetworkEdge> edges = new ArrayList<>();
        private Map<String, List<String>> adjacencyList = new HashMap<>();

        public NetworkGraph() {}

        public void buildAdjacencyList() {
            adjacencyList.clear();
            for (NetworkNode node : nodes) {
                adjacencyList.put(node.getId(), new ArrayList<>());
            }

            for (NetworkEdge edge : edges) {
                if (!adjacencyList.containsKey(edge.getFrom())) {
                    adjacencyList.put(edge.getFrom(), new ArrayList<>());
                }
                adjacencyList.get(edge.getFrom()).add(edge.getTo());

                if (edge.isBidirectional()) {
                    if (!adjacencyList.containsKey(edge.getTo())) {
                        adjacencyList.put(edge.getTo(), new ArrayList<>());
                    }
                    adjacencyList.get(edge.getTo()).add(edge.getFrom());
                }
            }
        }

        public NetworkNode getNodeById(String id) {
            return nodes.stream()
                    .filter(node -> node.getId().equals(id))
                    .findFirst()
                    .orElse(null);
        }

        public NetworkEdge getEdge(String from, String to) {
            return edges.stream()
                    .filter(edge -> (edge.getFrom().equals(from) && edge.getTo().equals(to)) ||
                            (edge.isBidirectional() && edge.getFrom().equals(to) && edge.getTo().equals(from)))
                    .findFirst()
                    .orElse(null);
        }
    }

    public AnalysisResult analyzeNetwork(NetworkGraph graph) {
        this.network = graph;
        reset();
        network.buildAdjacencyList();

        // 执行Tarjan算法
        for (NetworkNode node : network.getNodes()) {
            if (!disc.containsKey(node.getId())) {
                tarjan(node.getId(), null);
            }
        }

        // 生成分析报告
        return generateReport();
    }

    private void tarjan(String u, String parent) {
        disc.put(u, time);
        low.put(u, time);
        time++;
        stack.push(u);
        inStack.add(u);

        executionSteps.add("发现节点: " + u + " (发现时间: " + disc.get(u) + ")");

        int children = 0;

        List<String> neighbors = network.getAdjacencyList().getOrDefault(u, new ArrayList<>());
        for (String v : neighbors) {
            if (!disc.containsKey(v)) {
                children++;
                tarjan(v, u);
                low.put(u, Math.min(low.get(u), low.get(v)));

                // 检测关键节点（割点）
                if (parent == null && children > 1) {
                    criticalNodes.add(u);
                    executionSteps.add("发现关键节点(根节点): " + u);
                } else if (parent != null && low.get(v) >= disc.get(u)) {
                    criticalNodes.add(u);
                    executionSteps.add("发现关键节点: " + u);
                }

                // 检测脆弱连接（桥）
                if (low.get(v) > disc.get(u)) {
                    NetworkEdge bridge = network.getEdge(u, v);
                    if (bridge != null) {
                        bridges.add(bridge);
                        executionSteps.add("发现脆弱连接: " + u + " - " + v);
                    }
                }
            } else if (inStack.contains(v)) {
                low.put(u, Math.min(low.get(u), disc.get(v)));
                executionSteps.add("发现后向边: " + u + " -> " + v);
            }
        }

        // 如果u是SCC的根节点
        if (low.get(u).equals(disc.get(u))) {
            List<String> scc = new ArrayList<>();
            while (true) {
                String v = stack.pop();
                inStack.remove(v);
                scc.add(v);
                if (v.equals(u)) {
                    break;
                }
            }
            if (scc.size() > 1) {
                sccs.add(scc);
                executionSteps.add("发现强连通分量: " + scc);
            }
        }
    }

    private void reset() {
        time = 0;
        disc.clear();
        low.clear();
        stack.clear();
        inStack.clear();
        sccs.clear();
        criticalNodes.clear();
        bridges.clear();
        executionSteps.clear();
    }

    @Data
    public static class AnalysisResult {
        private List<List<String>> strongConnectedComponents;
        private Set<String> criticalNodes;
        private List<NetworkEdge> bridges;
        private List<String> executionSteps;
        private SecurityReport securityReport;

        public AnalysisResult() {
            this.securityReport = new SecurityReport();
        }
    }

    @Data
    public static class SecurityReport {
        private int totalNodes;
        private int totalEdges;
        private int criticalNodesCount;
        private int bridgesCount;
        private int sccCount;
        private double networkResilience;
        private List<Vulnerability> vulnerabilities = new ArrayList<>();
        private List<Recommendation> recommendations = new ArrayList<>();
        private List<AttackPath> attackPaths = new ArrayList<>();

        @Data
        public static class Vulnerability {
            private String type;
            private String description;
            private String severity; // CRITICAL, HIGH, MEDIUM, LOW
            private List<String> affectedComponents;
        }

        @Data
        public static class Recommendation {
            private String action;
            private String priority; // HIGH, MEDIUM, LOW
            private String description;
        }

        @Data
        public static class AttackPath {
            private String source;
            private String target;
            private List<List<String>> paths;
            private String riskLevel;
            private List<String> criticalNodesOnPath;
        }
    }

    private AnalysisResult generateReport() {
        AnalysisResult result = new AnalysisResult();
        result.setStrongConnectedComponents(sccs);
        result.setCriticalNodes(criticalNodes);
        result.setBridges(bridges);
        result.setExecutionSteps(executionSteps);

        SecurityReport report = result.getSecurityReport();
        report.setTotalNodes(network.getNodes().size());
        report.setTotalEdges(network.getEdges().size());
        report.setCriticalNodesCount(criticalNodes.size());
        report.setBridgesCount(bridges.size());
        report.setSccCount(sccs.size());

        // 计算网络弹性
        double resilience = 1.0 - ((double) criticalNodes.size() / network.getNodes().size());
        report.setNetworkResilience(Math.max(0, Math.min(1, resilience)) * 100);

        // 生成漏洞报告
        generateVulnerabilities(report);

        // 生成建议
        generateRecommendations(report);

        // 模拟攻击路径
        simulateAttackPaths(report);

        return result;
    }

    private void generateVulnerabilities(SecurityReport report) {
        // 关键节点漏洞
        for (String nodeId : criticalNodes) {
            NetworkNode node = network.getNodeById(nodeId);
            SecurityReport.Vulnerability vuln = new SecurityReport.Vulnerability();
            vuln.setType("单点故障");
            vuln.setDescription("节点 " + node.getName() + " 是关键节点，失效将导致网络分区");
            vuln.setSeverity(node.getRiskLevel().toUpperCase());
            vuln.setAffectedComponents(Arrays.asList(nodeId));
            report.getVulnerabilities().add(vuln);
        }

        // 脆弱连接漏洞
        for (NetworkEdge bridge : bridges) {
            SecurityReport.Vulnerability vuln = new SecurityReport.Vulnerability();
            vuln.setType("脆弱链路");
            vuln.setDescription("连接 " + bridge.getFrom() + " - " + bridge.getTo() + " 是脆弱连接，断开将影响网络连通性");
            vuln.setSeverity("HIGH");
            vuln.setAffectedComponents(Arrays.asList(bridge.getFrom(), bridge.getTo()));
            report.getVulnerabilities().add(vuln);
        }

        // 高风险设备漏洞
        for (NetworkNode node : network.getNodes()) {
            if ("critical".equals(node.getRiskLevel())) {
                SecurityReport.Vulnerability vuln = new SecurityReport.Vulnerability();
                vuln.setType("高风险设备");
                vuln.setDescription("设备 " + node.getName() + " 风险等级为关键，需要特别保护");
                vuln.setSeverity("CRITICAL");
                vuln.setAffectedComponents(Arrays.asList(node.getId()));
                report.getVulnerabilities().add(vuln);
            }
        }
    }

    private void generateRecommendations(SecurityReport report) {
        if (!criticalNodes.isEmpty()) {
            SecurityReport.Recommendation rec = new SecurityReport.Recommendation();
            rec.setAction("关键节点冗余");
            rec.setPriority("HIGH");
            rec.setDescription("对 " + criticalNodes.size() + " 个关键节点实施冗余部署");
            report.getRecommendations().add(rec);
        }

        if (!bridges.isEmpty()) {
            SecurityReport.Recommendation rec = new SecurityReport.Recommendation();
            rec.setAction("脆弱链路加固");
            rec.setPriority("HIGH");
            rec.setDescription("对 " + bridges.size() + " 条脆弱链路进行监控和加固");
            report.getRecommendations().add(rec);
        }

        if (report.getNetworkResilience() < 60) {
            SecurityReport.Recommendation rec = new SecurityReport.Recommendation();
            rec.setAction("网络弹性提升");
            rec.setPriority("MEDIUM");
            rec.setDescription("网络弹性较低 (" + String.format("%.1f", report.getNetworkResilience()) + "%)，建议优化拓扑结构");
            report.getRecommendations().add(rec);
        }

        // 添加通用建议
        SecurityReport.Recommendation rec1 = new SecurityReport.Recommendation();
        rec1.setAction("网络分段");
        rec1.setPriority("MEDIUM");
        rec1.setDescription("基于强连通分量实施网络微分段");
        report.getRecommendations().add(rec1);

        SecurityReport.Recommendation rec2 = new SecurityReport.Recommendation();
        rec2.setAction("访问控制");
        rec2.setPriority("HIGH");
        rec2.setDescription("加强关键节点和脆弱链路的访问控制策略");
        report.getRecommendations().add(rec2);
    }

    private void simulateAttackPaths(SecurityReport report) {
        // 模拟从用户终端到数据库的攻击路径
        List<NetworkNode> userNodes = network.getNodes().stream()
                .filter(n -> "workstation".equals(n.getType()))
                .limit(2)
                .toList();

        List<NetworkNode> criticalTargets = network.getNodes().stream()
                .filter(n -> "database".equals(n.getType()) || "server".equals(n.getType()))
                .filter(n -> "critical".equals(n.getRiskLevel()) || "high".equals(n.getRiskLevel()))
                .limit(2)
                .toList();

        for (NetworkNode source : userNodes) {
            for (NetworkNode target : criticalTargets) {
                List<List<String>> paths = findPaths(source.getId(), target.getId(), new ArrayList<>(), 3);
                if (!paths.isEmpty()) {
                    SecurityReport.AttackPath attackPath = new SecurityReport.AttackPath();
                    attackPath.setSource(source.getId());
                    attackPath.setTarget(target.getId());
                    attackPath.setPaths(paths);
                    attackPath.setRiskLevel("HIGH");

                    // 获取路径上的关键节点
                    Set<String> criticalOnPath = new HashSet<>();
                    for (List<String> path : paths) {
                        for (String nodeId : path) {
                            if (criticalNodes.contains(nodeId)) {
                                criticalOnPath.add(nodeId);
                            }
                        }
                    }
                    attackPath.setCriticalNodesOnPath(new ArrayList<>(criticalOnPath));

                    report.getAttackPaths().add(attackPath);
                }
            }
        }
    }

    private List<List<String>> findPaths(String current, String target, List<String> visited, int maxDepth) {
        if (current.equals(target)) {
            List<String> newPath = new ArrayList<>(visited);
            newPath.add(current);
            return Arrays.asList(newPath);
        }

        if (visited.size() >= maxDepth) {
            return new ArrayList<>();
        }

        List<String> newVisited = new ArrayList<>(visited);
        newVisited.add(current);

        List<List<String>> allPaths = new ArrayList<>();
        List<String> neighbors = network.getAdjacencyList().getOrDefault(current, new ArrayList<>());

        for (String neighbor : neighbors) {
            if (!newVisited.contains(neighbor)) {
                allPaths.addAll(findPaths(neighbor, target, newVisited, maxDepth));
            }
        }

        return allPaths;
    }

    // 创建示例网络
    public static NetworkGraph createSampleNetwork() {
        NetworkGraph graph = new NetworkGraph();

        // 添加节点
        List<NetworkNode> nodes = Arrays.asList(
                createNode("FW", "防火墙", "firewall", "critical", 0, 0),
                createNode("CS", "核心交换机", "switch", "critical", 0, 1),
                createNode("WEB", "Web服务器", "server", "high", 1, 1),
                createNode("DB", "数据库", "database", "critical", 1, 0),
                createNode("SW1", "接入交换机", "switch", "medium", -1, 1),
                createNode("PC1", "用户终端1", "workstation", "low", -2, 1.5),
                createNode("PC2", "用户终端2", "workstation", "low", -2, 0.5),
                createNode("DMZ", "DMZ交换机", "switch", "high", 1, -1),
                createNode("MAIL", "邮件服务器", "server", "high", 2, -1),
                createNode("INTERNET", "互联网", "internet", "high", 0, -1)
        );
        graph.setNodes(nodes);

        // 添加边
        List<NetworkEdge> edges = Arrays.asList(
                createEdge("FW", "CS", "core"),
                createEdge("CS", "WEB", "server"),
                createEdge("CS", "DB", "critical"),
                createEdge("CS", "SW1", "user"),
                createEdge("SW1", "PC1", "user"),
                createEdge("SW1", "PC2", "user"),
                createEdge("FW", "DMZ", "dmz"),
                createEdge("DMZ", "MAIL", "server"),
                createEdge("FW", "INTERNET", "external"),
                createEdge("PC1", "WEB", "vulnerable"),
                createEdge("INTERNET", "DMZ", "external", false)
        );
        graph.setEdges(edges);

        return graph;
    }

    private static NetworkNode createNode(String id, String name, String type, String riskLevel, double x, double y) {
        NetworkNode node = new NetworkNode(id, name, type, riskLevel);
        node.setX(x);
        node.setY(y);
        return node;
    }

    private static NetworkEdge createEdge(String from, String to, String type) {
        return createEdge(from, to, type, true);
    }

    private static NetworkEdge createEdge(String from, String to, String type, boolean bidirectional) {
        NetworkEdge edge = new NetworkEdge(from, to, type);
        edge.setBidirectional(bidirectional);
        return edge;
    }
}