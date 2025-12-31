package com.network.security.service;

import com.network.security.algorithm.TarjanAlgorithm;
import org.springframework.stereotype.Service;
import java.util.*;

@Service
public class NetworkAnalysisService {
    public TarjanAlgorithm.AnalysisResult analyzeNetwork(TarjanAlgorithm.NetworkGraph graph) {
        TarjanAlgorithm algorithm = new TarjanAlgorithm();
        return algorithm.analyzeNetwork(graph);
    }

    public TarjanAlgorithm.NetworkGraph getSampleNetwork() {
        return TarjanAlgorithm.createSampleNetwork();
    }

    public TarjanAlgorithm.NetworkGraph createCustomNetwork(String networkType) {
        TarjanAlgorithm.NetworkGraph graph = new TarjanAlgorithm.NetworkGraph();

        switch (networkType) {
            case "enterprise":
                graph = TarjanAlgorithm.createSampleNetwork();
                break;

            case "datacenter":
                graph = createDataCenterNetwork();
                break;

            case "campus":
                graph = createCampusNetwork();
                break;

            default:
                graph = TarjanAlgorithm.createSampleNetwork();
        }

        return graph;
    }

    private TarjanAlgorithm.NetworkGraph createDataCenterNetwork() {
        TarjanAlgorithm.NetworkGraph graph = new TarjanAlgorithm.NetworkGraph();

        // 添加数据中心网络节点
        List<TarjanAlgorithm.NetworkNode> nodes = Arrays.asList(
                createNode("CR1", "核心路由器1", "router", "critical", 0, 2),
                createNode("CR2", "核心路由器2", "router", "critical", 0, -2),
                createNode("AR1", "汇聚交换机1", "switch", "high", -2, 1),
                createNode("AR2", "汇聚交换机2", "switch", "high", -2, -1),
                createNode("SW1", "接入交换机1", "switch", "medium", -4, 1.5),
                createNode("SW2", "接入交换机2", "switch", "medium", -4, 0.5),
                createNode("SRV1", "应用服务器", "server", "high", -5, 2),
                createNode("SRV2", "数据库服务器", "database", "critical", -5, 1),
                createNode("STOR1", "存储设备1", "storage", "critical", 2, 1),
                createNode("STOR2", "存储设备2", "storage", "critical", 2, -1)
        );
        graph.setNodes(nodes);

        // 添加边
        List<TarjanAlgorithm.NetworkEdge> edges = Arrays.asList(
                createEdge("CR1", "CR2", "core"),
                createEdge("CR1", "AR1", "core"),
                createEdge("CR1", "AR2", "core"),
                createEdge("AR1", "SW1", "aggregation"),
                createEdge("AR1", "SW2", "aggregation"),
                createEdge("SW1", "SRV1", "server"),
                createEdge("SW1", "SRV2", "critical"),
                createEdge("CR2", "STOR1", "storage"),
                createEdge("CR2", "STOR2", "storage"),
                createEdge("SW1", "SW2", "redundant"),
                createEdge("AR1", "AR2", "redundant")
        );
        graph.setEdges(edges);

        return graph;
    }

    private TarjanAlgorithm.NetworkGraph createCampusNetwork() {
        TarjanAlgorithm.NetworkGraph graph = new TarjanAlgorithm.NetworkGraph();

        // 添加校园网络节点
        List<TarjanAlgorithm.NetworkNode> nodes = Arrays.asList(
                createNode("CORE", "校园核心", "switch", "critical", 0, 0),
                createNode("FW", "校园防火墙", "firewall", "critical", -2, 0),
                createNode("LIB", "图书馆网络", "switch", "medium", -1, 2),
                createNode("SCI", "科研楼网络", "switch", "high", 1, 2),
                createNode("DORM", "宿舍网络", "switch", "low", 0, -2),
                createNode("LIB_PC", "图书馆终端", "workstation", "low", -2, 2.5),
                createNode("LAB_PC", "实验室终端", "workstation", "medium", 2, 2.5),
                createNode("DORM_PC", "宿舍终端", "workstation", "low", 0, -3),
                createNode("EDU_SRV", "教务服务器", "server", "high", 2, 0),
                createNode("INTERNET", "互联网出口", "internet", "high", -3, 0)
        );
        graph.setNodes(nodes);

        // 添加边
        List<TarjanAlgorithm.NetworkEdge> edges = Arrays.asList(
                createEdge("CORE", "FW", "core"),
                createEdge("FW", "INTERNET", "external"),
                createEdge("CORE", "LIB", "campus"),
                createEdge("CORE", "SCI", "campus"),
                createEdge("CORE", "DORM", "campus"),
                createEdge("LIB", "LIB_PC", "access"),
                createEdge("SCI", "LAB_PC", "access"),
                createEdge("DORM", "DORM_PC", "access"),
                createEdge("CORE", "EDU_SRV", "server"),
                createEdge("LIB", "SCI", "campus_backbone")
        );
        graph.setEdges(edges);

        return graph;
    }

    private TarjanAlgorithm.NetworkNode createNode(String id, String name, String type, String riskLevel, double x, double y) {
        TarjanAlgorithm.NetworkNode node = new TarjanAlgorithm.NetworkNode(id, name, type, riskLevel);
        node.setX(x);
        node.setY(y);
        return node;
    }

    private TarjanAlgorithm.NetworkEdge createEdge(String from, String to, String type) {
        TarjanAlgorithm.NetworkEdge edge = new TarjanAlgorithm.NetworkEdge(from, to, type);
        edge.setBidirectional(true);
        return edge;
    }
}
