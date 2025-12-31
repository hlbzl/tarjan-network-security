package com.network.security.controller;

import com.network.security.algorithm.TarjanAlgorithm;
import com.network.security.service.NetworkAnalysisService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import java.util.*;

@Controller
public class NetworkController {
    @Autowired
    private NetworkAnalysisService analysisService;

    @GetMapping("/")
    public String index(Model model) {
        TarjanAlgorithm.NetworkGraph sampleNetwork = analysisService.getSampleNetwork();
        model.addAttribute("network", sampleNetwork);
        return "index";
    }

    @GetMapping("/analyze")
    public String analyzePage(Model model) {
        TarjanAlgorithm.NetworkGraph sampleNetwork = analysisService.getSampleNetwork();
        TarjanAlgorithm.AnalysisResult result = analysisService.analyzeNetwork(sampleNetwork);

        model.addAttribute("network", sampleNetwork);
        model.addAttribute("result", result);
        model.addAttribute("executionSteps", result.getExecutionSteps());

        return "analysis";
    }

    @PostMapping("/analyze/custom")
    public String analyzeCustomNetwork(@RequestParam String networkType, Model model) {
        TarjanAlgorithm.NetworkGraph network = analysisService.createCustomNetwork(networkType);
        TarjanAlgorithm.AnalysisResult result = analysisService.analyzeNetwork(network);

        model.addAttribute("network", network);
        model.addAttribute("result", result);
        model.addAttribute("executionSteps", result.getExecutionSteps());
        model.addAttribute("networkType", networkType);

        return "analysis";
    }

    @GetMapping("/api/network/sample")
    @ResponseBody
    public Map<String, Object> getSampleNetworkApi() {
        TarjanAlgorithm.NetworkGraph network = analysisService.getSampleNetwork();
        return convertToVisFormat(network);
    }

    @PostMapping("/api/network/analyze")
    @ResponseBody
    public Map<String, Object> analyzeNetworkApi(@RequestBody TarjanAlgorithm.NetworkGraph network) {
        TarjanAlgorithm.AnalysisResult result = analysisService.analyzeNetwork(network);

        Map<String, Object> response = new HashMap<>();
        response.put("network", convertToVisFormat(network));
        response.put("result", result);

        return response;
    }

    @GetMapping("/api/network/{type}")
    @ResponseBody
    public Map<String, Object> getNetworkByType(@PathVariable String type) {
        TarjanAlgorithm.NetworkGraph network = analysisService.createCustomNetwork(type);
        return convertToVisFormat(network);
    }

    private Map<String, Object> convertToVisFormat(TarjanAlgorithm.NetworkGraph network) {
        Map<String, Object> result = new HashMap<>();

        // 转换节点为vis.js格式（添加空值检查）
        List<Map<String, Object>> nodes = new ArrayList<>();
        for (TarjanAlgorithm.NetworkNode node : network.getNodes()) {
            if (node == null) {
                System.err.println("警告：发现null节点，已跳过");
                continue; // 跳过null节点
            }

            Map<String, Object> visNode = new HashMap<>();

            // 确保id不为null（关键！）
            String nodeId = node.getId();
            if (nodeId == null || nodeId.trim().isEmpty()) {
                System.err.println("警告：节点ID为空，使用默认ID");
                nodeId = "node_" + System.currentTimeMillis() + "_" + nodes.size();
            }

            visNode.put("id", nodeId);
            visNode.put("label", node.getName() != null ? node.getName() : nodeId);
            visNode.put("type", node.getType() != null ? node.getType() : "unknown");
            visNode.put("riskLevel", node.getRiskLevel() != null ? node.getRiskLevel() : "medium");

            // 确保坐标有值
            visNode.put("x", node.getX());
            visNode.put("y", node.getY());

            // 设置节点颜色（添加默认值）
            Map<String, Object> color = new HashMap<>();
            String risk = node.getRiskLevel();
            if (risk == null) risk = "medium";

            switch (risk.toLowerCase()) {
                case "critical":
                    color.put("background", "#FF6B6B");
                    color.put("border", "#FF0000");
                    break;
                case "high":
                    color.put("background", "#FFD700");
                    color.put("border", "#FF8C00");
                    break;
                case "medium":
                    color.put("background", "#90EE90");
                    color.put("border", "#32CD32");
                    break;
                default:
                    color.put("background", "#87CEEB");
                    color.put("border", "#1E90FF");
            }
            visNode.put("color", color);

            // 设置节点形状
            String type = node.getType();
            if (type == null) type = "unknown";

            switch (type.toLowerCase()) {
                case "firewall":
                    visNode.put("shape", "hexagon");
                    break;
                case "switch":
                case "router":
                    visNode.put("shape", "square");
                    break;
                case "server":
                case "database":
                    visNode.put("shape", "ellipse");
                    break;
                default:
                    visNode.put("shape", "circle");
            }

            nodes.add(visNode);
        }

        // 转换边为vis.js格式（添加空值检查）
        List<Map<String, Object>> edges = new ArrayList<>();
        for (TarjanAlgorithm.NetworkEdge edge : network.getEdges()) {
            if (edge == null) {
                System.err.println("警告：发现null边，已跳过");
                continue;
            }

            String from = edge.getFrom();
            String to = edge.getTo();

            // 确保from和to不为null
            if (from == null || to == null) {
                System.err.println("警告：边的from或to为null，已跳过。from=" + from + ", to=" + to);
                continue;
            }

            Map<String, Object> visEdge = new HashMap<>();
            visEdge.put("from", from);
            visEdge.put("to", to);
            visEdge.put("label", edge.getType() != null ? edge.getType() : "connection");

            // 设置边颜色和样式
            String edgeType = edge.getType();
            if (edgeType == null) edgeType = "normal";

            Map<String, Object> edgeStyle = new HashMap<>();
            switch (edgeType.toLowerCase()) {
                case "critical":
                    edgeStyle.put("color", "#FF0000");
                    edgeStyle.put("width", 3);
                    break;
                case "vulnerable":
                    edgeStyle.put("color", "#FF4500");
                    edgeStyle.put("width", 2);
                    edgeStyle.put("dashes", true);
                    break;
                case "core":
                    edgeStyle.put("color", "#0000FF");
                    edgeStyle.put("width", 3);
                    break;
                default:
                    edgeStyle.put("color", "#808080");
                    edgeStyle.put("width", 1);
            }

            visEdge.put("color", edgeStyle.get("color"));
            visEdge.put("width", edgeStyle.get("width"));
            if (edgeStyle.containsKey("dashes")) {
                visEdge.put("dashes", true);
            }
            if (!edge.isBidirectional()) {
                Map<String, Object> arrows = new HashMap<>();
                arrows.put("to", Map.of("enabled", true));
                visEdge.put("arrows", arrows);
            }

            edges.add(visEdge);
        }

        result.put("nodes", nodes);
        result.put("edges", edges);

        System.out.println("数据转换完成：节点数=" + nodes.size() + ", 边数=" + edges.size());
        return result;
    }
}
