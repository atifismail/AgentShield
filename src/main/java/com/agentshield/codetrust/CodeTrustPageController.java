package com.agentshield.codetrust;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@Controller
public class CodeTrustPageController {

    private static final DateTimeFormatter DAY_LABEL = DateTimeFormatter.ofPattern("MM-dd");

    private final CodeAssessmentRepository assessmentRepository;
    private final ObjectMapper objectMapper;

    public CodeTrustPageController(CodeAssessmentRepository assessmentRepository, ObjectMapper objectMapper) {
        this.assessmentRepository = assessmentRepository;
        this.objectMapper = objectMapper;
    }

    @GetMapping("/codetrust")
    public String index(Model model) {
        List<CodeAssessment> recent = assessmentRepository.findAllByOrderByCreatedAtDesc();

        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("totalCount", recent.size());
        stats.put("blockedCount", recent.stream().filter(CodeAssessment::isBlocked).count());
        stats.put("passedCount", recent.stream().filter(a -> a.getStatus() == AssessmentStatus.PASSED).count());
        stats.put("pendingRescanCount", recent.stream().filter(CodeAssessment::isRequiresRescan).count());

        model.addAttribute("pageTitle", "Code Trust");
        model.addAttribute("stats", stats);
        model.addAttribute("recentAssessments", recent.stream().limit(50).toList());
        model.addAttribute("chartSeriesJson", toJson(buildChartSeries(recent)));
        return "codetrust/index";
    }

    @GetMapping("/codetrust/{id}")
    public String detail(@PathVariable Long id, Model model) {
        CodeAssessment assessment = assessmentRepository.findById(id)
                .orElseThrow(() -> new com.agentshield.common.ResourceNotFoundException("code assessment " + id + " not found"));
        model.addAttribute("pageTitle", "Code Assessment #" + id);
        model.addAttribute("assessment", assessment);
        return "codetrust/detail";
    }

    private String toJson(Map<String, Object> value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            return "{}";
        }
    }

    private Map<String, Object> buildChartSeries(List<CodeAssessment> assessments) {
        Map<String, long[]> byDay = new LinkedHashMap<>();
        for (int i = 6; i >= 0; i--) {
            byDay.put(LocalDate.now(ZoneOffset.UTC).minusDays(i).format(DAY_LABEL), new long[2]); // passed, blocked
        }
        for (CodeAssessment a : assessments) {
            String label = a.getCreatedAt().atZone(ZoneOffset.UTC).toLocalDate().format(DAY_LABEL);
            long[] bucket = byDay.get(label);
            if (bucket == null) {
                continue;
            }
            if (a.getStatus() == AssessmentStatus.PASSED) {
                bucket[0]++;
            } else if (a.isBlocked()) {
                bucket[1]++;
            }
        }
        return Map.of(
                "labels", List.copyOf(byDay.keySet()),
                "passed", byDay.values().stream().map(b -> b[0]).toList(),
                "blocked", byDay.values().stream().map(b -> b[1]).toList());
    }
}
