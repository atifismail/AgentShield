package com.agentshield.dlp;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class DlpPageController {

    private static final DateTimeFormatter DAY_LABEL = DateTimeFormatter.ofPattern("MM-dd");

    private final DlpFindingRepository findingRepository;
    private final ClassificationProfileRepository profileRepository;
    private final ObjectMapper objectMapper;

    public DlpPageController(DlpFindingRepository findingRepository, ClassificationProfileRepository profileRepository,
            ObjectMapper objectMapper) {
        this.findingRepository = findingRepository;
        this.profileRepository = profileRepository;
        this.objectMapper = objectMapper;
    }

    @GetMapping("/dlp")
    public String index(Model model) {
        Instant since7d = Instant.now().minusSeconds(7 * 24 * 3600);
        List<DlpFinding> recent = findingRepository
                .findAll(DlpFindingSpecifications.search(null, null, since7d), PageRequest.of(0, 500,
                        Sort.by(Sort.Direction.ASC, "createdAt")))
                .getContent();

        Map<String, Long> byCategory = recent.stream()
                .collect(Collectors.groupingBy(f -> f.getCategory().name(), LinkedHashMap::new, Collectors.counting()));

        model.addAttribute("pageTitle", "DLP Findings");
        model.addAttribute("totalFindings7d", recent.size());
        model.addAttribute("blockedCount7d", recent.stream().filter(f -> f.getActionTaken() == DlpAction.BLOCK).count());
        model.addAttribute("redactedCount7d",
                recent.stream().filter(f -> f.getActionTaken() == DlpAction.REDACT || f.getActionTaken() == DlpAction.TOKENIZE).count());
        model.addAttribute("profileCount", profileRepository.count());
        model.addAttribute("recentFindings", recent.stream()
                .sorted((a, b) -> b.getCreatedAt().compareTo(a.getCreatedAt()))
                .limit(50)
                .toList());
        model.addAttribute("chartSeriesJson", toJson(buildChartSeries(recent, byCategory)));
        return "dlp/index";
    }

    private String toJson(Map<String, Object> value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            return "{}";
        }
    }

    private Map<String, Object> buildChartSeries(List<DlpFinding> findings, Map<String, Long> byCategory) {
        Map<String, Long> byDay = new LinkedHashMap<>();
        for (int i = 6; i >= 0; i--) {
            byDay.put(LocalDate.now(ZoneOffset.UTC).minusDays(i).format(DAY_LABEL), 0L);
        }
        for (DlpFinding finding : findings) {
            String label = finding.getCreatedAt().atZone(ZoneOffset.UTC).toLocalDate().format(DAY_LABEL);
            byDay.computeIfPresent(label, (k, v) -> v + 1);
        }
        return Map.of(
                "labels", List.copyOf(byDay.keySet()),
                "counts", List.copyOf(byDay.values()),
                "categoryLabels", List.copyOf(byCategory.keySet()),
                "categoryCounts", List.copyOf(byCategory.values()));
    }
}
