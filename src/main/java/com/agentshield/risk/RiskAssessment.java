package com.agentshield.risk;

import com.agentshield.common.RiskLevel;
import java.util.List;

public record RiskAssessment(int score, RiskLevel level, List<String> reasons) {
}
