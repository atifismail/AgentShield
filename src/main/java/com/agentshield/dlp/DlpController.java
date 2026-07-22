package com.agentshield.dlp;

import com.agentshield.dlp.DlpDtos.CreateProfileRequest;
import com.agentshield.dlp.DlpDtos.ProfileResponse;
import com.agentshield.dlp.DlpDtos.RagScanRequest;
import com.agentshield.dlp.DlpDtos.RagScanResponse;
import com.agentshield.risk.DetectorCategory;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * DLP scanning surface: a stateless RAG-chunk scan endpoint for an external ingestion pipeline
 * to call before indexing, plus read access to persisted findings and CRUD for classification
 * profiles. Deliberately does not persist the submitted source text — only the {@link DlpFinding}
 * metadata that {@link DlpScanService} already writes (indicator/category/confidence/location,
 * never the matched substring).
 */
@RestController
@RequestMapping("/api/dlp")
@Tag(name = "DLP", description = "Data-loss-prevention scanning: RAG-chunk classification, findings, and classification profiles.")
public class DlpController {

    private final DlpScanService dlpScanService;
    private final DlpFindingRepository findingRepository;
    private final ClassificationProfileService profileService;

    public DlpController(DlpScanService dlpScanService, DlpFindingRepository findingRepository,
            ClassificationProfileService profileService) {
        this.dlpScanService = dlpScanService;
        this.findingRepository = findingRepository;
        this.profileService = profileService;
    }

    @PostMapping("/rag/scan")
    public RagScanResponse scanRagChunk(@Valid @RequestBody RagScanRequest request) {
        String correlationId = request.sourceName() != null ? request.sourceName() : "rag-" + UUID.randomUUID();
        DlpScanResult result = dlpScanService.scan(request.text(), ContentStage.RAG_CHUNK, correlationId);
        return RagScanResponse.from(result);
    }

    @GetMapping("/findings")
    public Page<DlpFinding> findings(
            @RequestParam(required = false) ContentStage stage,
            @RequestParam(required = false) DetectorCategory category,
            @RequestParam(required = false) Instant since,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        return findingRepository.findAll(DlpFindingSpecifications.search(stage, category, since),
                PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt")));
    }

    @GetMapping("/profiles")
    public List<ProfileResponse> listProfiles() {
        return profileService.listAll().stream().map(ProfileResponse::from).toList();
    }

    @PostMapping("/profiles")
    @ResponseStatus(HttpStatus.CREATED)
    public ProfileResponse createProfile(@Valid @RequestBody CreateProfileRequest request, Authentication authentication) {
        return ProfileResponse.from(profileService.create(request, actorName(authentication)));
    }

    @PostMapping("/profiles/{id}/enable")
    public ProfileResponse enableProfile(@PathVariable Long id, Authentication authentication) {
        return ProfileResponse.from(profileService.setEnabled(id, true, actorName(authentication)));
    }

    @PostMapping("/profiles/{id}/disable")
    public ProfileResponse disableProfile(@PathVariable Long id, Authentication authentication) {
        return ProfileResponse.from(profileService.setEnabled(id, false, actorName(authentication)));
    }

    private String actorName(Authentication authentication) {
        return authentication == null ? "system" : authentication.getName();
    }
}
