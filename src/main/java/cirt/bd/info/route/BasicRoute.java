package cirt.bd.info.route;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;


import cirt.bd.info.dto.CVEDto;

import cirt.bd.info.entity.CVEEntity;
import cirt.bd.info.repository.CVERepository;
import cirt.bd.info.service.CVESyncService;
import cirt.bd.info.service.CirclCVEService;
import cirt.bd.info.service.CirclCWEService;
import cirt.bd.info.service.CirclCapecService;
import cirt.bd.info.service.CveService;
import jakarta.transaction.Transactional;

@Controller
@RequestMapping
public class BasicRoute {
    private static final Logger log = LoggerFactory.getLogger(BasicRoute.class);
    private final int PAGE_SIZE = 100;
    private final CVERepository cveRepository;
    private final CveService cveService;

    public BasicRoute(
            CVERepository cveRepository,
            CveService cveService) {
        this.cveRepository = cveRepository;
        this.cveService = cveService;
    }

    
    @GetMapping("/init")
    public void fetchHistoricalCVEs() throws InterruptedException {
        // Instant newestTime = cveRepository.findTopByOrderByUpdatedAtDesc()
        // .map(CVEEntity::getModifiedAt)
        // .orElse(Instant.EPOCH);
        Instant cutoff = Instant.now().minus(1700, ChronoUnit.DAYS);
        int page = 3700;
        boolean finished = false;
        while (!finished) {
            List<CVEDto> response = cveService.getCvesOnetime(page, PAGE_SIZE);
            // log.info("DTO size: "+ response.size());
            if (response == null || response.isEmpty()) {
                page++;
                continue;
            }

            List<CVEEntity> cveEntities = new ArrayList<>();
            for (CVEDto cveDto : response) {
                Instant updated = parseInstant(cveDto.getModifiedAt());
                // log.info(cutoff+ " " + updated);
                cveEntities.add(toCveEntity(cveDto));
            }
            // log.info("Entity size: "+ cveEntities.size());
            if (!cveEntities.isEmpty()) {
                cveService.saveCveBatch(cveEntities);
                log.warn("Saved Page " + page + ": " + cveEntities.size() + " CVEs");
            }
            page++;
        }
        log.info("CVE Sync finished at page " + (page - 1));
    }

    @GetMapping("/cve-circl")
    public String showCVEPage(Model model) {
        return "basic/cve-circl";
    }

    @GetMapping("/cve-local")
    public String showLocalCVEPage(Model model) {
        return "basic/cve-local";
    }

    private Instant parseInstant(String value) {

        if (value == null || value.isBlank()) {
            return Instant.EPOCH;
        }
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException ignored) {
        }

        try {
            return LocalDateTime
                    .parse(value)
                    .toInstant(ZoneOffset.UTC);

        } catch (DateTimeParseException ignored) {
        }
        log.warn(
                "Could not parse CVE timestamp: {}",
                value);
        return Instant.EPOCH;
    }

    private CVEEntity toCveEntity(CVEDto cveDto) {
        CVEEntity cveEntity = new CVEEntity();
        cveEntity.setCveId(cveDto.getCveId());
        cveEntity.setCweId(cveDto.getCweId());
        cveEntity.setTitle(cveDto.getTitle());
        cveEntity.setDescription(cveDto.getDescription());
        cveEntity.setCvssScore(cveDto.getCvssScore());
        cveEntity.setCvssVersion(cveDto.getCvssVersion());
        cveEntity.setSeverity(cveDto.getSeverity());
        cveEntity.setVendor(cveDto.getVendor());
        cveEntity.setProduct(cveDto.getProduct());
        cveEntity.setState(cveDto.getState());
        cveEntity.setPublishedAt(parseInstant(cveDto.getPublishedAt()));
        cveEntity.setModifiedAt(parseInstant(cveDto.getModifiedAt()));
        return cveEntity;
    }
}
