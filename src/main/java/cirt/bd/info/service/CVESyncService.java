package cirt.bd.info.service;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import cirt.bd.info.dto.CVEDto;
import cirt.bd.info.entity.CVEEntity;
import cirt.bd.info.repository.CVERepository;
import cirt.bd.info.scheduled.CVESyncScheduler;
import jakarta.transaction.Transactional;

@Service
public class CVESyncService {
    private static final Logger log = LoggerFactory.getLogger(CVESyncService.class);
    private final int PAGE_SIZE = 100;
    @Autowired
    private CVERepository cveRepository;
    @Autowired
    private CirclCveService circlCveService;

    @Transactional
    @Async
    public void saveCveBatch(List<CVEEntity> cveEntities, int page) {
        try {
            cveRepository.saveAll(cveEntities);
            cveRepository.flush();
            log.info("Daily Cron Job Saving successful page {}.", page);
        } catch (Exception e) {
            log.error("Daily Cron Job Skipping saving page {} due to database error: {}", page, e.getMessage());
        }
    }

    public void synchronize() {
        Instant newestTime = cveRepository.findTopByOrderByModifiedAtDesc()
                .map(CVEEntity::getModifiedAt)
                .orElse(Instant.EPOCH);
        Instant cutoff = newestTime.minus(5, ChronoUnit.MINUTES);
        int page = 1;
        boolean finished = false;
        while (!finished) {
            List<CVEDto> response = circlCveService.getLatestCves(page, PAGE_SIZE);

            if (response == null || response.isEmpty())
                break;
            List<CVEEntity> cveEntities = new ArrayList<>();
            for (CVEDto cveDto : response) {
                Instant updated = parseInstant(cveDto.getModifiedAt());
                if (!updated.isAfter(cutoff)) {
                    finished = true;
                    break;
                }
                cveEntities.add(toCveEntity(cveDto));
            }
            if (!cveEntities.isEmpty()) {
                this.saveCveBatch(cveEntities, page);
            }
            if (finished || response.size() < PAGE_SIZE) {
                break;
            }
            page++;
        }
        System.out.println("CVE Sync finished at page " + page);
    }

    private Instant parseInstant(String value) {
        if (value == null || value.isBlank())
            return Instant.now();
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException e) {
            return Instant.EPOCH;
        }
    }

    private CVEEntity toCveEntity(CVEDto cveDto) {
        CVEEntity cveEntity = new CVEEntity();
        cveEntity.setCveId(cveDto.getCveId());
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
