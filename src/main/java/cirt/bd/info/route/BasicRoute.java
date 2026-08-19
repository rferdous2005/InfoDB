package cirt.bd.info.route;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import cirt.bd.info.dto.CVEDto;
import cirt.bd.info.entity.CVEEntity;
import cirt.bd.info.repository.CVERepository;
import cirt.bd.info.service.CVESyncService;
import cirt.bd.info.service.CirclCveService;
import jakarta.transaction.Transactional;

@RestController
public class BasicRoute {
    private static final Logger log = LoggerFactory.getLogger(BasicRoute.class);
    private final int PAGE_SIZE = 100;
    private final CVERepository cveRepository;
    private final CirclCveService circlCveService;

    public BasicRoute(
            CVERepository cveRepository,
            CirclCveService circlCveService) {
        this.cveRepository = cveRepository;
        this.circlCveService = circlCveService;
    }
    @GetMapping("/init")
    public void fetchHistoricalCVEs() throws InterruptedException {
        // Instant newestTime = cveRepository.findTopByOrderByUpdatedAtDesc()
        //                         .map(CVEEntity::getModifiedAt)
        //                         .orElse(Instant.EPOCH);
        Instant cutoff = Instant.now().minus(1500, ChronoUnit.DAYS);
        int page = 41;
        boolean finished = false;
        while(!finished) {
            List<CVEDto> response = circlCveService.getCvesOnetime(page, PAGE_SIZE);
            // log.info("DTO size: "+ response.size());
            if(response == null || response.isEmpty()) break;
            List<CVEEntity> cveEntities = new ArrayList<>();
            for(CVEDto cveDto: response) {
                Instant updated = parseInstant(cveDto.getPublishedAt());
                log.info(cutoff+ "  " + updated);
                if(updated.isBefore(cutoff)) {
                    finished = true;
                    break;
                }
                cveEntities.add(toCveEntity(cveDto));
            }
            // log.info("Entity size: "+ cveEntities.size());
            if(!cveEntities.isEmpty()) {
                saveCveBatch(cveEntities);
                log.info("Saved Page "+page+": "+cveEntities.size()+" CVEs");
            }
            if(finished) {
                break;
            }
            page++;
        }
        log.info("CVE Sync finished at page "+ page);
    }

    @Transactional
    @Async
    public void saveCveBatch(List<CVEEntity> cveEntities) {
        try {
            cveRepository.saveAll(cveEntities);
            cveRepository.flush();
        } catch (Exception e) {
            // TODO: handle exception
        }
    }

    private Instant parseInstant(String value) {
        if(value == null || value.isBlank()) return Instant.now();
        try{
            return Instant.parse(value);
        } catch(DateTimeParseException e) {
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
