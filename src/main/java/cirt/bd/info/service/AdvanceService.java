package cirt.bd.info.service;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import cirt.bd.info.dto.AdvancePagedResponse;
import cirt.bd.info.dto.CVEDto;
import cirt.bd.info.dto.circl.CVEDetailsDto;
import cirt.bd.info.entity.CVEEntity;
import cirt.bd.info.repository.CVERepository;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@Service
public class AdvanceService {
    private final int PAGE_SIZE = 30;
    private static final Logger log = LoggerFactory.getLogger(AdvanceService.class);
    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    private CVERepository cveRepository;
    // public String searchByKeyword(String keyword) {
    // return restTemplate.getForObject(BASE_URL + "search/" + keyword,
    // String.class);
    // }

    public AdvancePagedResponse showLatest(int page) {
        Pageable pageable = PageRequest.of(page - 1, 30);
        Page<CVEEntity> cveListPaged = cveRepository.findAllByOrderByPublishedAtDesc(pageable);
        AdvancePagedResponse advancePagedResponse = new AdvancePagedResponse();
        advancePagedResponse.setPageCount(cveListPaged.getTotalPages());
        advancePagedResponse.setCveList(cveListPaged.getContent());

        return advancePagedResponse;
    }

    public AdvancePagedResponse showCwewise(String cweId, int page) {
        Pageable pageable = PageRequest.of(page - 1, 30);
        if (!cweId.toUpperCase().startsWith("CWE-"))
            cweId = "CWE-" + cweId;
        Page<CVEEntity> cveListPaged = cveRepository.findByCweIdOrderByPublishedAtDesc(cweId, pageable);
        AdvancePagedResponse advancePagedResponse = new AdvancePagedResponse();
        advancePagedResponse.setPageCount(cveListPaged.getTotalPages());
        advancePagedResponse.setCveList(cveListPaged.getContent());

        return advancePagedResponse;
    }

    public AdvancePagedResponse showDatewise(String fromDate, String toDate, int page) {
        Pageable pageable = PageRequest.of(page - 1, 30);
        LocalDate from = LocalDate.parse(fromDate);
        LocalDate to = LocalDate.parse(toDate);

        // Include the entire fromDate and toDate
        Instant fromInstant = from.atStartOfDay(ZoneOffset.UTC).toInstant();

        Instant toInstant = to.plusDays(1).atStartOfDay(ZoneOffset.UTC).toInstant();

        Page<CVEEntity> cveListPaged = cveRepository
                .findByPublishedAtGreaterThanEqualAndPublishedAtLessThanOrderByPublishedAtDesc(fromInstant, toInstant, pageable);
        AdvancePagedResponse advancePagedResponse = new AdvancePagedResponse();

        advancePagedResponse.setPageCount(cveListPaged.getTotalPages());
        advancePagedResponse.setCveList(cveListPaged.getContent());

        return advancePagedResponse;
    }

    public List<CVEEntity> getCveEntitiesAll() {
        return this.cveRepository.findAll();
    }

}
