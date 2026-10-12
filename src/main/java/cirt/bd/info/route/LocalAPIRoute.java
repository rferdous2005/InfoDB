package cirt.bd.info.route;

import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException.InternalServerError;

import cirt.bd.info.dto.circl.CVEDetailsDto;
import cirt.bd.info.dto.circl.CapecDetailsDto;
import cirt.bd.info.entity.CVEEntity;
import cirt.bd.info.entity.CWEEntity;
import cirt.bd.info.entity.CapecEntity;
import cirt.bd.info.service.AdvanceService;
import cirt.bd.info.service.CapecService;
import cirt.bd.info.service.CveService;
import cirt.bd.info.service.CweService;
import cirt.bd.info.dto.AdvancePagedResponse;
import cirt.bd.info.dto.CVEDto;
import cirt.bd.info.dto.CWEDetailsDto;

@RestController
@RequestMapping("/local")
public class LocalAPIRoute {
    @Autowired
    private CapecService capecService;
    @Autowired
    private CveService cveService;
    @Autowired
    private CweService cweService;
    @Autowired 
    private AdvanceService advanceService;

    private static final Logger log = LoggerFactory.getLogger(AdvanceService.class);
    @GetMapping("/cve")
    public ResponseEntity<AdvancePagedResponse > getCVEList(@RequestParam(required = false) String cweId, @RequestParam(required = false) String latest,
                            @RequestParam(required = false) String fromDate, @RequestParam(required = false) String toDate, @RequestParam(defaultValue="1") int page) {
        AdvancePagedResponse filteredCVEList = null;
        if(latest != null && latest.equals("true")) {
            log.warn("Latest page "+ page);
            filteredCVEList = advanceService.showLatest(page);
        } else if(cweId != null && !cweId.isEmpty()) {
            log.warn("CWEwise page "+ page);
            filteredCVEList = advanceService.showCwewise(cweId, page);
        } else if(fromDate != null && !fromDate.isEmpty()) {
            log.warn("Datewise page "+ page);
            filteredCVEList = advanceService.showDatewise(fromDate, toDate, page);
        }
        return ResponseEntity.ok(filteredCVEList);
    }
    @GetMapping("/cve/{cveID}")
    public ResponseEntity<?> getCVE(@PathVariable String cveID) {
        try {
            CVEDetailsDto cveDetailsDto = cveService.getCveFromCircl(cveID);
            return ResponseEntity.ok(cveDetailsDto);
        } catch(HttpClientErrorException error) {
            log.warn("Catch branch 500");
            CVEEntity cveEntity = cveService.getCve(cveID);
            return ResponseEntity.ok(cveEntity);
        }
    }

    @GetMapping("/cwe/{cweID}")
    public CWEDetailsDto getCWE(@PathVariable String cweID) {
        int id = Integer.parseInt(cweID.split("-")[1]);
        CWEDetailsDto cweDetailsDto = cweService.getCWEDetails(id);
        return cweDetailsDto;
    }

    @GetMapping("/capec/{capecID}")
    public ResponseEntity<CapecEntity> getCapec(@PathVariable String capecID) {
        int id = Integer.parseInt(capecID.split("-")[1]);
        Optional<CapecEntity> capecEntity = capecService.getCapecDetails(id);
        if(capecEntity.isPresent()) {
            return ResponseEntity.ok(capecEntity.get());
        } else {
            return null;
        }
    }

    @GetMapping("/cveAll")
    public void getCVEAll() {
        List<CVEEntity> cveEntities = advanceService.getCveEntitiesAll();
        for(int i=0; i < cveEntities.size(); i++){
            System.out.println(i+ " "+ cveEntities.get(i).getCveId());
        }
    }
}
