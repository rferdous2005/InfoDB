package cirt.bd.info.route;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import cirt.bd.info.dto.circl.CapecDetailsDto;
import cirt.bd.info.dto.circl.CVESummaryDto;
import cirt.bd.info.dto.circl.CWEDetailsDto;
import cirt.bd.info.dto.circl.CVEDetailsDto;

@RestController
@RequestMapping("/local")
public class LocalAPIRoute {
    // @GetMapping("/cve")
    // public ResponseEntity<List<CVESummaryDto> > getCVEList(@RequestParam(required = false) String cweId, @RequestParam(required = false) String latest,
    //                         @RequestParam(required = false) String fromDate, @RequestParam(defaultValue="1") int page) {
    //     String CVE_LIST_URL = "https://vulnerability.circl.lu/api/vulnerability/?date_sort=published&sort_order=desc&per_page=40&page=";
    //     int circlPageNo = page;
    //     if(latest != null && latest.equals("true")) {
    //         circlPageNo += 2;
    //         CVE_LIST_URL = CVE_LIST_URL + circlPageNo;
    //     } else if(cweId != null && !cweId.isEmpty()) {
    //         CVE_LIST_URL = CVE_LIST_URL + circlPageNo + "&cwe=" + cweId;
    //     } else if(fromDate != null && !fromDate.isEmpty()) {
    //         CVE_LIST_URL = CVE_LIST_URL + circlPageNo + "&since=" + fromDate;
    //     }
    //     System.out.println(CVE_LIST_URL);
    //     return ResponseEntity.ok(circlCVEService.getLatestCves(CVE_LIST_URL));
    // }
    // @GetMapping("/cve/{cveID}")
    // public ResponseEntity<CVEDetailsDto> getCVE(@PathVariable String cveID) {
    //     return ResponseEntity.ok(circlCVEService.getCve(cveID));
    // }

    // @GetMapping("/cwe/{cweID}")
    // public ResponseEntity<CWEDetailsDto> getCWE(@PathVariable String cweID) {
    //     return ResponseEntity.ok(circlCWEService.getCweDetails(cweID));
    // }

    // @GetMapping("/capec/{capecID}")
    // public ResponseEntity<CapecDetailsDto> getCapec(@PathVariable String capecID) {
    //     return ResponseEntity.ok(circlCapecService.getCapecDetails(capecID));
    // }
}
