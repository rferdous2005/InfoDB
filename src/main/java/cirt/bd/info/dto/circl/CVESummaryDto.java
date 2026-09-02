package cirt.bd.info.dto.circl;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CVESummaryDto {

    private String cveId;
    private String title;
    private String description;
    private String published;
    private String updated;
    private String severity;
    private Double cvssScore;
    private String cvssVersion;
    private String cweId;
    private String vendor;
    private String product;
    private String source;

    public CVESummaryDto() {
    }
}