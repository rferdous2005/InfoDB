package cirt.bd.info.dto.circl;

import java.util.List;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CVEDetailsDto {
    private String cveId;
    private String title;
    private String description;
    private String state;
    private String assigner;
    private String published;
    private String updated;

    private Double cvssScore;
    private String cvssSeverity;
    private String cvssVector;
    private String cvssVersion;

    private String cweId;
    private String cweDescription;

    private String vendor;
    private String product;
    private List<String> affectedVersions;

    private String advisorySource;

    private String exploitation;
    private String automatable;
    private String technicalImpact;

    private List<String> references;
}
