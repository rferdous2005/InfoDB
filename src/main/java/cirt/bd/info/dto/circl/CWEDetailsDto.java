package cirt.bd.info.dto.circl;

import java.util.List;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CWEDetailsDto {
    private String id;
    private String name;
    private String abstraction;
    private String structure;
    private String status;
    private String diagram;
    private String description;
    private String extendedDescription;
    private String likelihoodOfExploit;

    private List<String> alternateTerms;
    private List<String> platforms;
    private List<String> modesOfIntroduction;
    private List<String> relatedWeaknesses;
    private List<String> consequences;
    private List<String> detectionMethods;
    private List<String> mitigations;
    private List<String> demonstrativeExamples;
    private List<String> observedExamples;
    private List<String> relatedAttackPatterns;
}
