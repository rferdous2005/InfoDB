package cirt.bd.info.dto.circl;

import java.util.List;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CapecDetailsDto {
    private String id;
    private String name;
    private String abstraction;
    private String status;
    private String description;
    private String extendedDescription;
    private String likelihoodOfAttack;
    private String typicalSeverity;

    private List<String> relatedAttackPatterns;
    private List<String> executionFlow;
    private List<String> prerequisites;
    private List<String> skillsRequired;
    private List<String> resourcesRequired;
    private List<String> consequences;
    private List<String> mitigations;
    private List<String> exampleInstances;
    private List<String> relatedWeaknesses;
    private List<String> references;
}
