package cirt.bd.info.entity;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "cwe")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CWEEntity {

    @Id
    @Column(name = "cwe_id", nullable = false, unique = true)
    private Integer cweId;

    @Column(nullable = false, length = 500)
    private String name;

    @Column(length = 50)
    private String abstraction;

    @Column(name = "structure_type", length = 50)
    private String structureType;

    @Column(length = 50)
    private String status;

    @Column(length = 1000)
    private String diagram;

    @Lob
    @Column(columnDefinition = "LONGTEXT")
    private String description;

    @Lob
    @Column(name = "extended_description", columnDefinition = "LONGTEXT")
    private String extendedDescription;

    @Column(name = "likelihood_of_exploit", length = 100)
    private String likelihoodOfExploit;

    @Column(name = "related_weaknesses", columnDefinition = "JSON")
    private String relatedWeaknesses;

    @Column(name = "weakness_ordinalities", columnDefinition = "JSON")
    private String weaknessOrdinalities;

    @Column(name = "applicable_platforms", columnDefinition = "JSON")
    private String applicablePlatforms;

    @Column(name = "alternate_terms", columnDefinition = "JSON")
    private String alternateTerms;

    @Column(name = "background_details", columnDefinition = "JSON")
    private String backgroundDetails;

    @Column(name = "modes_of_introduction", columnDefinition = "JSON")
    private String modesOfIntroduction;

    @Column(name = "common_consequences", columnDefinition = "JSON")
    private String commonConsequences;

    @Column(name = "detection_methods", columnDefinition = "JSON")
    private String detectionMethods;

    @Column(name = "potential_mitigations", columnDefinition = "JSON")
    private String potentialMitigations;

    @Column(name = "demonstrative_examples", columnDefinition = "JSON")
    private String demonstrativeExamples;

    @Column(name = "observed_examples", columnDefinition = "JSON")
    private String observedExamples;

    @Column(name = "functional_areas", columnDefinition = "JSON")
    private String functionalAreas;

    @Column(name = "affected_resources", columnDefinition = "JSON")
    private String affectedResources;

    @Column(name = "taxonomy_mappings", columnDefinition = "JSON")
    private String taxonomyMappings;

    @Column(name = "related_attack_patterns", columnDefinition = "JSON")
    private String relatedAttackPatterns;

    @Column(name = "references_data", columnDefinition = "JSON")
    private String referencesData;

    @Column(name = "mapping_notes", columnDefinition = "JSON")
    private String mappingNotes;

    @Column(name = "notes", columnDefinition = "JSON")
    private String notes;

    @Column(name = "content_history", columnDefinition = "JSON")
    private String contentHistory;

    @Column(name = "raw_json", nullable = false, columnDefinition = "JSON")
    private String rawJson;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @PrePersist
    void prePersist() {
        LocalDateTime now = LocalDateTime.now();
        createdAt = now;
        updatedAt = now;
    }

    @PreUpdate
    void preUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
