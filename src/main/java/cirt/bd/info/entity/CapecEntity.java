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
@Table(name = "capec")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CapecEntity {
    @Id
    @Column(name = "capec_id", nullable = false)
    private Integer capecId;

    @Column(nullable = false, length = 500)
    private String name;

    @Column(length = 50)
    private String abstraction;

    @Column(length = 50)
    private String status;

    @Lob
    @Column(columnDefinition = "LONGTEXT")
    private String description;

    @Lob
    @Column(name = "extended_description", columnDefinition = "LONGTEXT")
    private String extendedDescription;

    @Column(name = "likelihood_of_attack", length = 100)
    private String likelihoodOfAttack;

    @Column(name = "typical_severity", length = 100)
    private String typicalSeverity;

    @Column(name = "related_attack_patterns", columnDefinition = "JSON")
    private String relatedAttackPatterns;

    @Column(name = "execution_flow", columnDefinition = "JSON")
    private String executionFlow;

    @Column(name = "prerequisites", columnDefinition = "JSON")
    private String prerequisites;

    @Column(name = "skills_required", columnDefinition = "JSON")
    private String skillsRequired;

    @Column(name = "resources_required", columnDefinition = "JSON")
    private String resourcesRequired;

    @Column(name = "indicators", columnDefinition = "JSON")
    private String indicators;

    @Column(name = "consequences", columnDefinition = "JSON")
    private String consequences;

    @Column(name = "mitigations", columnDefinition = "JSON")
    private String mitigations;

    @Column(name = "example_instances", columnDefinition = "JSON")
    private String exampleInstances;

    @Column(name = "related_weaknesses", columnDefinition = "JSON")
    private String relatedWeaknesses;

    @Column(name = "taxonomy_mappings", columnDefinition = "JSON")
    private String taxonomyMappings;

    @Column(name = "references_data", columnDefinition = "JSON")
    private String referencesData;

    @Column(name = "content_history", columnDefinition = "JSON")
    private String contentHistory;

    @Column(name = "raw_json", nullable = false, columnDefinition = "JSON")
    private String rawJson;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @PrePersist
    public void prePersist() {
        LocalDateTime now = LocalDateTime.now();
        createdAt = now;
        updatedAt = now;
    }

    @PreUpdate
    public void preUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
