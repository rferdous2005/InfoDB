package cirt.bd.info.entity;

import java.time.Instant;
import java.time.LocalDateTime;

import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "cve_summary", indexes = {
        @Index(name = "idx_cve_published_at", columnList = "publishedAt"),
        @Index(name = "idx_cve_modified_at", columnList = "modifiedAt"),
        @Index(name = "idx_cve_cwe_id", columnList = "cweId"),
        @Index(name = "idx_cve_severity", columnList = "severity"),
        @Index(name = "idx_created_updated", columnList = "updatedAt, createdAt")
})
public class CVEEntity {
    @Id
    @Column(length = 30)
    private String cveId;

    @Column(length = 30)
    private String state;
    @Column(columnDefinition = "TEXT")
    private String title;
    @Column(columnDefinition = "TEXT")
    private String description;

    private String severity;
    private double cvssScore;
    private String cvssVersion;

    private String cweId;
    @Column(columnDefinition = "TEXT")
    private String vendor;
    @Column(columnDefinition = "TEXT")
    private String product;

    private Instant publishedAt;
    private Instant modifiedAt;

    @CreationTimestamp
    private LocalDateTime createdAt;
    @UpdateTimestamp
    private LocalDateTime updatedAt;
}
