package cirt.bd.info.entity;

import java.time.Instant;
import java.time.LocalDateTime;

import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
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
