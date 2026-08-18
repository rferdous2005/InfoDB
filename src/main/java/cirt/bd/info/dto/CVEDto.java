package cirt.bd.info.dto;

import java.time.Instant;
import java.time.LocalDateTime;

import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import jakarta.persistence.Column;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CVEDto {
    private String cveId;
    private String title;
    private String description, state;

    private String severity;
    private double cvssScore;
    private String cvssVersion;

    private String cweId;
    private String vendor;
    private String product;
    private String source;

    private String publishedAt;
    private String modifiedAt;
}
