package cirt.bd.info.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(
    name = "cwe_observed_example",
    indexes = {
        @Index(
            name = "idx_observed_reference",
            columnList = "reference"
        ),
        @Index(
            name = "idx_cwe",
            columnList = "cweId"
        )
    }
)
@Getter
@Setter
@NoArgsConstructor
public class CWEObservedEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "cwe_id", nullable = false)
    private Integer cweId;

    @Column(length = 100)
    private String reference;

    @Lob
    @Column(columnDefinition = "LONGTEXT")
    private String description;

    @Column(length = 1000)
    private String link;
}
