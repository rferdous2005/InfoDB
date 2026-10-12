package cirt.bd.info.repository;

import java.time.Instant;
import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import cirt.bd.info.entity.CVEEntity;

@Repository
public interface CVERepository extends JpaRepository<CVEEntity, String> {
    Optional<CVEEntity> findTopByOrderByPublishedAtDesc();

    Page<CVEEntity> findAllByOrderByPublishedAtDesc(Pageable pageable);

    Page<CVEEntity> findByCweIdOrderByPublishedAtDesc(String cweId, Pageable pageable);

    Page<CVEEntity> findByPublishedAtGreaterThanEqualAndPublishedAtLessThanOrderByPublishedAtDesc(Instant start, Instant end, Pageable pageable);
}
