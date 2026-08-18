package cirt.bd.info.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import cirt.bd.info.entity.CVEEntity;

@Repository
public interface CVERepository extends JpaRepository<CVEEntity, String> {
    Optional<CVEEntity> findTopByOrderByUpdatedAtDesc();
}
