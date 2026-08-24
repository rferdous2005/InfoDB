package cirt.bd.info.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import cirt.bd.info.entity.CapecEntity;

import java.util.Optional;

@Repository
public interface CapecRepository extends JpaRepository<CapecEntity, Integer> {
    Optional<CapecEntity> findByCapecId(Integer capecId);

    boolean existsByCapecId(Integer capecId);
}
