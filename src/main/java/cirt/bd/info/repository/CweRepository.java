package cirt.bd.info.repository;

import cirt.bd.info.entity.CWEEntity;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface CweRepository extends JpaRepository<CWEEntity, Integer> {

    Optional<CWEEntity> findByCweId(Integer cweId);

    boolean existsByCweId(Integer cweId);
}
