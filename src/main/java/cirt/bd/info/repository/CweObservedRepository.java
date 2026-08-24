package cirt.bd.info.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import cirt.bd.info.entity.CWEObservedEntity;

@Repository
public interface CweObservedRepository
        extends JpaRepository<CWEObservedEntity, Long> {

    void deleteByCweId(Integer cweId);

    List<CWEObservedEntity> findByCweId(Integer cweId);

    Optional<CWEObservedEntity> findByReference(String reference);
}
