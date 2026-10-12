package cirt.bd.info.dto;

import java.util.List;

import cirt.bd.info.entity.CWEEntity;
import cirt.bd.info.entity.CWEObservedEntity;

public class CWEDetailsDto {
    private CWEEntity cweEntity;

    private List<CWEObservedEntity> observedExamples;

    public CWEDetailsDto(
            CWEEntity cweEntity,
            List<CWEObservedEntity> observedExamples) {

        this.cweEntity = cweEntity;
        this.observedExamples = observedExamples;
    }

    public CWEEntity getCwe() {
        return cweEntity;
    }

    public List<CWEObservedEntity> getObservedExamples() {
        return observedExamples;
    }
}
