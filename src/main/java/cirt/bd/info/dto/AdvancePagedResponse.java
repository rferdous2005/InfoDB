package cirt.bd.info.dto;

import java.util.List;

import cirt.bd.info.entity.CVEEntity;
import lombok.Getter;
import lombok.Setter;

@Getter 
@Setter 
public class AdvancePagedResponse {
    int pageCount;
    List<CVEEntity> cveList;
}
