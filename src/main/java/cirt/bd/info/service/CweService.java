package cirt.bd.info.service;

import lombok.RequiredArgsConstructor;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestClient;

import cirt.bd.info.dto.CWEDetailsDto;
import cirt.bd.info.entity.CWEEntity;
import cirt.bd.info.entity.CWEObservedEntity;
import cirt.bd.info.repository.CweObservedRepository;
import cirt.bd.info.repository.CweRepository;

@Service
@RequiredArgsConstructor
public class CweService {
    private final RestClient restClient = RestClient.create();

    private final CweRepository cweRepository;
    private final ObjectMapper objectMapper;
    private final CweObservedRepository cweObservedRepository;

    private static final String CWE_LIST_URL = "https://vulnerability.circl.lu/api/cwe/?page=1&per_page=1000";

    private static final String CWE_DETAIL_URL = "https://vulnerability.circl.lu/api/cwe/{cweId}";

    public CWEDetailsDto getCWEDetails(int cweId) {
        CWEEntity cweEntity = cweRepository.findById(cweId)
                .orElseThrow(() ->
                        new RuntimeException("CWE not found: " + cweId));
        List<CWEObservedEntity> examples = cweObservedRepository.findByCweId(cweId);
        return new CWEDetailsDto(cweEntity, examples);
    }
    
    public int importAllCwes() {
        String response = restClient
                .get()
                .uri(CWE_LIST_URL)
                .retrieve()
                .body(String.class);
        if (response == null || response.isBlank()) {
            throw new IllegalStateException(
                    "CWE list API returned an empty response");
        }
        List<Integer> cweIds = extractCweIds(response);
        int imported = 0;
        for (Integer cweId : cweIds) {
            importCwe(cweId);
            imported++;
        }
        return imported;
    }

    public void importCwe(Integer cweId) {

        String detailResponse = restClient
                .get()
                .uri(CWE_DETAIL_URL, cweId)
                .retrieve()
                .body(String.class);

        if (detailResponse == null ||
                detailResponse.isBlank()) {

            throw new IllegalStateException(
                    "Empty response for CWE-" + cweId);
        }
        saveFromJson(detailResponse);
    }

    private List<Integer> extractCweIds(
            String json) {
        try {
            JsonNode root = objectMapper.readTree(json);

            JsonNode data = root.get("data");

            if (data == null || !data.isArray()) {
                throw new IllegalArgumentException(
                        "CWE API response does not contain a data array");
            }

            List<Integer> ids = new ArrayList<>();

            for (JsonNode item : data) {

                JsonNode idNode = item.get("@ID");

                if (idNode == null ||
                        idNode.isNull()) {
                    continue;
                }

                String id = idNode.asString();

                if (id == null ||
                        id.isBlank()) {
                    continue;
                }

                ids.add(
                        Integer.valueOf(id));
            }

            return ids;

        } catch (Exception e) {
            throw new IllegalArgumentException(
                    "Unable to parse CWE list response",
                    e);
        }
    }

    @Transactional
    public CWEEntity saveFromJson(String json) {
        try {
            JsonNode root = objectMapper.readTree(json);

            Integer cweId = integerValue(root, "@ID");

            if (cweId == null) {
                throw new IllegalArgumentException(
                        "CWE response does not contain @ID");
            }

            CWEEntity cwe = cweRepository
                    .findByCweId(cweId)
                    .orElseGet(CWEEntity::new);

            cwe.setCweId(cweId);

            cwe.setName(textValue(root, "@Name"));
            cwe.setAbstraction(textValue(root, "@Abstraction"));
            cwe.setStructureType(textValue(root, "@Structure"));
            cwe.setStatus(textValue(root, "@Status"));
            cwe.setDiagram(textValue(root, "@Diagram"));

            cwe.setDescription(
                    extractText(root.get("Description")));

            cwe.setExtendedDescription(
                    extractText(root.get("Extended_Description")));

            cwe.setLikelihoodOfExploit(
                    textValue(root, "Likelihood_Of_Exploit"));

            cwe.setRelatedWeaknesses(
                    jsonValue(root, "Related_Weaknesses"));

            cwe.setWeaknessOrdinalities(
                    jsonValue(root, "Weakness_Ordinalities"));

            cwe.setApplicablePlatforms(
                    jsonValue(root, "Applicable_Platforms"));

            cwe.setAlternateTerms(
                    jsonValue(root, "Alternate_Terms"));

            cwe.setBackgroundDetails(
                    jsonValue(root, "Background_Details"));

            cwe.setModesOfIntroduction(
                    jsonValue(root, "Modes_Of_Introduction"));

            cwe.setCommonConsequences(
                    jsonValue(root, "Common_Consequences"));

            cwe.setDetectionMethods(
                    jsonValue(root, "Detection_Methods"));

            cwe.setPotentialMitigations(
                    jsonValue(root, "Potential_Mitigations"));

            cwe.setDemonstrativeExamples(
                    jsonValue(root, "Demonstrative_Examples"));

            cwe.setObservedExamples(
                    jsonValue(root, "Observed_Examples"));

            cwe.setFunctionalAreas(
                    jsonValue(root, "Functional_Areas"));

            cwe.setAffectedResources(
                    jsonValue(root, "Affected_Resources"));

            cwe.setTaxonomyMappings(
                    jsonValue(root, "Taxonomy_Mappings"));

            cwe.setRelatedAttackPatterns(
                    jsonValue(root, "Related_Attack_Patterns"));

            cwe.setReferencesData(
                    jsonValue(root, "References"));

            cwe.setMappingNotes(
                    jsonValue(root, "Mapping_Notes"));

            cwe.setNotes(
                    jsonValue(root, "Notes"));

            cwe.setContentHistory(
                    jsonValue(root, "Content_History"));

            // Most important:
            // preserve the entire original MITRE response.
            cwe.setRawJson(
                    objectMapper.writeValueAsString(root));

            CWEEntity cweEntity = cweRepository.save(cwe);
            saveObservedExamples(
                cweEntity.getCweId(),
                root
            );
            return cweEntity;

        } catch (Exception e) {
            throw new IllegalArgumentException(
                    "Unable to parse/save CWE JSON",
                    e);
        }
    }

    private String textValue(JsonNode node, String property) {
        JsonNode value = node.get(property);
        if (value == null || value.isNull()) {
            return null;
        }
        if (value.isValueNode()) {
            return value.asString();
        }

        return extractText(value);
    }

    private Integer integerValue(JsonNode node, String property) {

        JsonNode value = node.get(property);

        if (value == null || value.isNull()) {
            return null;
        }

        if (value.isInt() || value.isLong()) {
            return value.asInt();
        }

        String text = value.asString();

        if (text == null || text.isBlank()) {
            return null;
        }

        return Integer.valueOf(text);
    }

    private String jsonValue(JsonNode root, String property) {

        JsonNode value = root.get(property);

        if (value == null || value.isNull()) {
            return null;
        }

        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Could not serialize property: " + property,
                    e);
        }
    }

    /**
     * Converts MITRE's mixed XHTML/JSON representation
     * into human-readable text.
     *
     * Works with:
     *
     * "some string"
     *
     * { "#text": "some text" }
     *
     * { "xhtml:p": "some text" }
     *
     * { "xhtml:p": ["text1", "text2"] }
     *
     * and arbitrarily nested combinations.
     */
    private String extractText(JsonNode node) {

        if (node == null || node.isNull()) {
            return null;
        }

        if (node.isString() ||
                node.isNumber() ||
                node.isBoolean()) {

            return node.asString();
        }

        StringBuilder result = new StringBuilder();

        collectText(node, result);

        String text = result.toString()
                .replaceAll("\\s+", " ")
                .trim();

        return text.isEmpty() ? null : text;
    }

    private void collectText(
            JsonNode node,
            StringBuilder result) {

        if (node == null || node.isNull()) {
            return;
        }

        if (node.isValueNode()) {
            String value = node.asString();

            if (value != null && !value.isBlank()) {
                if (result.length() > 0) {
                    result.append(' ');
                }

                result.append(value);
            }

            return;
        }

        if (node.isArray()) {
            for (JsonNode child : node) {
                collectText(child, result);
            }

            return;
        }

        if (node.isObject()) {

            // Give #text priority because MITRE's XML-to-JSON
            // conversion frequently stores actual text here.
            JsonNode textNode = node.get("#text");

            if (textNode != null) {
                collectText(textNode, result);
            }

            node.properties().forEach(entry -> {

                String key = entry.getKey();

                // Skip XML-style metadata attributes.
                if (key.startsWith("@")) {
                    return;
                }

                if ("#text".equals(key)) {
                    return;
                }

                // Formatting metadata isn't useful as prose.
                if ("xhtml:br".equals(key)) {
                    return;
                }

                collectText(entry.getValue(), result);
            });
        }
    }

    private void saveObservedExamples(
            Integer cweId,
            JsonNode root) {

        JsonNode observedExamples = root.path("Observed_Examples");

        if (observedExamples.isMissingNode()) {
            return;
        }

        JsonNode observed = observedExamples.get("Observed_Example");

        if (observed == null) {
            return;
        }

        cweObservedRepository.deleteByCweId(cweId);

        for (JsonNode item : (observed)) {

            CWEObservedEntity entity = new CWEObservedEntity();
            entity.setCweId(cweId);
            entity.setReference(
                    textValue(item, "Reference"));
            entity.setDescription(
                    extractText(item.get("Description")));
            entity.setLink(
                    textValue(item, "Link"));

            cweObservedRepository.save(entity);
        }
    }
}
