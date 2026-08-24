package cirt.bd.info.service;

import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestClient;

import cirt.bd.info.entity.CapecEntity;
import cirt.bd.info.repository.CapecRepository;
import cirt.bd.info.repository.CweObservedRepository;
import cirt.bd.info.repository.CweRepository;

@Service
@AllArgsConstructor
public class CapecService {
    private final RestClient restClient = RestClient.create();

    private final CapecRepository capecRepository;
    private final ObjectMapper objectMapper;
    private final CweObservedRepository cweObservedRepository;

    private static final String CAPEC_LIST_URL = "https://vulnerability.circl.lu/api/capec/?per_page=100&page=";

    private static final String CAPEC_DETAIL_URL = "https://vulnerability.circl.lu/api/capec/{capecId}";

    public void importAllCapecs() {
        for (int page = 1; page <= 7; page++) {
            String response = restClient
                    .get()
                    .uri(CAPEC_LIST_URL+page)
                    .retrieve()
                    .body(String.class);
            if (response == null || response.isBlank()) {
                throw new IllegalStateException(
                        "CWE list API returned an empty response");
            }
            List<Integer> capecIds = extractCapecIds(response);
            for (Integer capecId : capecIds) {
                importCapec(capecId);
            }
        }

    }

    private List<Integer> extractCapecIds(
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
                    "Unable to parse CAPEC list response",
                    e);
        }
    }

    public void importCapec(Integer capecId) {
        String detailResponse = restClient
                .get()
                .uri(CAPEC_DETAIL_URL, capecId)
                .retrieve()
                .body(String.class);

        if (detailResponse == null ||
                detailResponse.isBlank()) {

            throw new IllegalStateException(
                    "Empty response for CAPEC-" + capecId);
        }
        saveFromJson(detailResponse);
    }

    @Transactional
    public CapecEntity saveFromJson(String json) {

        try {
            JsonNode root = objectMapper.readTree(json);

            Integer capecId = integerValue(root, "@ID");

            if (capecId == null) {
                throw new IllegalArgumentException(
                        "CAPEC JSON does not contain @ID");
            }

            CapecEntity capec = capecRepository
                    .findByCapecId(capecId)
                    .orElseGet(CapecEntity::new);

            capec.setCapecId(capecId);
            capec.setName(textValue(root, "@Name"));
            capec.setAbstraction(textValue(root, "@Abstraction"));
            capec.setStatus(textValue(root, "@Status"));

            capec.setDescription(
                    extractText(root.get("Description")));

            capec.setExtendedDescription(
                    extractText(root.get("Extended_Description")));

            capec.setLikelihoodOfAttack(
                    textValue(root, "Likelihood_Of_Attack"));

            capec.setTypicalSeverity(
                    textValue(root, "Typical_Severity"));

            capec.setRelatedAttackPatterns(
                    jsonValue(root, "Related_Attack_Patterns"));

            capec.setExecutionFlow(
                    jsonValue(root, "Execution_Flow"));

            capec.setPrerequisites(
                    jsonValue(root, "Prerequisites"));

            capec.setSkillsRequired(
                    jsonValue(root, "Skills_Required"));

            capec.setResourcesRequired(
                    jsonValue(root, "Resources_Required"));

            capec.setIndicators(
                    jsonValue(root, "Indicators"));

            capec.setConsequences(
                    jsonValue(root, "Consequences"));

            capec.setMitigations(
                    jsonValue(root, "Mitigations"));

            capec.setExampleInstances(
                    jsonValue(root, "Example_Instances"));

            capec.setRelatedWeaknesses(
                    jsonValue(root, "Related_Weaknesses"));

            capec.setTaxonomyMappings(
                    jsonValue(root, "Taxonomy_Mappings"));

            capec.setReferencesData(
                    jsonValue(root, "References"));

            capec.setContentHistory(
                    jsonValue(root, "Content_History"));

            // Preserve the complete original CAPEC response
            capec.setRawJson(
                    objectMapper.writeValueAsString(root));

            return capecRepository.save(capec);

        } catch (Exception e) {
            throw new IllegalArgumentException(
                    "Unable to parse/save CAPEC JSON",
                    e);
        }
    }

    private Integer integerValue(
            JsonNode node,
            String property) {

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

    private String textValue(
            JsonNode node,
            String property) {

        JsonNode value = node.get(property);

        if (value == null || value.isNull()) {
            return null;
        }

        if (value.isValueNode()) {
            return value.asString();
        }

        return extractText(value);
    }

    private String jsonValue(
            JsonNode root,
            String property) {

        JsonNode value = root.get(property);

        if (value == null || value.isNull()) {
            return null;
        }

        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Could not serialize CAPEC property: "
                            + property,
                    e);
        }
    }

    private String extractText(JsonNode node) {

        if (node == null || node.isNull()) {
            return null;
        }

        if (node.isValueNode()) {
            return node.asString();
        }
        StringBuilder result = new StringBuilder();
        collectText(node, result);
        String text = result.toString()
                .replaceAll("\\s+", " ")
                .trim();

        return text.isEmpty()
                ? null
                : text;
    }

    private void collectText(
            JsonNode node,
            StringBuilder result) {

        if (node == null || node.isNull()) {
            return;
        }

        if (node.isValueNode()) {

            String value = node.asText();

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

            // MITRE XML-to-JSON frequently puts textual
            // content inside "#text".
            JsonNode textNode = node.get("#text");

            if (textNode != null) {
                collectText(textNode, result);
            }

            for (Map.Entry<String, JsonNode> entry : node.properties()) {

                String key = entry.getKey();

                // XML attributes such as @ID, @Level, etc.
                if (key.startsWith("@")) {
                    continue;
                }

                // Already processed above.
                if ("#text".equals(key)) {
                    continue;
                }

                // Formatting only.
                if ("xhtml:br".equals(key)) {
                    continue;
                }

                collectText(
                        entry.getValue(),
                        result);
            }
        }
    }
}
