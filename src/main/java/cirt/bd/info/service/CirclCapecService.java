package cirt.bd.info.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import cirt.bd.info.dto.circl.CapecDetailsDto;

@Service
public class CirclCapecService {
    private static final String CIRCL_CAPEC_BASE_URL =
            "https://vulnerability.circl.lu/api/capec/";

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public CapecDetailsDto getCapecDetails(String capecId) {
        String normalized = normalizeCapecId(capecId);

        String response = restTemplate.getForObject(
                CIRCL_CAPEC_BASE_URL + normalized,
                String.class
        );

        try {
            JsonNode root = objectMapper.readTree(response);
            return convertToDto(root);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse CAPEC response", e);
        }
    }

    private CapecDetailsDto convertToDto(JsonNode root) {
        CapecDetailsDto dto = new CapecDetailsDto();

        dto.setId("CAPEC-" + root.path("@ID").asText(""));
        dto.setName(clean(root.path("@Name").asText("")));
        dto.setAbstraction(root.path("@Abstraction").asText(""));
        dto.setStatus(root.path("@Status").asText(""));
        dto.setDescription(clean(root.path("Description").asText("")));
        dto.setExtendedDescription(extractText(root.path("Extended_Description")));
        dto.setLikelihoodOfAttack(root.path("Likelihood_Of_Attack").asText(""));
        dto.setTypicalSeverity(root.path("Typical_Severity").asText(""));

        dto.setRelatedAttackPatterns(extractRelatedAttackPatterns(root));
        dto.setExecutionFlow(extractExecutionFlow(root));
        dto.setPrerequisites(extractSimpleList(root.path("Prerequisites").path("Prerequisite")));
        dto.setSkillsRequired(extractSkills(root));
        dto.setResourcesRequired(extractSimpleList(root.path("Resources_Required").path("Resource")));
        dto.setConsequences(extractConsequences(root));
        dto.setMitigations(extractSimpleList(root.path("Mitigations").path("Mitigation")));
        dto.setExampleInstances(extractSimpleList(root.path("Example_Instances").path("Example")));
        dto.setRelatedWeaknesses(extractRelatedWeaknesses(root));
        dto.setReferences(extractReferences(root));

        return dto;
    }

    private String normalizeCapecId(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("CAPEC ID is required");
        }
        String v = value.trim().toUpperCase();
        if (v.startsWith("CAPEC-")) {
            return v;
        }
        String digits = v.replaceAll("[^0-9]", "");
        if (digits.isBlank()) {
            throw new IllegalArgumentException("Invalid CAPEC ID");
        }
        return "CAPEC-" + digits;
    }

    private List<String> extractRelatedAttackPatterns(JsonNode root) {
        List<String> result = new ArrayList<>();
        JsonNode patterns =
                root.path("Related_Attack_Patterns").path("Related_Attack_Pattern");
        for (JsonNode p : asList(patterns)) {
            String nature = p.path("@Nature").asText("");
            String id = p.path("@CAPEC_ID").asText("");
            if (!id.isBlank()) {
                result.add(
                        (nature.isBlank() ? "" : nature + " ") +
                        "CAPEC-" + id
                );
            }
        }
        return result;
    }

    private List<String> extractExecutionFlow(JsonNode root) {
        List<String> result = new ArrayList<>();
        JsonNode steps =
                root.path("Execution_Flow").path("Attack_Step");
        for (JsonNode step : asList(steps)) {
            String stepNo = extractText(step.path("Step"));
            String phase = extractText(step.path("Phase"));
            String description = extractText(step.path("Description"));
            String technique = extractText(step.path("Technique"));
            String text = "";
            if (!stepNo.isBlank()) {
                text += "Step " + stepNo;
            }
            if (!phase.isBlank()) {
                text += text.isBlank() ? phase : " | Phase: " + phase;
            }
            if (!description.isBlank()) {
                text += text.isBlank() ? description : " | " + description;
            }
            if (!technique.isBlank()) {
                text += " | Technique: " + technique;
            }
            if (!text.isBlank()) {
                result.add(clean(text));
            }
        }
        return result;
    }

    private List<String> extractSkills(JsonNode root) {
        List<String> result = new ArrayList<>();
        JsonNode skills =
                root.path("Skills_Required").path("Skill");
        for (JsonNode skill : asList(skills)) {
            String level = skill.path("@Level").asText("");
            String text = extractText(skill);
            if (!text.isBlank()) {
                result.add(
                        level.isBlank()
                                ? text
                                : "Level: " + level + " | " + text
                );
            }
        }
        return result;
    }

    private List<String> extractConsequences(JsonNode root) {
        List<String> result = new ArrayList<>();
        JsonNode consequences =
                root.path("Consequences").path("Consequence");
        for (JsonNode c : asList(consequences)) {
            String scope = extractText(c.path("Scope"));
            String impact = extractText(c.path("Impact"));
            String note = extractText(c.path("Note"));
            String text = "";
            if (!scope.isBlank()) {
                text += "Scope: " + scope;
            }
            if (!impact.isBlank()) {
                text += text.isBlank()
                        ? "Impact: " + impact
                        : " | Impact: " + impact;
            }
            if (!note.isBlank()) {
                text += " | " + note;
            }
            if (!text.isBlank()) {
                result.add(clean(text));
            }
        }
        return result;
    }

    private List<String> extractRelatedWeaknesses(JsonNode root) {
        List<String> result = new ArrayList<>();
        JsonNode weaknesses =
                root.path("Related_Weaknesses").path("Related_Weakness");
        for (JsonNode w : asList(weaknesses)) {
            String id = w.path("@CWE_ID").asText("");
            if (!id.isBlank()) {
                result.add("CWE-" + id);
            }
        }
        return result;
    }

    private List<String> extractReferences(JsonNode root) {
        List<String> result = new ArrayList<>();
        JsonNode refs =
                root.path("References").path("Reference");
        for (JsonNode ref : asList(refs)) {
            String id = ref.path("@External_Reference_ID").asText("");
            String section = ref.path("@Section").asText("");
            if (!id.isBlank()) {
                result.add(
                        section.isBlank()
                                ? id
                                : id + " | " + section
                );
            }
        }
        return result;
    }

    private List<String> extractSimpleList(JsonNode node) {
        List<String> result = new ArrayList<>();
        for (JsonNode item : asList(node)) {
            String text = extractText(item);
            if (!text.isBlank()) {
                result.add(clean(text));
            }
        }
        return result;
    }

    private List<JsonNode> asList(JsonNode node) {
        List<JsonNode> list = new ArrayList<>();
        if (node == null || node.isMissingNode() || node.isNull()) {
            return list;
        }
        if (node.isArray()) {
            node.forEach(list::add);
        } else {
            list.add(node);
        }

        return list;
    }

    private String extractText(JsonNode node) {
        if (node == null || node.isMissingNode() || node.isNull()) {
            return "";
        }
        if (node.isTextual() || node.isNumber() || node.isBoolean()) {
            return clean(node.asText());
        }
        if (node.isArray()) {
            List<String> parts = new ArrayList<>();

            for (JsonNode child : node) {
                String text = extractText(child);
                if (!text.isBlank()) {
                    parts.add(text);
                }
            }
            return clean(String.join(" ", parts));
        }
        if (node.isObject()) {
            List<String> parts = new ArrayList<>();
            node.properties().forEach(entry -> {
                String key = entry.getKey();
                if (!key.startsWith("@")) {
                    String text = extractText(entry.getValue());

                    if (!text.isBlank()) {
                        parts.add(text);
                    }
                }
            });
            return clean(String.join(" ", parts));
        }
        return "";
    }
    private String clean(String value) {
        if (value == null) {
            return "";
        }
        return value
                .replaceAll("\\s+", " ")
                .trim();
    }
}
