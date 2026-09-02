package cirt.bd.info.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import cirt.bd.info.dto.circl.CWEDetailsDto;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@Service
public class CirclCWEService {
    private static final String CIRCL_CWE_BASE_URL =
            "https://vulnerability.circl.lu/api/cwe/";

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public CWEDetailsDto getCweDetails(String cweId) {
        String normalized = normalizeCweId(cweId);

        String response = restTemplate.getForObject(
                CIRCL_CWE_BASE_URL + normalized,
                String.class
        );

        try {
            JsonNode root = objectMapper.readTree(response);
            return convertToDto(root);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse CWE response", e);
        }
    }

    private CWEDetailsDto convertToDto(JsonNode root) {
        CWEDetailsDto dto = new CWEDetailsDto();

        dto.setId("CWE-" + root.path("@ID").asText(""));
        dto.setName(clean(root.path("@Name").asText("")));
        dto.setAbstraction(root.path("@Abstraction").asText(""));
        dto.setStructure(root.path("@Structure").asText(""));
        dto.setStatus(root.path("@Status").asText(""));
        dto.setDiagram(root.path("@Diagram").asText(""));
        dto.setDescription(clean(root.path("Description").asText("")));
        dto.setExtendedDescription(extractText(root.path("Extended_Description")));
        dto.setLikelihoodOfExploit(root.path("Likelihood_Of_Exploit").asText(""));

        dto.setAlternateTerms(extractAlternateTerms(root));
        dto.setPlatforms(extractPlatforms(root));
        dto.setModesOfIntroduction(extractModesOfIntroduction(root));
        dto.setRelatedWeaknesses(extractRelatedWeaknesses(root));
        dto.setConsequences(extractConsequences(root));
        dto.setDetectionMethods(extractDetectionMethods(root));
        dto.setMitigations(extractMitigations(root));
        dto.setDemonstrativeExamples(extractDemonstrativeExamples(root));
        dto.setObservedExamples(extractObservedExamples(root));
        dto.setRelatedAttackPatterns(extractRelatedAttackPatterns(root));

        return dto;
    }

    private String normalizeCweId(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("CWE ID is required");
        }

        String v = value.trim().toUpperCase();

        if (v.startsWith("CWE-")) {
            return v;
        }

        String digits = v.replaceAll("[^0-9]", "");
        System.out.println(digits);

        if (digits.isBlank()) {
            throw new IllegalArgumentException("Invalid CWE ID");
        }

        return "CWE-" + digits;
    }

    private List<String> extractAlternateTerms(JsonNode root) {
        List<String> result = new ArrayList<>();

        JsonNode terms = root.path("Alternate_Terms").path("Alternate_Term");

        for (JsonNode term : asList(terms)) {
            String name = extractText(term.path("Term"));
            String desc = extractText(term.path("Description"));

            if (!name.isBlank()) {
                result.add(desc.isBlank() ? name : name + " - " + desc);
            }
        }

        return result;
    }

    private List<String> extractPlatforms(JsonNode root) {
        List<String> result = new ArrayList<>();

        JsonNode platforms = root.path("Applicable_Platforms");

        JsonNode languages = platforms.path("Language");
        for (JsonNode lang : asList(languages)) {
            String text = buildPlatformText("Language", lang);
            if (!text.isBlank()) result.add(text);
        }

        JsonNode technologies = platforms.path("Technology");
        for (JsonNode tech : asList(technologies)) {
            String text = buildPlatformText("Technology", tech);
            if (!text.isBlank()) result.add(text);
        }

        return result;
    }

    private String buildPlatformText(String type, JsonNode node) {
        String name = node.path("@Name").asText("");
        String clazz = node.path("@Class").asText("");
        String prevalence = node.path("@Prevalence").asText("");

        String main = !name.isBlank() ? name : clazz;

        if (main.isBlank()) return "";

        return type + ": " + main +
                (prevalence.isBlank() ? "" : " (" + prevalence + ")");
    }

    private List<String> extractModesOfIntroduction(JsonNode root) {
        List<String> result = new ArrayList<>();

        JsonNode introductions =
                root.path("Modes_Of_Introduction").path("Introduction");

        for (JsonNode intro : asList(introductions)) {
            String phase = extractText(intro.path("Phase"));
            String note = extractText(intro.path("Note"));

            String text = "";
            if (!phase.isBlank()) text += "Phase: " + phase;
            if (!note.isBlank()) text += " | " + note;

            if (!text.isBlank()) result.add(text);
        }

        return result;
    }

    private List<String> extractRelatedWeaknesses(JsonNode root) {
        List<String> result = new ArrayList<>();

        JsonNode weaknesses =
                root.path("Related_Weaknesses").path("Related_Weakness");

        for (JsonNode rw : asList(weaknesses)) {
            String nature = rw.path("@Nature").asText("");
            String cweId = rw.path("@CWE_ID").asText("");
            String viewId = rw.path("@View_ID").asText("");

            if (!cweId.isBlank()) {
                result.add(
                        (nature.isBlank() ? "" : nature + " ") +
                        "CWE-" + cweId +
                        (viewId.isBlank() ? "" : " | View: " + viewId)
                );
            }
        }

        return result;
    }

    private List<String> extractConsequences(JsonNode root) {
        List<String> result = new ArrayList<>();

        JsonNode consequences =
                root.path("Common_Consequences").path("Consequence");

        for (JsonNode c : asList(consequences)) {
            String scope = extractText(c.path("Scope"));
            String impact = extractText(c.path("Impact"));
            String note = extractText(c.path("Note"));

            String text = "";
            if (!scope.isBlank()) text += "Scope: " + scope;
            if (!impact.isBlank()) text += " | Impact: " + impact;
            if (!note.isBlank()) text += " | " + note;

            if (!text.isBlank()) result.add(text);
        }

        return result;
    }

    private List<String> extractDetectionMethods(JsonNode root) {
        List<String> result = new ArrayList<>();

        JsonNode methods =
                root.path("Detection_Methods").path("Detection_Method");

        for (JsonNode m : asList(methods)) {
            String method = extractText(m.path("Method"));
            String effectiveness = extractText(m.path("Effectiveness"));
            String description = extractText(m.path("Description"));

            if (!method.isBlank()) {
                result.add(
                        method +
                        (effectiveness.isBlank() ? "" : " (" + effectiveness + ")") +
                        (description.isBlank() ? "" : " - " + description)
                );
            }
        }

        return result;
    }

    private List<String> extractMitigations(JsonNode root) {
        List<String> result = new ArrayList<>();

        JsonNode mitigations =
                root.path("Potential_Mitigations").path("Mitigation");

        for (JsonNode m : asList(mitigations)) {
            String phase = extractText(m.path("Phase"));
            String strategy = extractText(m.path("Strategy"));
            String effectiveness = extractText(m.path("Effectiveness"));
            String description = extractText(m.path("Description"));

            String text = "";
            if (!phase.isBlank()) text += "Phase: " + phase;
            if (!strategy.isBlank()) text += " | Strategy: " + strategy;
            if (!effectiveness.isBlank()) text += " | Effectiveness: " + effectiveness;
            if (!description.isBlank()) text += " | " + description;

            if (!text.isBlank()) result.add(text);
        }

        return result;
    }

    private List<String> extractDemonstrativeExamples(JsonNode root) {
        List<String> result = new ArrayList<>();

        JsonNode examples =
                root.path("Demonstrative_Examples").path("Demonstrative_Example");

        for (JsonNode ex : asList(examples)) {
            String id = ex.path("@Demonstrative_Example_ID").asText("");
            String intro = extractText(ex.path("Intro_Text"));
            String body = extractText(ex.path("Body_Text"));

            String text = "";
            if (!id.isBlank()) text += id + ": ";
            if (!intro.isBlank()) text += intro;
            if (!body.isBlank()) text += " " + body;

            if (!text.isBlank()) result.add(clean(text));
        }

        return result;
    }

    private List<String> extractObservedExamples(JsonNode root) {
        List<String> result = new ArrayList<>();

        JsonNode examples =
                root.path("Observed_Examples").path("Observed_Example");

        for (JsonNode ex : asList(examples)) {
            String reference = extractText(ex.path("Reference"));
            String description = extractText(ex.path("Description"));
            String link = extractText(ex.path("Link"));

            String text = "";
            if (!reference.isBlank()) text += reference;
            if (!description.isBlank()) text += " - " + description;
            if (!link.isBlank()) text += " | " + link;

            if (!text.isBlank()) result.add(clean(text));
        }

        return result;
    }

    private List<String> extractRelatedAttackPatterns(JsonNode root) {
        List<String> result = new ArrayList<>();

        JsonNode patterns =
                root.path("Related_Attack_Patterns").path("Related_Attack_Pattern");

        for (JsonNode pattern : asList(patterns)) {
            String capecId = pattern.path("@CAPEC_ID").asText("");

            if (!capecId.isBlank()) {
                result.add("CAPEC-" + capecId);
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
