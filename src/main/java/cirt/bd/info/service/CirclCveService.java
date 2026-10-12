package cirt.bd.info.service;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import cirt.bd.info.dto.circl.CVEDetailsDto;
import cirt.bd.info.dto.circl.CVESummaryDto;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@Service
public class CirclCVEService {
    private final String BASE_URL = "https://vulnerability.circl.lu/api/";

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public CVEDetailsDto getCve(String id) {
        if (id == null || !id.toUpperCase().matches("^CVE-\\d{4}-\\d{4,}$")) {
            throw new IllegalArgumentException("Invalid CVE ID");
        }

        String normalizedCveId = id.toUpperCase();
        String url = BASE_URL + "vulnerability/" + normalizedCveId;

        String response = restTemplate.getForObject(url, String.class);

        try {
            JsonNode root = objectMapper.readTree(response);
            return convertToDto(root);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse CIRCL CVE response", e);
        }
    }

    public String getCwe(String id) {
        return restTemplate.getForObject(BASE_URL + "cwe/" + id, String.class);
    }

    public String getCapec(String id) {
        return restTemplate.getForObject(BASE_URL + "capec/" + id, String.class);
    }

    public String searchByKeyword(String keyword) {
        return restTemplate.getForObject(BASE_URL + "search/" + keyword, String.class);
    }

    public static CVEDetailsDto convertToDto(JsonNode root) {
        CVEDetailsDto dto = new CVEDetailsDto();

        JsonNode metadata = root.path("cveMetadata");
        JsonNode cna = root.path("containers").path("cna");

        dto.setCveId(text(metadata, "cveId"));
        dto.setState(text(metadata, "state"));
        dto.setAssigner(text(metadata, "assignerShortName"));
        dto.setPublished(text(metadata, "datePublished"));
        dto.setUpdated(text(metadata, "dateUpdated"));

        dto.setTitle(cleanText(text(cna, "title")));
        dto.setDescription(extractDescription(cna));
        dto.setAdvisorySource(cna.path("source").path("advisory").asString(""));

        extractCwe(cna, dto);
        extractCvss(cna, dto);
        extractAffectedProducts(cna, dto);
        extractReferences(root, dto);
        extractSsvc(root, dto);

        return dto;
    }

    public static String extractDescription(JsonNode cna) {
        JsonNode descriptions = cna.path("descriptions");

        if (descriptions.isArray()) {
            for (JsonNode desc : descriptions) {
                if ("en".equalsIgnoreCase(desc.path("lang").asString())) {
                    return cleanText(desc.path("value").asString(""));
                }
            }

            if (descriptions.size() > 0) {
                return cleanText(descriptions.get(0).path("value").asString(""));
            }
        }

        return "";
    }

    public static void extractCwe(JsonNode cna, CVEDetailsDto dto) {
        JsonNode problemTypes = cna.path("problemTypes");

        if (!problemTypes.isArray()) {
            dto.setCweId("");
            dto.setCweDescription("");
            return;
        }

        for (JsonNode problemType : problemTypes) {
            JsonNode descriptions = problemType.path("descriptions");

            if (!descriptions.isArray()) {
                continue;
            }

            for (JsonNode desc : descriptions) {
                String cweId = desc.path("cweId").asString("");
                String description = desc.path("description").asString("");

                if (!cweId.isBlank() || description.toUpperCase().contains("CWE-")) {
                    dto.setCweId(cweId);
                    dto.setCweDescription(cleanCweDescription(description));
                    return;
                }
            }
        }

        dto.setCweId("");
        dto.setCweDescription("");
    }

    public static void extractCvss(JsonNode cna, CVEDetailsDto dto) {
        JsonNode metrics = cna.path("metrics");

        if (!metrics.isArray()) {
            return;
        }

        for (JsonNode metric : metrics) {
            if (metric.has("cvssV4_0")) {
                setCvss(dto, metric.path("cvssV4_0"), "4.0");
                return;
            }

            if (metric.has("cvssV3_1")) {
                setCvss(dto, metric.path("cvssV3_1"), "3.1");
                return;
            }

            if (metric.has("cvssV3_0")) {
                setCvss(dto, metric.path("cvssV3_0"), "3.0");
                return;
            }

            if (metric.has("cvssV2_0")) {
                setCvss(dto, metric.path("cvssV2_0"), "2.0");
                return;
            }

            if (metric.has("cvssV2")) {
                setCvss(dto, metric.path("cvssV2"), "2.0");
                return;
            }
        }
    }

    public static void setCvss(CVEDetailsDto dto, JsonNode cvss, String version) {
        if (cvss.has("baseScore")) {
            dto.setCvssScore(cvss.path("baseScore").asDouble());
        }

        dto.setCvssSeverity(cvss.path("baseSeverity").asString(""));
        dto.setCvssVector(cvss.path("vectorString").asString(""));
        dto.setCvssVersion(version);
    }

    public static void extractAffectedProducts(JsonNode cna, CVEDetailsDto dto) {
        JsonNode affected = cna.path("affected");

        List<String> versions = new ArrayList<>();
        Set<String> vendors = new LinkedHashSet<>();
        Set<String> products = new LinkedHashSet<>();

        if (affected.isArray()) {
            for (JsonNode item : affected) {
                String vendor = item.path("vendor").asString("");
                String product = item.path("product").asString("");

                if (!vendor.isBlank()) {
                    vendors.add(vendor);
                }

                if (!product.isBlank()) {
                    products.add(product);
                }

                JsonNode versionArray = item.path("versions");

                if (versionArray.isArray()) {
                    for (JsonNode versionNode : versionArray) {
                        String version = versionNode.path("version").asString("");
                        String status = versionNode.path("status").asString("");
                        String lessThan = versionNode.path("lessThan").asString("");
                        String lessThanOrEqual = versionNode.path("lessThanOrEqual").asString("");

                        StringBuilder versionText = new StringBuilder();

                        if (!version.isBlank()) {
                            versionText.append(version);
                        }

                        if (!lessThan.isBlank()) {
                            versionText.append(" < ").append(lessThan);
                        }

                        if (!lessThanOrEqual.isBlank()) {
                            versionText.append(" <= ").append(lessThanOrEqual);
                        }

                        if (!status.isBlank()) {
                            versionText.append(" (").append(status).append(")");
                        }

                        if (!versionText.isEmpty()) {
                            versions.add(versionText.toString());
                        }
                    }
                }
            }
        }

        dto.setVendor(String.join(", ", vendors));
        dto.setProduct(String.join(", ", products));
        dto.setAffectedVersions(versions);
    }

    public static void extractReferences(JsonNode root, CVEDetailsDto dto) {
        Set<String> refs = new LinkedHashSet<>();

        JsonNode cnaRefs = root.path("containers").path("cna").path("references");

        if (cnaRefs.isArray()) {
            for (JsonNode ref : cnaRefs) {
                String url = ref.path("url").asString("");
                if (!url.isBlank()) {
                    refs.add(url);
                }
            }
        }

        JsonNode adp = root.path("containers").path("adp");

        if (adp.isArray()) {
            for (JsonNode adpItem : adp) {
                JsonNode adpRefs = adpItem.path("references");

                if (adpRefs.isArray()) {
                    for (JsonNode ref : adpRefs) {
                        String url = ref.path("url").asString("");
                        if (!url.isBlank()) {
                            refs.add(url);
                        }
                    }
                }
            }
        }

        dto.setReferences(new ArrayList<>(refs));
    }

    public static void extractSsvc(JsonNode root, CVEDetailsDto dto) {
        JsonNode adp = root.path("containers").path("adp");

        if (!adp.isArray()) {
            dto.setExploitation("");
            dto.setAutomatable("");
            dto.setTechnicalImpact("");
            return;
        }

        for (JsonNode adpItem : adp) {
            JsonNode metrics = adpItem.path("metrics");

            if (!metrics.isArray()) {
                continue;
            }

            for (JsonNode metric : metrics) {
                JsonNode options = metric
                        .path("other")
                        .path("content")
                        .path("options");

                if (!options.isArray()) {
                    continue;
                }

                for (JsonNode option : options) {
                    if (option.has("Exploitation")) {
                        dto.setExploitation(option.path("Exploitation").asString(""));
                    }

                    if (option.has("Automatable")) {
                        dto.setAutomatable(option.path("Automatable").asString(""));
                    }

                    if (option.has("Technical Impact")) {
                        dto.setTechnicalImpact(option.path("Technical Impact").asString(""));
                    }
                }
            }
        }

        if (dto.getExploitation() == null) {
            dto.setExploitation("");
        }

        if (dto.getAutomatable() == null) {
            dto.setAutomatable("");
        }

        if (dto.getTechnicalImpact() == null) {
            dto.setTechnicalImpact("");
        }
    }

    public static String text(JsonNode node, String field) {
        return node.path(field).asString("");
    }

    public static String cleanText(String value) {
        if (value == null) {
            return "";
        }

        return value
                .replaceAll("\\s+", " ")
                .trim();
    }

    public static String cleanCweDescription(String value) {
        if (value == null) {
            return "";
        }

        return value
                .replaceFirst("^CWE-\\d+:\\s*", "")
                .replaceAll("\\s+", " ")
                .trim();
    }

    public List<CVESummaryDto> getLatestCves(String url) {
        // String LATEST_CVE_URL = BASE_URL + "/?date_sort=published&sort_order=desc&page=2&per_page=40";
        String response = restTemplate.getForObject(url,String.class);
        if (response == null || response.isBlank()) {
            return List.of();
        }
        try {
            JsonNode root = objectMapper.readTree(response);
            if (!root.isArray()) {
                throw new IllegalStateException(
                        "Latest CVE API response must be a JSON array");
            }
            /*
             * LinkedHashMap lets us deduplicate CVE_RECORD and GHSA entries
             * referring to the same CVE.
             */
            Map<String, CVESummaryDto> cvesById = new LinkedHashMap<>();
            for (JsonNode item : root) {
                CVESummaryDto dto = convertToSummaryDto(item);

                if (dto == null || dto.getCveId() == null
                        || dto.getCveId().isBlank()) {
                    continue;
                }

                String normalizedId = dto.getCveId().trim().toUpperCase();
                // System.out.println(normalizedId);
                if (!normalizedId.matches("^CVE-\\d{4}-\\d{4,}$")) {
                    continue;
                }

                dto.setCveId(normalizedId);

                /*
                 * Prefer the native CVE_RECORD entry over the GHSA copy because
                 * CVE_RECORD usually contains vendor, product and numeric CVSS.
                 */
                cvesById.merge(
                        normalizedId,
                        dto,
                        this::selectPreferredSummary);
            }

            return cvesById.values()
                    .stream()
                    .sorted(
                            Comparator.comparing(
                                    this::publishedInstant,
                                    Comparator.reverseOrder()))
                    .toList();

        } catch (Exception e) {
            throw new RuntimeException(
                    "Failed to parse latest CIRCL CVE response",
                    e);
        }
    }

    private CVESummaryDto convertToSummaryDto(JsonNode root) {
        if (root.has("cveMetadata")) {
            return convertCveRecordToSummary(root);
        }

        if (root.has("schema_version")
                || root.has("aliases")
                || root.path("id").asString("").startsWith("GHSA-")) {
            return convertGhsaToSummary(root);
        }

        return null;
    }

    private CVESummaryDto convertCveRecordToSummary(JsonNode root) {
        CVESummaryDto dto = new CVESummaryDto();

        JsonNode metadata = root.path("cveMetadata");
        JsonNode cna = root.path("containers").path("cna");

        dto.setCveId(metadata.path("cveId").asString(""));
        dto.setTitle(cleanText(cna.path("title").asString("")));
        dto.setDescription(extractEnglishDescription(cna.path("descriptions")));
        dto.setPublished(metadata.path("datePublished").asString(""));
        dto.setUpdated(metadata.path("dateUpdated").asString(""));
        dto.setSource("CVE");

        extractSummaryCweFromCveRecord(cna, dto);
        extractSummaryCvssFromCveRecord(cna, dto);
        extractSummaryAffectedProduct(cna, dto);

        /*
         * Some CVE records do not contain a title.
         * Use a shortened description instead.
         */
        if (dto.getTitle() == null || dto.getTitle().isBlank()) {
            dto.setTitle(shorten(dto.getDescription(), 160));
        }

        return dto;
    }

    private CVESummaryDto convertGhsaToSummary(JsonNode root) {
        CVESummaryDto dto = new CVESummaryDto();

        dto.setCveId(extractCveIdFromGhsa(root));
        dto.setDescription(cleanText(root.path("details").asString("")));
        dto.setTitle(shorten(dto.getDescription(), 160));
        dto.setPublished(root.path("published").asString(""));
        dto.setUpdated(root.path("modified").asString(""));
        dto.setSource("GHSA");

        JsonNode databaseSpecific = root.path("database_specific");

        dto.setSeverity(
                databaseSpecific.path("severity")
                        .asString("UNKNOWN")
                        .toUpperCase());

        JsonNode cweIds = databaseSpecific.path("cwe_ids");

        if (cweIds.isArray() && !cweIds.isEmpty()) {
            dto.setCweId(cweIds.get(0).asString(""));
        } else {
            dto.setCweId("");
        }

        extractSummaryCvssFromGhsa(root, dto);

        dto.setVendor("");
        dto.setProduct("");

        return dto;
    }

    private String extractCveIdFromGhsa(JsonNode root) {
        JsonNode aliases = root.path("aliases");

        if (aliases.isArray()) {
            for (JsonNode alias : aliases) {
                String value = alias.asString("").trim().toUpperCase();

                if (value.matches("^CVE-\\d{4}-\\d{4,}$")) {
                    return value;
                }
            }
        }

        String id = root.path("id").asString("").trim().toUpperCase();

        if (id.matches("^CVE-\\d{4}-\\d{4,}$")) {
            return id;
        }

        return "";
    }

    private void extractSummaryCweFromCveRecord(
            JsonNode cna,
            CVESummaryDto dto) {
        JsonNode problemTypes = cna.path("problemTypes");

        if (!problemTypes.isArray()) {
            dto.setCweId("");
            return;
        }

        for (JsonNode problemType : problemTypes) {
            JsonNode descriptions = problemType.path("descriptions");

            if (!descriptions.isArray()) {
                continue;
            }

            for (JsonNode description : descriptions) {
                String cweId = description.path("cweId").asString("");

                if (!cweId.isBlank()) {
                    dto.setCweId(cweId);
                    return;
                }

                String text = description.path("description").asString("");
                String extracted = extractCweIdFromText(text);

                if (!extracted.isBlank()) {
                    dto.setCweId(extracted);
                    return;
                }
            }
        }

        dto.setCweId("");
    }

    private void extractSummaryCvssFromCveRecord(
            JsonNode cna,
            CVESummaryDto dto) {
        JsonNode metrics = cna.path("metrics");

        if (!metrics.isArray()) {
            dto.setSeverity("UNKNOWN");
            return;
        }

        /*
         * Prefer CVSS 4, then 3.1, then 3.0, then 2.0.
         */
        String[] cvssKeys = {
                "cvssV4_0",
                "cvssV3_1",
                "cvssV3_0",
                "cvssV2_0",
                "cvssV2"
        };

        for (String key : cvssKeys) {
            for (JsonNode metric : metrics) {
                if (!metric.has(key)) {
                    continue;
                }

                JsonNode cvss = metric.path(key);

                if (cvss.has("baseScore")) {
                    dto.setCvssScore(cvss.path("baseScore").asDouble());
                }

                dto.setSeverity(
                        cvss.path("baseSeverity")
                                .asString("UNKNOWN")
                                .toUpperCase());

                dto.setCvssVersion(
                        cvss.path("version").asString(
                                cvssVersionFromKey(key)));

                return;
            }
        }

        dto.setSeverity("UNKNOWN");
    }

    private void extractSummaryCvssFromGhsa(
            JsonNode root,
            CVESummaryDto dto) {
        JsonNode severities = root.path("severity");

        if (!severities.isArray()) {
            return;
        }

        /*
         * GHSA data provides the vector but often does not provide a numeric
         * base score. Keep cvssScore null instead of displaying an incorrect
         * calculated score.
         */
        for (JsonNode severityNode : severities) {
            String type = severityNode.path("type").asString("");

            if ("CVSS_V4".equalsIgnoreCase(type)) {
                dto.setCvssVersion("4.0");
                return;
            }
        }

        for (JsonNode severityNode : severities) {
            String type = severityNode.path("type").asString("");

            if ("CVSS_V3".equalsIgnoreCase(type)) {
                dto.setCvssVersion("3.x");
                return;
            }
        }
    }

    private void extractSummaryAffectedProduct(
            JsonNode cna,
            CVESummaryDto dto) {
        JsonNode affected = cna.path("affected");

        Set<String> vendors = new LinkedHashSet<>();
        Set<String> products = new LinkedHashSet<>();

        if (affected.isArray()) {
            for (JsonNode affectedItem : affected) {
                String vendor = affectedItem.path("vendor").asString("");
                String product = affectedItem.path("product").asString("");

                if (!vendor.isBlank()) {
                    vendors.add(vendor);
                }

                if (!product.isBlank()) {
                    products.add(product);
                }
            }
        }

        dto.setVendor(String.join(", ", vendors));
        dto.setProduct(String.join(", ", products));
    }

    private CVESummaryDto selectPreferredSummary(
            CVESummaryDto existing,
            CVESummaryDto incoming) {
        if ("CVE".equalsIgnoreCase(existing.getSource())) {
            fillMissingSummaryFields(existing, incoming);
            return existing;
        }

        if ("CVE".equalsIgnoreCase(incoming.getSource())) {
            fillMissingSummaryFields(incoming, existing);
            return incoming;
        }

        /*
         * When both records are the same type, keep the one with the newest
         * publication date.
         */
        if (publishedInstant(incoming)
                .isAfter(publishedInstant(existing))) {
            fillMissingSummaryFields(incoming, existing);
            return incoming;
        }

        fillMissingSummaryFields(existing, incoming);
        return existing;
    }

    private void fillMissingSummaryFields(
            CVESummaryDto target,
            CVESummaryDto fallback) {
        if (isBlank(target.getTitle())) {
            target.setTitle(fallback.getTitle());
        }

        if (isBlank(target.getDescription())) {
            target.setDescription(fallback.getDescription());
        }

        if (isBlank(target.getPublished())) {
            target.setPublished(fallback.getPublished());
        }

        if (isBlank(target.getUpdated())) {
            target.setUpdated(fallback.getUpdated());
        }

        if (isBlank(target.getSeverity())
                || "UNKNOWN".equalsIgnoreCase(target.getSeverity())) {
            target.setSeverity(fallback.getSeverity());
        }

        if (target.getCvssScore() == null) {
            target.setCvssScore(fallback.getCvssScore());
        }

        if (isBlank(target.getCvssVersion())) {
            target.setCvssVersion(fallback.getCvssVersion());
        }

        if (isBlank(target.getCweId())) {
            target.setCweId(fallback.getCweId());
        }

        if (isBlank(target.getVendor())) {
            target.setVendor(fallback.getVendor());
        }

        if (isBlank(target.getProduct())) {
            target.setProduct(fallback.getProduct());
        }
    }

    private String extractEnglishDescription(JsonNode descriptions) {
        if (!descriptions.isArray()) {
            return "";
        }

        for (JsonNode description : descriptions) {
            if ("en".equalsIgnoreCase(
                    description.path("lang").asString(""))) {
                return cleanText(
                        description.path("value").asString(""));
            }
        }

        if (!descriptions.isEmpty()) {
            return cleanText(
                    descriptions.get(0).path("value").asString(""));
        }

        return "";
    }

    private String extractCweIdFromText(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }

        java.util.regex.Matcher matcher = java.util.regex.Pattern
                .compile("CWE-\\d+", java.util.regex.Pattern.CASE_INSENSITIVE)
                .matcher(value);

        return matcher.find()
                ? matcher.group().toUpperCase()
                : "";
    }

    private String cvssVersionFromKey(String key) {
        return switch (key) {
            case "cvssV4_0" -> "4.0";
            case "cvssV3_1" -> "3.1";
            case "cvssV3_0" -> "3.0";
            default -> "2.0";
        };
    }

    private Instant publishedInstant(CVESummaryDto dto) {
        if (dto == null || dto.getPublished() == null
                || dto.getPublished().isBlank()) {
            return Instant.EPOCH;
        }

        try {
            return Instant.parse(dto.getPublished());
        } catch (DateTimeParseException exception) {
            return Instant.EPOCH;
        }
    }

    private String shorten(String value, int maximumLength) {
        String cleaned = cleanText(value);

        if (cleaned.length() <= maximumLength) {
            return cleaned;
        }

        return cleaned.substring(0, maximumLength).trim() + "...";
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
