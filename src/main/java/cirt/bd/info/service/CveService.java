package cirt.bd.info.service;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import jakarta.transaction.Transactional;
import org.springframework.web.client.RestTemplate;

import cirt.bd.info.dto.CVEDto;
import cirt.bd.info.entity.CVEEntity;
import cirt.bd.info.repository.CVERepository;
import cirt.bd.info.scheduled.CVESyncScheduler;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@Service
public class CveService {
    @Autowired
    private CVERepository cveRepository;
    private final String BASE_URL = "https://vulnerability.circl.lu/api/";
    private static final Logger log = LoggerFactory.getLogger(CveService.class);
    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    // public CVEDto getCve(String id) {
    // if (id == null || !id.toUpperCase().matches("^CVE-\\d{4}-\\d{4,}$")) {
    // throw new IllegalArgumentException("Invalid CVE ID");
    // }

    // String normalizedCveId = id.toUpperCase();
    // String url = BASE_URL + "vulnerability/" + normalizedCveId;

    // String response = restTemplate.getForObject(url, String.class);

    // try {
    // JsonNode root = objectMapper.readTree(response);
    // return convertToDto(root);
    // } catch (Exception e) {
    // throw new RuntimeException("Failed to parse CIRCL CVE response", e);
    // }
    // }

    public String getCwe(String id) {
        return restTemplate.getForObject(BASE_URL + "cwe/" + id, String.class);
    }

    public String getCapec(String id) {
        return restTemplate.getForObject(BASE_URL + "capec/" + id, String.class);
    }

    public String searchByKeyword(String keyword) {
        return restTemplate.getForObject(BASE_URL + "search/" + keyword, String.class);
    }

    private String cleanText(String value) {
        if (value == null) {
            return "";
        }

        return value
                .replaceAll("\\s+", " ")
                .trim();
    }

    private String cleanCweDescription(String value) {
        if (value == null) {
            return "";
        }

        return value
                .replaceFirst("^CWE-\\d+:\\s*", "")
                .replaceAll("\\s+", " ")
                .trim();
    }

    public List<CVEDto> getLatestCves(int page, int pageSize) {
        String LATEST_CVE_URL = BASE_URL + "vulnerability/?date_sort=published&sort_order=desc&page=" + page
                + "&per_page=" + pageSize;
        String response = restTemplate.getForObject(LATEST_CVE_URL, String.class);
        log.warn("By scheduler API URL: " + LATEST_CVE_URL);
        log.info("By scheduler Response: " + response);
        Map<String, CVEDto> cvesById = new LinkedHashMap<>();
        if (response == null || response.isBlank()) {
            return List.of();
        }

        try {
            JsonNode root = objectMapper.readTree(response);
            if (!root.isArray()) {
                throw new IllegalStateException(
                        "Latest CVE API response must be a JSON array");
            }
            for (JsonNode item : root) {
                CVEDto dto = convertToSummaryDto(item);

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
                cvesById.merge(normalizedId, dto, this::selectPreferredSummary);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse latest CIRCL CVE response", e);
        }
        return cvesById.values().stream().toList();
    }

    @Transactional
    public void saveCveBatch(List<CVEEntity> cveEntities) {
        try {
            cveRepository.saveAll(cveEntities);
            cveRepository.flush();
        } catch (Exception e) {
            log.error(
                    "Skipping batch saving due to database error: {}", e.getMessage());
        }
    }

    public List<CVEDto> getCvesOnetime(int page, int pageSize) throws InterruptedException {
        String LATEST_CVE_URL = BASE_URL
                + "vulnerability/?date_sort=published&sort_order=asc&per_page=100&since=2021-01-01&page=" + page;
        String response = "";
        try {
            response = restTemplate.getForObject(LATEST_CVE_URL, String.class);
        } catch (Exception e) {
            log.error("Too many Request Error");
            return null;
        }

        log.warn("API URL: " + LATEST_CVE_URL);
        Map<String, CVEDto> cvesById = new LinkedHashMap<>();
        if (response == null || response.isBlank()) {
            return List.of();
        }
        try {
            JsonNode root = objectMapper.readTree(response);
            if (!root.isArray()) {
                throw new IllegalStateException(
                        "Latest CVE API response must be a JSON array");
            }

            for (JsonNode item : root) {
                CVEDto dto = convertToSummaryDto(item);

                if (dto == null || dto.getCveId() == null
                        || dto.getCveId().isBlank()) {
                    continue;
                }
                String normalizedId = dto.getCveId().trim().toUpperCase();
                if (!normalizedId.matches("^CVE-\\d{4}-\\d{4,}$")) {
                    continue;
                }
                dto.setCveId(normalizedId);
                /*
                 * Prefer the native CVE_RECORD entry over the GHSA copy because
                 * CVE_RECORD usually contains vendor, product and numeric CVSS.
                 */
                cvesById.merge(normalizedId, dto, this::selectPreferredSummary);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse latest CIRCL CVE response", e);
        }
        return cvesById.values().stream().toList();
    }

    private CVEDto convertFlatCveToSummary(JsonNode root) {

        CVEDto dto = new CVEDto();

        dto.setCveId(
                root.path("id")
                        .asString("")
                        .trim()
                        .toUpperCase());

        dto.setDescription(
                extractEnglishDescription(
                        root.path("descriptions")));

        /*
         * This response does not normally contain a title,
         * so use shortened description like you already do elsewhere.
         */
        dto.setTitle(
                shorten(dto.getDescription(), 160));

        dto.setState(
                root.path("vulnStatus")
                        .asString(""));

        dto.setPublishedAt(
                normalizeCveDate(
                        root.path("published")
                                .asString("")));

        dto.setModifiedAt(
                normalizeCveDate(
                        root.path("lastModified")
                                .asString("")));

        dto.setSource("CVE");

        extractSummaryCweFromFlatCve(root, dto);
        extractSummaryCvssFromFlatCve(root, dto);
        extractSummaryAffectedProductFromFlatCve(root, dto);

        return dto;
    }

    private CVEDto convertToSummaryDto(JsonNode root) {

        /*
         * Native CVE 5.x record
         */
        if (root.has("cveMetadata")) {
            return convertCveRecordToSummary(root);
        }
        /*
         * GHSA record
         */
        if (root.has("schema_version")
                || root.has("aliases")
                || root.path("id").asString("").startsWith("GHSA-")) {
            return convertGhsaToSummary(root);
        }
        String id = root.path("id").asString("");
        if (id.matches("(?i)^CVE-\\d{4}-\\d{4,}$")) {
            return convertFlatCveToSummary(root);
        }
        return null;
    }

    private void extractSummaryCweFromFlatCve(
            JsonNode root,
            CVEDto dto) {

        JsonNode weaknesses = root.path("weaknesses");

        if (!weaknesses.isArray()) {
            dto.setCweId("");
            return;
        }

        /*
         * Prefer NVD Primary CWE.
         */
        for (JsonNode weakness : weaknesses) {

            String source = weakness.path("source")
                    .asString("");

            String type = weakness.path("type")
                    .asString("");

            if (!"nvd@nist.gov".equalsIgnoreCase(source)
                    || !"Primary".equalsIgnoreCase(type)) {
                continue;
            }

            String cwe = extractCweFromWeakness(weakness);

            if (!cwe.isBlank()) {
                dto.setCweId(cwe);
                return;
            }
        }

        /*
         * Otherwise take the first real CWE available.
         */
        for (JsonNode weakness : weaknesses) {

            String cwe = extractCweFromWeakness(weakness);

            if (!cwe.isBlank()) {
                dto.setCweId(cwe);
                return;
            }
        }

        dto.setCweId("");
    }

    private String extractCweFromWeakness(
            JsonNode weakness) {
        JsonNode descriptions = weakness.path("description");
        if (!descriptions.isArray()) {
            return "";
        }
        for (JsonNode description : descriptions) {

            String value = description.path("value")
                    .asString("");

            String cwe = extractCweIdFromText(value);
            if (!cwe.isBlank()) {
                return cwe;
            }
        }
        return "";
    }

    private void extractSummaryCvssFromFlatCve(
            JsonNode root,
            CVEDto dto) {

        JsonNode metrics = root.path("metrics");

        if (metrics.isMissingNode()
                || metrics.isNull()) {

            dto.setSeverity("UNKNOWN");
            return;
        }

        /*
         * Highest CVSS version first.
         */
        String[] metricKeys = {
                "cvssMetricV40",
                "cvssMetricV31",
                "cvssMetricV30",
                "cvssMetricV2"
        };

        for (String metricKey : metricKeys) {
            JsonNode metricArray = metrics.path(metricKey);
            if (!metricArray.isArray()
                    || metricArray.isEmpty()) {
                continue;
            }
            JsonNode selected = selectPreferredFlatCvss(metricArray);
            if (selected == null) {
                continue;
            }
            JsonNode cvss = selected.path("cvssData");
            if (cvss.isMissingNode()) {
                continue;
            }
            if (cvss.has("baseScore")) {
                dto.setCvssScore(
                        cvss.path("baseScore")
                                .asDouble());
            }
            String severity = cvss.path("baseSeverity")
                    .asString("");
            if (severity.isBlank()) {
                severity = selected.path("baseSeverity")
                        .asString("");
            }
            dto.setSeverity(
                    severity.isBlank()
                            ? "UNKNOWN"
                            : severity.toUpperCase());
            dto.setCvssVersion(
                    cvss.path("version")
                            .asString(
                                    flatCvssVersion(metricKey)));
            return;
        }
        dto.setSeverity("UNKNOWN");
    }

    private JsonNode selectPreferredFlatCvss(
            JsonNode metricArray) {

        JsonNode primary = null;
        JsonNode nvd = null;
        JsonNode first = null;

        for (JsonNode metric : metricArray) {

            if (first == null) {
                first = metric;
            }

            String source = metric.path("source")
                    .asString("");

            String type = metric.path("type")
                    .asString("");

            boolean isNvd = "nvd@nist.gov"
                    .equalsIgnoreCase(source);

            boolean isPrimary = "Primary"
                    .equalsIgnoreCase(type);

            /*
             * Best possible match.
             */
            if (isNvd && isPrimary) {
                return metric;
            }

            if (primary == null && isPrimary) {
                primary = metric;
            }

            if (nvd == null && isNvd) {
                nvd = metric;
            }
        }

        if (primary != null) {
            return primary;
        }

        if (nvd != null) {
            return nvd;
        }

        return first;
    }

    private String flatCvssVersion(
            String metricKey) {
        return switch (metricKey) {
            case "cvssMetricV40" -> "4.0";
            case "cvssMetricV31" -> "3.1";
            case "cvssMetricV30" -> "3.0";
            default -> "2.0";
        };
    }

    private void extractSummaryAffectedProductFromFlatCve(
            JsonNode root,
            CVEDto dto) {

        JsonNode affected = root.path("affected");

        Set<String> vendors = new LinkedHashSet<>();

        Set<String> products = new LinkedHashSet<>();

        if (!affected.isArray()) {
            dto.setVendor("");
            dto.setProduct("");
            return;
        }

        /*
         * Prefer the original CNA data first.
         * Multiple enrichment sources can repeat the same
         * vendor/product with different capitalization.
         */
        String sourceIdentifier = root.path("sourceIdentifier")
                .asString("");

        extractFlatAffectedForSource(
                affected,
                sourceIdentifier,
                vendors,
                products);

        /*
         * If CNA data gave us nothing, use all sources.
         */
        if (vendors.isEmpty() && products.isEmpty()) {

            for (JsonNode sourceNode : affected) {

                extractFlatAffectedData(
                        sourceNode.path("affectedData"),
                        vendors,
                        products);
            }
        }

        dto.setVendor(
                String.join(", ", vendors));

        dto.setProduct(
                String.join(", ", products));
    }

    private void extractFlatAffectedForSource(
            JsonNode affected,
            String desiredSource,
            Set<String> vendors,
            Set<String> products) {

        for (JsonNode sourceNode : affected) {

            String source = sourceNode.path("source")
                    .asString("");

            if (!source.equalsIgnoreCase(desiredSource)) {
                continue;
            }

            extractFlatAffectedData(
                    sourceNode.path("affectedData"),
                    vendors,
                    products);
        }
    }

    private void extractFlatAffectedData(
            JsonNode affectedData,
            Set<String> vendors,
            Set<String> products) {

        if (!affectedData.isArray()) {
            return;
        }

        for (JsonNode item : affectedData) {

            String vendor = cleanText(
                    item.path("vendor")
                            .asString(""));

            String product = cleanText(
                    item.path("product")
                            .asString(""));

            if (!vendor.isBlank()
                    && !"n/a".equalsIgnoreCase(vendor)
                    && !"unknown".equalsIgnoreCase(vendor)) {

                vendors.add(vendor);
            }

            if (!product.isBlank()
                    && !"n/a".equalsIgnoreCase(product)
                    && !"unknown".equalsIgnoreCase(product)) {

                products.add(product);
            }
        }
    }

    private String normalizeCveDate(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }

        try {
            return Instant.parse(value).toString();
        } catch (DateTimeParseException ignored) {
        }
        try {
            return java.time.LocalDateTime
                    .parse(value)
                    .toInstant(java.time.ZoneOffset.UTC)
                    .toString();

        } catch (DateTimeParseException ignored) {
        }
        return value;
    }

    private CVEDto convertCveRecordToSummary(JsonNode root) {
        CVEDto dto = new CVEDto();

        JsonNode metadata = root.path("cveMetadata");
        JsonNode cna = root.path("containers").path("cna");

        dto.setCveId(metadata.path("cveId").asString(""));
        dto.setTitle(cleanText(cna.path("title").asString("")));
        dto.setDescription(extractEnglishDescription(cna.path("descriptions")));
        dto.setState(metadata.path("state").asString(""));
        if (dto.getState().equals("REJECTED"))
            dto.setPublishedAt(root.path("dateRejected").asString(""));
        else
            dto.setPublishedAt(metadata.path("datePublished").asString(""));
        dto.setModifiedAt(metadata.path("dateUpdated").asString(""));

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

    private CVEDto convertGhsaToSummary(JsonNode root) {
        CVEDto dto = new CVEDto();

        dto.setCveId(extractCveIdFromGhsa(root));
        dto.setDescription(cleanText(root.path("details").asString("")));
        dto.setTitle(shorten(dto.getDescription(), 360));
        dto.setState(root.path("state").asString(""));
        if (dto.getState().equals("REJECTED"))
            dto.setPublishedAt(root.path("rejected").asString(""));
        else
            dto.setPublishedAt(root.path("published").asString(""));
        dto.setModifiedAt(root.path("modified").asString(""));
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

    private void extractSummaryCweFromCveRecord(JsonNode cna, CVEDto dto) {
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

    private void extractSummaryCvssFromCveRecord(JsonNode cna, CVEDto dto) {
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

                dto.setSeverity(cvss.path("baseSeverity")
                        .asString("UNKNOWN")
                        .toUpperCase());
                dto.setCvssVersion(cvss.path("version").asString(
                        cvssVersionFromKey(key)));
                return;
            }
        }
        dto.setSeverity("UNKNOWN");
    }

    private void extractSummaryCvssFromGhsa(JsonNode root, CVEDto dto) {
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
            CVEDto dto) {
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

    private CVEDto selectPreferredSummary(CVEDto existing, CVEDto incoming) {
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
            CVEDto target,
            CVEDto fallback) {
        if (isBlank(target.getTitle())) {
            target.setTitle(fallback.getTitle());
        }

        if (isBlank(target.getDescription())) {
            target.setDescription(fallback.getDescription());
        }

        if (isBlank(target.getPublishedAt())) {
            target.setPublishedAt(fallback.getPublishedAt());
        }

        if (isBlank(target.getModifiedAt())) {
            target.setModifiedAt(fallback.getModifiedAt());
        }

        if (isBlank(target.getSeverity())
                || "UNKNOWN".equalsIgnoreCase(target.getSeverity())) {
            target.setSeverity(fallback.getSeverity());
        }

        if (target.getCvssScore() == 0) {
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

    private Instant publishedInstant(CVEDto dto) {
        if (dto == null || dto.getPublishedAt() == null
                || dto.getPublishedAt().isBlank()) {
            return Instant.EPOCH;
        }

        try {
            return Instant.parse(dto.getPublishedAt());
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
