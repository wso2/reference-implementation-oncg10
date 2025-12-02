// Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
//
// WSO2 LLC. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
import ballerina/file;
import ballerina/ftp;
import ballerina/http;
import ballerina/io;
import ballerina/log;
import ballerina/jwt;
import ballerina/lang.'string as strings;
import ballerina/lang.'xml as xmls;
import ballerina/url;
import ballerinax/health.clients.fhir as fhir;
import ballerinax/health.fhir.r4;
import ballerinax/health.fhir.r4utils.ccdatofhir;


type RemoteClinicConfig record {|
    string baseURL;
    string tokenEndpoint;
    string clientId;
    string keyContent;
|};

type ResolvedClinicConfig record {|
    string baseURL;
    string tokenEndpoint;
    string clientId;
    string keyFilePath;
    boolean urlRewrite;
    string? replacementURL;
    boolean validateServerCapabilities;
|};

final map<fhir:FHIRConnector> fhirConnectorCache = {};
final map<ResolvedClinicConfig> resolvedClinicConfigCache = {};
final map<string> clinicConfigSignatures = {};
final map<string> clinicConnectorSignatures = {};
final map<http:Client> resolverClientCache = {};

function createSftpClient() returns ftp:Client|error {
    ftp:ClientConfiguration clientConfig = {
        protocol: ftp:SFTP,
        host: sftpHost,
        port: sftpPort,
        auth: {
            credentials: {
                username: sftpUsername,
                password: sftpPassword
            }
        }
    };

    return new (clientConfig);
}

function isSkippableDirectory(string name) returns boolean {
    return name == "." || name == "..";
}

function containsString(string[] collection, string value) returns boolean {
    foreach string item in collection {
        if item == value {
            return true;
        }
    }

    return false;
}

function normalizeDirectoryPath(string path) returns string {
    string trimmedPath = strings:trim(path);
    if trimmedPath.length() == 0 {
        return trimmedPath;
    }

    if trimmedPath == "/" {
        return "/";
    }

    if trimmedPath.endsWith("/") {
        return trimmedPath.substring(0, trimmedPath.length() - 1);
    }

    return trimmedPath;
}

function isSameDirectory(string first, string second) returns boolean {
    return normalizeDirectoryPath(first) == normalizeDirectoryPath(second);
}

function isChildDirectory(string parent, string possibleChild) returns boolean {
    string normalizedParent = normalizeDirectoryPath(parent);
    string normalizedChild = normalizeDirectoryPath(possibleChild);

    if normalizedParent == normalizedChild {
        return false;
    }

    if normalizedParent == "/" {
        return normalizedChild != "/";
    }

    string prefix = string `${normalizedParent}/`;
    return normalizedChild.startsWith(prefix);
}

function deriveParentDirectory(string directoryPath) returns string {
    string normalizedPath = normalizeDirectoryPath(directoryPath);
    if normalizedPath.length() == 0 {
        return normalizedPath;
    }

    if normalizedPath == "/" {
        return "/";
    }

    int? lastSlashIndex = normalizedPath.lastIndexOf("/");
    if lastSlashIndex is int {
        int slashIndex = lastSlashIndex;
        if slashIndex <= 0 {
            return "/";
        }
        return normalizedPath.substring(0, slashIndex);
    }

    return "/";
}

function resolveClinicName(string filePath) returns string? {
    string? matchedClinic = ();
    int matchedPathLength = -1;

    foreach string clinicName in monitoredFolders.keys() {
        string? folderPath = monitoredFolders[clinicName];
        if folderPath is string && filePath.startsWith(folderPath) {
            int currentLength = folderPath.length();
            if currentLength > matchedPathLength {
                matchedClinic = clinicName;
                matchedPathLength = currentLength;
            }
        }
    }

    return matchedClinic;
}

function ensureLeadingSlash(string value) returns string {
    if value.startsWith("/") {
        return value;
    }
    return string `/${value}`;
}

function materializeKeyFile(string clinicName, string keyContent, string? reusePath) returns string|error {
    if reusePath is string && reusePath.length() > 0 {
        string existingPath = reusePath;
        error? rewriteResult = io:fileWriteString(existingPath, keyContent);
        if rewriteResult is () {
            return existingPath;
        }
        if rewriteResult is error {
            log:printWarn(string `Failed to reuse existing key file for clinic ${clinicName}`);
        }
    }

    string tempFilePath = check file:createTemp(prefix = string `g10_key_${clinicName}_`, suffix = ".pem");
    check io:fileWriteString(tempFilePath, keyContent);
    return tempFilePath;
}

function extractNonEmptyString(json payload, string fieldName) returns string|error {
    if payload is map<json> {
        json? value = payload[fieldName];
        if value is string {
            string trimmed = strings:trim(value);
            if trimmed.length() > 0 {
                return trimmed;
            }
        }
    }

    return error(string `Missing or empty field '${fieldName}' in resolver response`);
}

function extractKeyFileField(json payload) returns string|error {
    if payload is map<json> {
        json? value = payload["keyFile"];
        if value is string {
            string trimmed = strings:trim(value);
            if trimmed.length() > 0 {
                return trimmed;
            }
        }
    }

    return error("Missing or empty field 'keyFile' in resolver response");
}

function isPemContent(string value) returns boolean {
    string normalized = strings:trim(value);
    boolean hasBegin = normalized.startsWith("-----BEGIN ");
    boolean hasEnd = strings:indexOf(normalized, "-----END ") != -1;
    return hasBegin && hasEnd;
}

function ensureKeyFileContent(string rawKeyFile) returns string|error {
    string trimmedValue = strings:trim(rawKeyFile);
    if trimmedValue.length() == 0 {
        return error("Key content returned by resolver is empty");
    }

    if isPemContent(trimmedValue) {
        return trimmedValue;
    }

    return error("Key content returned by resolver is not in PEM format");
}

function getClinicResolverConfig(string clinicName) returns ClinicFhirConnectorConfig|error {
    ClinicFhirConnectorConfig? configOpt = clinicFhirConfigs[clinicName];
    if configOpt is () {
        return error(string `No resolver configuration found for clinic ${clinicName}`);
    }

    ClinicFhirConnectorConfig config = configOpt;
    string normalizedBase = strings:trim(config.resolverBaseUrl);
    if normalizedBase.length() == 0 {
        return error(string `Resolver base URL is empty for clinic ${clinicName}`);
    }

    if normalizedBase.endsWith("/") {
        normalizedBase = normalizedBase.substring(0, normalizedBase.length() - 1);
    }

    string configuredPath = strings:trim(config.resolverPath);
    if configuredPath.length() == 0 {
        configuredPath = "/resolver/orgs";
    }

    string normalizedPath = ensureLeadingSlash(configuredPath);

    return {
        resolverBaseUrl: normalizedBase,
        resolverPath: normalizedPath,
        urlRewrite: config.urlRewrite,
        replacementURL: config.replacementURL,
        validateServerCapabilities: config.validateServerCapabilities
    };
}

function getOrCreateResolverClient(string baseUrl) returns http:Client|error {
    http:Client? existing = resolverClientCache[baseUrl];
    if existing is http:Client {
        return existing;
    }

    http:Client httpClient = check new (baseUrl);
    resolverClientCache[baseUrl] = httpClient;
    return httpClient;
}

function buildResolverRequestPath(string basePath, string clinicName) returns string|error {
    string sanitizedBase = basePath.endsWith("/") ? basePath.substring(0, basePath.length() - 1) : basePath;
    string encodedClinic = check url:encode(clinicName, "UTF-8");
    return string `${sanitizedBase}/${encodedClinic}`;
}

function fetchRemoteClinicConfig(string clinicName, ClinicFhirConnectorConfig resolverConfig) returns RemoteClinicConfig|error {
    http:Client resolverClient = check getOrCreateResolverClient(resolverConfig.resolverBaseUrl);
    string requestPath = check buildResolverRequestPath(resolverConfig.resolverPath, clinicName);
    http:Response response = check resolverClient->get(requestPath);

    int statusCode = response.statusCode;
    if statusCode >= 400 {
        map<anydata> logProperties = {
            clinicName: clinicName,
            resolverBaseUrl: resolverConfig.resolverBaseUrl,
            resolverPath: resolverConfig.resolverPath,
            statusCode: statusCode
        };
        json|error errorPayload = response.getJsonPayload();
        if errorPayload is json {
            logProperties["body"] = errorPayload;
        }

        log:printError(string `Resolver service responded with status ${statusCode} for clinic ${clinicName}`,
            properties = logProperties);
        return error(string `Resolver service returned status ${statusCode}`);
    }

    json payload = check response.getJsonPayload();
    string baseURL = check extractNonEmptyString(payload, "baseURL");
    string tokenEndpoint = check extractNonEmptyString(payload, "tokenEndpoint");
    string clientId = check extractNonEmptyString(payload, "clientId");
    string rawKeyFile = check extractKeyFileField(payload);
    string keyContent = check ensureKeyFileContent(rawKeyFile);

    return {
        baseURL: baseURL,
        tokenEndpoint: tokenEndpoint,
        clientId: clientId,
        keyContent: keyContent
    };
}

function buildConfigSignature(RemoteClinicConfig remoteConfig, ClinicFhirConnectorConfig clinicConfig) returns string {
    string replacement = clinicConfig.replacementURL is string ? <string>clinicConfig.replacementURL : "";
    return string `${remoteConfig.baseURL}|${remoteConfig.tokenEndpoint}|${remoteConfig.clientId}|${remoteConfig.keyContent}|${clinicConfig.urlRewrite}|${replacement}|${clinicConfig.validateServerCapabilities}`;
}

function getResolvedClinicConfig(string clinicName) returns ResolvedClinicConfig|error {
    ClinicFhirConnectorConfig resolverConfig = check getClinicResolverConfig(clinicName);
    RemoteClinicConfig remoteConfig = check fetchRemoteClinicConfig(clinicName, resolverConfig);
    string signature = buildConfigSignature(remoteConfig, resolverConfig);

    ResolvedClinicConfig? cachedConfig = resolvedClinicConfigCache[clinicName];
    string? reusePath = cachedConfig is ResolvedClinicConfig ? cachedConfig.keyFilePath : ();
    string keyFilePath = check materializeKeyFile(clinicName, remoteConfig.keyContent, reusePath);
    ResolvedClinicConfig resolvedConfig = {
        baseURL: remoteConfig.baseURL,
        tokenEndpoint: remoteConfig.tokenEndpoint,
        clientId: remoteConfig.clientId,
        keyFilePath: keyFilePath,
        urlRewrite: resolverConfig.urlRewrite,
        replacementURL: resolverConfig.replacementURL,
        validateServerCapabilities: resolverConfig.validateServerCapabilities
    };

    resolvedClinicConfigCache[clinicName] = resolvedConfig;
    clinicConfigSignatures[clinicName] = signature;

    string? existingConnectorSignature = clinicConnectorSignatures[clinicName];
    if existingConnectorSignature is string && existingConnectorSignature != signature {
        _ = fhirConnectorCache.remove(clinicName);
        _ = clinicConnectorSignatures.remove(clinicName);
    }

    return resolvedConfig;
}

function buildJwtAssertion(ResolvedClinicConfig resolvedConfig) returns string|error {
    jwt:IssuerConfig issuerConfig = {
        issuer: resolvedConfig.clientId,
        username: resolvedConfig.clientId,
        audience: resolvedConfig.tokenEndpoint,
        customClaims: {"scope": "https://www.googleapis.com/auth/cloud-platform"},
        expTime: 3600,
        signatureConfig: {
            config: {
                keyFile: resolvedConfig.keyFilePath
            }
        }
    };

    return check jwt:issue(issuerConfig);
}

function getOrCreateFhirConnector(string clinicName) returns fhir:FHIRConnector|error {
    ResolvedClinicConfig resolvedConfig = check getResolvedClinicConfig(clinicName);
    string currentSignature = clinicConfigSignatures[clinicName] ?: "";

    string? cachedSignature = clinicConnectorSignatures[clinicName];
    fhir:FHIRConnector? existing = fhirConnectorCache[clinicName];
    if existing is fhir:FHIRConnector && cachedSignature is string && cachedSignature == currentSignature {
        return existing;
    }

    string jwtAssertion = check buildJwtAssertion(resolvedConfig);
    http:OAuth2JwtBearerGrantConfig oauthConfig = {
        tokenUrl: resolvedConfig.tokenEndpoint,
        assertion: jwtAssertion,
        clientId: resolvedConfig.clientId
    };

    fhir:FHIRConnectorConfig connectorConfig = {
        baseURL: resolvedConfig.baseURL,
        mimeType: fhir:FHIR_JSON,
        authConfig: oauthConfig,
        urlRewrite: resolvedConfig.urlRewrite,
        replacementURL: resolvedConfig.replacementURL
    };

    fhir:FHIRConnector connector = check new (connectorConfig,
        enableCapabilityStatementValidation = resolvedConfig.validateServerCapabilities);
    fhirConnectorCache[clinicName] = connector;
    clinicConnectorSignatures[clinicName] = currentSignature;
    log:printInfo(string `Initialized FHIR connector for clinic ${clinicName}`,
        properties = {clinicName: clinicName, baseURL: resolvedConfig.baseURL});
    return connector;
}

function resolveRequestMethod(map<json>? requestMap) returns string {
    if requestMap is map<json> {
        json? methodValue = requestMap["method"];
        if methodValue is string {
            string trimmedMethod = strings:trim(methodValue);
            if trimmedMethod.length() > 0 {
                return strings:toUpperAscii(trimmedMethod);
            }
        }
    }
    return "POST";
}

function extractRequestUrl(map<json>? requestMap) returns string? {
    if requestMap is map<json> {
        json? urlValue = requestMap["url"];
        if urlValue is string {
            string trimmedUrl = strings:trim(urlValue);
            if trimmedUrl.length() > 0 {
                return trimmedUrl;
            }
        }
    }
    return ();
}

function extractIfNoneExist(map<json>? requestMap) returns string? {
    if requestMap is map<json> {
        json? conditionValue = requestMap["ifNoneExist"];
        if conditionValue is string {
            string trimmedCondition = strings:trim(conditionValue);
            if trimmedCondition.length() > 0 {
                return trimmedCondition;
            }
        }
    }
    return ();
}

function resolveResourceType(json resourcePayload) returns string {
    if resourcePayload is map<json> {
        json? typeValue = resourcePayload["resourceType"];
        if typeValue is string {
            return typeValue;
        }
    }
    return "Unknown";
}

function resolveResourceId(json resourcePayload) returns string? {
    if resourcePayload is map<json> {
        json? idValue = resourcePayload["id"];
        if idValue is string {
            string trimmedId = strings:trim(idValue);
            if trimmedId.length() > 0 {
                return trimmedId;
            }
        }
    }
    return ();
}

function resolveIdFromUrl(string? requestUrl, string resourceType) returns string? {
    if requestUrl is () {
        return ();
    }

    string sanitizedUrl = requestUrl;
    int? queryIndex = sanitizedUrl.indexOf("?");
    if queryIndex is int {
        sanitizedUrl = sanitizedUrl.substring(0, queryIndex);
    }

    if resourceType.length() > 0 && sanitizedUrl.startsWith(resourceType + "/") {
        string candidate = sanitizedUrl.substring(resourceType.length() + 1);
        if candidate.length() > 0 {
            return candidate;
        }
    }

    int? lastSlashIndex = sanitizedUrl.lastIndexOf("/");
    if lastSlashIndex is int {
        int slashIndex = lastSlashIndex;
        int idStartIndex = slashIndex + 1;
        if idStartIndex < sanitizedUrl.length() {
            string tailSegment = sanitizedUrl.substring(idStartIndex);
            if tailSegment.length() > 0 {
                return tailSegment;
            }
        }
    } else {
        if sanitizedUrl.length() > 0 {
            return sanitizedUrl;
        }
    }

    return ();
}

type ReferenceLink record {|
    string resourceType;
    string? resolvedId;
|};

type BundleEntryContext record {|
    map<json> entryMap;
    map<json> resourcePayload;
    map<json>? requestMap;
    string method;
    string resourceType;
    string? resourceId;
    string? requestUrl;
    string? fullUrl;
    string[] dependencyPlaceholders;
|};

final map<string[]> usCoreReferenceFieldMap = {
    "AllergyIntolerance": ["patient.reference", "encounter.reference", "recorder.reference", "asserter.reference"],
    "CarePlan": ["subject.reference", "encounter.reference", "author.reference", "careTeam[*].reference", "addresses[*].reference",
        "supportingInfo[*].reference", "goal[*].reference"],
    "CareTeam": ["subject.reference", "participant[*].member.reference", "encounter.reference", "managingOrganization[*].reference"],
    "Condition": ["subject.reference", "encounter.reference", "recorder.reference", "asserter.reference",
        "evidence[*].detail[*].reference"],
    "DiagnosticReport": ["subject.reference", "encounter.reference", "performer[*].reference", "resultsInterpreter[*].reference",
        "specimen[*].reference", "result[*].reference", "imagingStudy[*].reference", "basedOn[*].reference"],
    "DocumentReference": ["subject.reference", "author[*].reference", "custodian.reference", "context.encounter[*].reference",
        "context.sourcePatientInfo.reference", "relatesTo[*].target.reference"],
    "Encounter": ["subject.reference", "participant[*].individual.reference", "serviceProvider.reference", "basedOn[*].reference",
        "diagnosis[*].condition.reference"],
    "Immunization": ["patient.reference", "encounter.reference", "performer[*].actor.reference", "location.reference"],
    "MedicationRequest": ["subject.reference", "encounter.reference", "requester.reference", "performer.reference",
        "recorder.reference", "reasonReference[*].reference", "medicationReference.reference", "basedOn[*].reference"],
    "MedicationStatement": ["subject.reference", "context.reference", "informationSource.reference", "derivedFrom[*].reference",
        "basedOn[*].reference", "partOf[*].reference", "medicationReference.reference"],
    "Observation": ["subject.reference", "encounter.reference", "performer[*].reference", "specimen.reference",
        "derivedFrom[*].reference", "focus[*].reference", "basedOn[*].reference"],
    "Procedure": ["subject.reference", "encounter.reference", "performer[*].actor.reference", "reasonReference[*].reference",
        "report[*].reference", "recorder.reference", "asserter.reference", "basedOn[*].reference"],
    "ServiceRequest": ["subject.reference", "encounter.reference", "requester.reference", "performer[*].reference",
        "basedOn[*].reference", "reasonReference[*].reference", "replaces[*].reference"]
};

function extractFullUrl(map<json> entryMap) returns string? {
    json? fullUrlValue = entryMap["fullUrl"];
    if fullUrlValue is string {
        string trimmedUrl = strings:trim(fullUrlValue);
        if trimmedUrl.length() > 0 {
            return trimmedUrl;
        }
    }
    return ();
}

function appendPlaceholderIfMissing(string[] placeholders, string candidate) {
    if !containsString(placeholders, candidate) {
        placeholders.push(candidate);
    }
}

function collectReferencePlaceholders(map<json> resourcePayload, string resourceType) returns string[] {
    string[] placeholders = [];
    string[]? configuredPaths = usCoreReferenceFieldMap[resourceType];
    if configuredPaths is string[] {
        foreach string path in configuredPaths {
            collectPlaceholdersByPath(resourcePayload, path, placeholders);
        }
    }
    // Always execute a generic pass to pick up any additional references.
    collectGenericReferencePlaceholders(resourcePayload, placeholders);
    return placeholders;
}

function splitReferencePath(string path) returns string[] {
    string[] segments = [];
    int startIndex = 0;
    int pathLength = path.length();

    while startIndex < pathLength {
        int? dotIndex = strings:indexOf(path, ".", startIndex);
        if dotIndex is int {
            string segment = path.substring(startIndex, dotIndex);
            segments.push(segment);
            startIndex = dotIndex + 1;
        } else {
            string tailSegment = path.substring(startIndex);
            segments.push(tailSegment);
            break;
        }
    }

    if segments.length() == 0 {
        segments.push(path);
    }

    return segments;
}

function collectPlaceholdersByPath(map<json> resourcePayload, string path, string[] placeholders) {
    string[] segments = splitReferencePath(path);
    if segments.length() == 0 {
        return;
    }
    json node = resourcePayload;
    collectPlaceholdersForSegments(node, segments, 0, placeholders);
}

function collectPlaceholdersForSegments(json node, string[] segments, int index, string[] placeholders) {
    if index >= segments.length() {
        handlePlaceholderTerminalNode(node, placeholders);
        return;
    }

    string segment = segments[index];
    boolean iterateArray = false;
    string key = segment;

    if segment.endsWith("[*]") {
        iterateArray = true;
        key = segment.substring(0, segment.length() - 3);
    }

    if node is map<json> {
        json? nextValue = node[key];
        if nextValue is () {
            return;
        }
        if iterateArray {
            if nextValue is json[] {
                foreach json item in nextValue {
                    collectPlaceholdersForSegments(item, segments, index + 1, placeholders);
                }
            } else {
                collectPlaceholdersForSegments(nextValue, segments, index + 1, placeholders);
            }
        } else {
            collectPlaceholdersForSegments(nextValue, segments, index + 1, placeholders);
        }
    } else if node is json[] {
        foreach json item in node {
            collectPlaceholdersForSegments(item, segments, index, placeholders);
        }
    }
}

function handlePlaceholderTerminalNode(json node, string[] placeholders) {
    if node is string {
        string trimmed = strings:trim(node);
        if trimmed.startsWith("urn:uuid:") {
            appendPlaceholderIfMissing(placeholders, trimmed);
        }
        return;
    }

    if node is map<json> {
        json? referenceValue = node["reference"];
        if referenceValue is string {
            string trimmedReference = strings:trim(referenceValue);
            if trimmedReference.startsWith("urn:uuid:") {
                appendPlaceholderIfMissing(placeholders, trimmedReference);
            }
        }
    }

    if node is json[] {
        foreach json item in node {
            handlePlaceholderTerminalNode(item, placeholders);
        }
    }
}

function collectGenericReferencePlaceholders(json node, string[] placeholders) {
    if node is map<json> {
        json? referenceValue = node["reference"];
        if referenceValue is string {
            string trimmedReference = strings:trim(referenceValue);
            if trimmedReference.startsWith("urn:uuid:") {
                appendPlaceholderIfMissing(placeholders, trimmedReference);
            }
        }

        foreach string key in node.keys() {
            json? child = node[key];
            if child is json {
                collectGenericReferencePlaceholders(child, placeholders);
            }
        }
    } else if node is json[] {
        foreach json item in node {
            collectGenericReferencePlaceholders(item, placeholders);
        }
    }
}

function dependenciesResolved(string[] dependencies, map<ReferenceLink> referenceLinkMap) returns boolean {
    foreach string dependency in dependencies {
        ReferenceLink? link = referenceLinkMap[dependency];
        if link is () {
            return false;
        }
        if link.resolvedId is () {
            return false;
        }
    }
    return true;
}

function isUnresolvedDependency(string dependency, map<ReferenceLink> referenceLinkMap) returns boolean {
    ReferenceLink? link = referenceLinkMap[dependency];
    if link is ReferenceLink {
        return link.resolvedId is ();
    }
    return true;
}

function replaceResolvedReferences(map<json> resourcePayload, map<ReferenceLink> referenceLinkMap) {
    replaceReferencesRecursive(resourcePayload, referenceLinkMap);
}

function replaceReferencesRecursive(json node, map<ReferenceLink> referenceLinkMap) {
    if node is map<json> {
        json? referenceValue = node["reference"];
        if referenceValue is string {
            string trimmedReference = strings:trim(referenceValue);
            ReferenceLink? link = referenceLinkMap[trimmedReference];
            if link is ReferenceLink {
                string? resolvedId = link.resolvedId;
                if resolvedId is string {
                    node["reference"] = string `${link.resourceType}/${resolvedId}`;
                }
            }
        }

        foreach string key in node.keys() {
            json? child = node[key];
            if child is json {
                replaceReferencesRecursive(child, referenceLinkMap);
            }
        }
    } else if node is json[] {
        foreach json item in node {
            replaceReferencesRecursive(item, referenceLinkMap);
        }
    }
}

function createBaseLogContext(string clinicName, string resourceType, string method, string? resourceId) returns map<anydata> {
    map<anydata> context = {
        clinicName: clinicName,
        resourceType: resourceType,
        method: method
    };
    if resourceId is string {
        context["resourceId"] = resourceId;
    }
    return context;
}

function extractResourceIdFromResponse(fhir:FHIRResponse response, string resourceType, map<json> resourcePayload,
        string? requestUrl) returns string? {
    json|xml responseResource = response.'resource;
    if responseResource is json {
        if responseResource is map<json> {
            json? idValue = responseResource["id"];
            if idValue is string {
                string trimmedId = strings:trim(idValue);
                if trimmedId.length() > 0 {
                    return trimmedId;
                }
            }
        }
    }

    string? locationHeader = response.serverResponseHeaders["location"];
    if locationHeader is string {
        string trimmedLocation = strings:trim(locationHeader);
        if trimmedLocation.length() > 0 {
            string? derivedId = resolveIdFromUrl(trimmedLocation, resourceType);
            if derivedId is string {
                return derivedId;
            }
        }
    }

    string? payloadId = resolveResourceId(resourcePayload);
    if payloadId is string {
        return payloadId;
    }

    string? derivedFromRequest = resolveIdFromUrl(requestUrl, resourceType);
    if derivedFromRequest is string {
        return derivedFromRequest;
    }

    return ();
}

function updateReferenceLink(map<ReferenceLink> referenceLinkMap, string? placeholder, string resourceType,
        string? resourceId, string? previousResourceId = ()) {
    if placeholder is () && resourceId is () {
        return;
    }

    ReferenceLink placeholderLink = {resourceType: resourceType, resolvedId: resourceId};
    if placeholder is string {
        referenceLinkMap[placeholder] = placeholderLink;
    }

    if resourceId is () {
        return;
    }

    string resolvedId = resourceId;
    ReferenceLink resolvedLink = {resourceType: resourceType, resolvedId: resolvedId};
    string canonicalKey = string `${resourceType}/${resolvedId}`;
    referenceLinkMap[canonicalKey] = resolvedLink;

    if previousResourceId is string && previousResourceId.length() > 0 && previousResourceId != resolvedId {
        string previousKey = string `${resourceType}/${previousResourceId}`;
        referenceLinkMap[previousKey] = resolvedLink;
    }
}

function processBundleEntries(string clinicName, fhir:FHIRConnector fhirConnector,
        BundleEntryContext[] entryContexts, map<ReferenceLink> referenceLinkMap) returns error? {
    BundleEntryContext[] pendingEntries = entryContexts;

    while pendingEntries.length() > 0 {
        boolean madeProgress = false;
        BundleEntryContext[] nextCycle = [];

        foreach BundleEntryContext entryContext in pendingEntries {
            if dependenciesResolved(entryContext.dependencyPlaceholders, referenceLinkMap) {
                error? processResult = processBundleEntry(clinicName, fhirConnector, entryContext, referenceLinkMap);
                if processResult is error {
                    return processResult;
                }
                madeProgress = true;
            } else {
                nextCycle.push(entryContext);
            }
        }

        if !madeProgress {
            string[] unresolved = [];
            foreach BundleEntryContext entryContext in nextCycle {
                foreach string dependency in entryContext.dependencyPlaceholders {
                    if isUnresolvedDependency(dependency, referenceLinkMap) && !containsString(unresolved, dependency) {
                        unresolved.push(dependency);
                    }
                }
            }
            return error(string `Unable to resolve FHIR bundle dependencies for clinic ${clinicName}: unresolved references ${unresolved.toString()}`);
        }

        pendingEntries = nextCycle;
    }

    return;
}

function processBundleEntry(string clinicName, fhir:FHIRConnector fhirConnector, BundleEntryContext entryContext,
        map<ReferenceLink> referenceLinkMap) returns error? {
    map<json> resourcePayload = entryContext.resourcePayload;
    replaceResolvedReferences(resourcePayload, referenceLinkMap);

    string method = entryContext.method;
    string resourceType = entryContext.resourceType;

    string? resourceId = resolveResourceId(resourcePayload);
    string? originalResourceId = resourceId;
    if method == "PUT" && resourceId is () {
        string? derivedId = resolveIdFromUrl(entryContext.requestUrl, resourceType);
        if derivedId is string {
            resourcePayload["id"] = derivedId;
            resourceId = derivedId;
            originalResourceId = resourceId;
        }
    }
    updateReferenceLink(referenceLinkMap, entryContext.fullUrl, resourceType, resourceId);

    map<anydata> baseLogContext = createBaseLogContext(clinicName, resourceType, method, resourceId);

    if method == "POST" {
        fhir:OnCondition? condition = asOnCondition(extractIfNoneExist(entryContext.requestMap));
        fhir:FHIRResponse|fhir:FHIRError createResult = fhirConnector->create(resourcePayload, onCondition = condition);
        if createResult is fhir:FHIRResponse {
            string? createdId = extractResourceIdFromResponse(createResult, resourceType, resourcePayload,
                entryContext.requestUrl);
            if createdId is string {
                resourcePayload["id"] = createdId;
                string? previousResourceId = originalResourceId;
                resourceId = createdId;
                updateReferenceLink(referenceLinkMap, entryContext.fullUrl, resourceType, createdId, previousResourceId);
            }
            baseLogContext = createBaseLogContext(clinicName, resourceType, method, resourceId);
            logFhirSuccess("create", clinicName, baseLogContext, createResult);
        } else {
            return emitFhirError("create", clinicName, baseLogContext, createResult);
        }
    } else if method == "PUT" {
        fhir:FHIRResponse|fhir:FHIRError updateResult = fhirConnector->update(resourcePayload);
        if updateResult is fhir:FHIRResponse {
            string? updatedId = extractResourceIdFromResponse(updateResult, resourceType, resourcePayload,
                entryContext.requestUrl);
            if updatedId is string {
                resourcePayload["id"] = updatedId;
                string? previousResourceId = originalResourceId;
                resourceId = updatedId;
                updateReferenceLink(referenceLinkMap, entryContext.fullUrl, resourceType, updatedId, previousResourceId);
            }
            baseLogContext = createBaseLogContext(clinicName, resourceType, method, resourceId);
            logFhirSuccess("update", clinicName, baseLogContext, updateResult);
        } else {
            return emitFhirError("update", clinicName, baseLogContext, updateResult);
        }
    } else {
        log:printWarn(string `Skipping unsupported FHIR bundle entry method ${method}`, properties = baseLogContext);
    }

    return;
}

function asOnCondition(string? condition) returns fhir:OnCondition? {
    if condition is string {
        string trimmedCondition = strings:trim(condition);
        if trimmedCondition.length() > 0 {
            return trimmedCondition;
        }
    }
    return ();
}

function copyLogContext(map<anydata> context) returns map<anydata> {
    map<anydata> clone = {};
    foreach string key in context.keys() {
        anydata? value = context[key];
        if value is () {
            continue;
        }
        if value is anydata {
            clone[key] = value;
        }
    }
    return clone;
}

function logFhirSuccess(string action, string clinicName, map<anydata> logContext,
        fhir:FHIRResponse response) {
    map<anydata> logProperties = copyLogContext(logContext);
    logProperties["statusCode"] = response.httpStatusCode;
    log:printInfo(string `FHIR ${action} succeeded for clinic ${clinicName}`,
        properties = logProperties);
}

function emitFhirError(string action, string clinicName, map<anydata> logContext,
        fhir:FHIRError err) returns error {
    map<anydata> logProperties = copyLogContext(logContext);
    logProperties["diagnostic"] = err.message();
    log:printError(string `FHIR ${action} failed for clinic ${clinicName}`, properties = logProperties, 'error = err);
    return error(string `FHIR ${action} failed for clinic ${clinicName}: ${err.message()}`, cause = err);
}

function sendFhirBundle(string clinicName, r4:Bundle bundle) returns error? {
    fhir:FHIRConnector fhirConnector = check getOrCreateFhirConnector(clinicName);
    json bundleJson = bundle.toJson();
    io:println(bundleJson);
    if bundleJson is map<json> {
        json? entriesValue = bundleJson["entry"];
        if entriesValue is json[] {
            BundleEntryContext[] entryContexts = [];
            map<ReferenceLink> referenceLinkMap = {};

            foreach json entryValue in entriesValue {
                if entryValue is map<json> {
                    map<json> entryMap = entryValue;
                    json? resourceValue = entryMap["resource"];
                    if resourceValue is () {
                        continue;
                    }

                    if resourceValue is map<json> {
                        map<json> resourcePayload = resourceValue;
                        map<json>? requestMap = ();
                        json? requestValue = entryMap["request"];
                        if requestValue is map<json> {
                            requestMap = requestValue;
                        }

                        string method = resolveRequestMethod(requestMap);
                        string resourceType = resolveResourceType(resourcePayload);
                        string? resourceId = resolveResourceId(resourcePayload);
                        string? requestUrl = extractRequestUrl(requestMap);
                        string? fullUrl = extractFullUrl(entryMap);

                        if method == "PUT" && resourceId is () {
                            string? derivedId = resolveIdFromUrl(requestUrl, resourceType);
                            if derivedId is string {
                                resourcePayload["id"] = derivedId;
                                resourceId = derivedId;
                            }
                        }

                        string[] dependencyPlaceholders = collectReferencePlaceholders(resourcePayload, resourceType);

                        if fullUrl is string {
                            updateReferenceLink(referenceLinkMap, fullUrl, resourceType, resourceId);
                        }

                        entryContexts.push({
                            entryMap: entryMap,
                            resourcePayload: resourcePayload,
                            requestMap: requestMap,
                            method: method,
                            resourceType: resourceType,
                            resourceId: resourceId,
                            requestUrl: requestUrl,
                            fullUrl: fullUrl,
                            dependencyPlaceholders: dependencyPlaceholders
                        });
                    }
                }
            }

            if entryContexts.length() > 0 {
                return processBundleEntries(clinicName, fhirConnector, entryContexts, referenceLinkMap);
            }
            return;
        }
    }

    return error(string `Unable to process bundle entries for clinic ${clinicName}: unrecognized structure`);
}

function sanitizeXmlString(string xmlContent) returns string {
    string sanitized = xmlContent;

    if sanitized.startsWith("\u{FEFF}") {
        sanitized = sanitized.substring(1);
    }

    int? declStart = sanitized.indexOf("<?xml");
    if declStart is int {
        string prefix = sanitized.substring(0, declStart);
        if prefix.trim().length() == 0 {
            int? declEnd = sanitized.indexOf("?>", declStart);
            if declEnd is int {
                int afterDeclIndex = declEnd + 2;
                if afterDeclIndex <= sanitized.length() {
                    return sanitized.substring(afterDeclIndex);
                }
            }
        }
    }

    return sanitized;
}

function processCcdaDocument(string filePath, byte[] fileContent) returns error? {
    string? clinicNameOpt = resolveClinicName(filePath);
    if clinicNameOpt is () {
        return error(string `Unable to resolve clinic for file ${filePath}`);
    }

    string clinicName = clinicNameOpt;
    string? clinicFolderPathOpt = monitoredFolders[clinicName];
    string clinicFolderPath = clinicFolderPathOpt is string ? clinicFolderPathOpt : "";
    string documentString = check strings:fromBytes(fileContent);
    string sanitizedDocumentString = sanitizeXmlString(documentString);

    xml|error xmlPayloadResult = xmls:fromString(sanitizedDocumentString);
    if xmlPayloadResult is error {
        string diagnosticMsg = xmlPayloadResult.message();
        error? cause = xmlPayloadResult.cause();
        if cause is error {
            diagnosticMsg = cause.message();
        }

        r4:OperationOutcome operationOutcome = r4:errorToOperationOutcome(r4:createFHIRError(
            "Invalid xml document.", r4:CODE_SEVERITY_ERROR, r4:TRANSIENT_EXCEPTION,
            diagnostic = diagnosticMsg));
        json|error outcomeJson = operationOutcome.toJson();
        map<anydata> logProperties = {filePath: filePath, clinicName: clinicName};
        if clinicFolderPath.length() > 0 {
            logProperties["clinicFolderPath"] = clinicFolderPath;
        }

        if outcomeJson is json {
            logProperties["outcome"] = outcomeJson;
        } else {
            logProperties["diagnostic"] = diagnosticMsg;
        }

        log:printError("Invalid XML document.", properties = logProperties);

        return error(string `Invalid XML document at ${filePath}: ${diagnosticMsg}`);
    }

    xml xmlPayload = xmlPayloadResult;

    r4:Bundle|r4:FHIRError ccdaToFhirResult = ccdatofhir:ccdaToFhir(xmlPayload);
    if ccdaToFhirResult is r4:FHIRError {
        r4:OperationOutcome operationOutcome = r4:errorToOperationOutcome(ccdaToFhirResult);
        json|error outcomeJson = operationOutcome.toJson();
        map<anydata> logProperties = {filePath: filePath, clinicName: clinicName};
        if clinicFolderPath.length() > 0 {
            logProperties["clinicFolderPath"] = clinicFolderPath;
        }

        if outcomeJson is json {
            logProperties["outcome"] = outcomeJson;
        }

        log:printError("CCDA to FHIR conversion failed.", properties = logProperties);

        return error(string `CCDA to FHIR conversion failed for file ${filePath}`);
    }

    r4:Bundle bundle = ccdaToFhirResult;
    return sendFhirBundle(clinicName, bundle);
}

function readFileContent(stream<byte[] & readonly, io:Error?> fileStream) returns byte[]|error {
    byte[] completeContent = [];

    check fileStream.forEach(function(byte[] & readonly chunk) {
        foreach byte byteValue in chunk {
            completeContent.push(byteValue);
        }
    });

    return completeContent;
}

function processClinicDirectory(string clinicName, string clinicFolderPath) returns error? {
    ftp:Client ftpClient = check createSftpClient();
    string normalizedClinicPath = ensureLeadingSlash(normalizeDirectoryPath(clinicFolderPath));

    log:printInfo("Starting clinic folder scan.",
        properties = {clinicName: clinicName, clinicFolderPath: normalizedClinicPath});

    error? result = processDirectoryRecursively(ftpClient, clinicName, normalizedClinicPath, normalizedClinicPath);
    if result is error {
        log:printError("Clinic folder scan failed.", properties = {
            clinicName: clinicName,
            clinicFolderPath: normalizedClinicPath,
            errorMessage: result.message()
        });
        return result;
    }

    log:printDebug("Completed clinic folder scan.",
        properties = {clinicName: clinicName, clinicFolderPath: normalizedClinicPath});
}

// Process a single file using FTP client
function processFile(ftp:Client ftpClient, string clinicName, string clinicFolderPath, ftp:FileInfo file)
    returns error? {

    stream<byte[] & readonly, io:Error?> fileStream = check ftpClient->get(path = file.path);
    byte[] fileContent = check readFileContent(fileStream);

    check processCcdaDocument(file.path, fileContent);

    string targetPath = computeProcessedFilePath(file.path);
    check ensureProcessedDestination(ftpClient, targetPath);
    check ftpClient->rename(file.path, targetPath);

    log:printInfo("Moved processed file.",
        properties = {clinicName: clinicName, sourcePath: file.path, processedPath: targetPath});
}

function processDirectoryRecursively(ftp:Client ftpClient, string clinicName, string clinicFolderPath,
        string directoryPath) returns error? {

    ftp:FileInfo[] entries = check ftpClient->list(path = directoryPath);

    if entries.length() == 0 {
        log:printDebug("No entries found in directory.",
            properties = {clinicName: clinicName, directoryPath: directoryPath});
        return;
    }

    foreach ftp:FileInfo entry in entries {
        if entry.isFile {
            check processFile(ftpClient, clinicName, clinicFolderPath, entry);
        } else if !entry.isFile && !isSkippableDirectory(entry.name) {
            if isProcessedDirectory(entry.name) {
                log:printDebug("Skipping processed directory.",
                    properties = {clinicName: clinicName, directoryPath: entry.path});
                continue;
            }
            check processDirectoryRecursively(ftpClient, clinicName, clinicFolderPath, entry.path);
        }
    }
}

function computeProcessedFilePath(string filePath) returns string {
    string parentDirectory = deriveParentDirectory(filePath);
    string processedDirectory = parentDirectory == "/" ?
        "/processed" : string `${parentDirectory}/processed`;
    string fileName = extractFileName(filePath);
    return string `${processedDirectory}/${fileName}`;
}

function ensureProcessedDestination(ftp:Client ftpClient, string targetFilePath) returns error? {
    string processedDirectory = deriveParentDirectory(targetFilePath);
    if processedDirectory.length() == 0 {
        return;
    }

    check ensureRemoteDirectory(ftpClient, processedDirectory);
}

function ensureRemoteDirectory(ftp:Client ftpClient, string directoryPath) returns error? {
    if directoryPath.length() == 0 || directoryPath == "/" {
        return;
    }

    var isDirectoryResult = ftpClient->isDirectory(directoryPath);
    if isDirectoryResult is boolean {
        if isDirectoryResult {
            return;
        }
    } else {
        return isDirectoryResult;
    }

    string parentDirectory = deriveParentDirectory(directoryPath);
    if parentDirectory != directoryPath {
        check ensureRemoteDirectory(ftpClient, parentDirectory);
    }

    ftp:Error? creationResult = ftpClient->mkdir(directoryPath);
    if creationResult is ftp:Error {
        var recheckResult = ftpClient->isDirectory(directoryPath);
        if recheckResult is boolean && recheckResult {
            return;
        }
        return creationResult;
    }
}

function isProcessedDirectory(string directoryName) returns boolean {
    return strings:toLowerAscii(directoryName) == "processed";
}

function extractFileName(string filePath) returns string {
    int? lastSlashIndex = filePath.lastIndexOf("/");
    if lastSlashIndex is int {
        int index = lastSlashIndex;
        if index >= 0 && index < filePath.length() - 1 {
            return filePath.substring(index + 1);
        }
    }
    return filePath;
}

