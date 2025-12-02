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
import ballerina/lang.'string as strings;
import ballerina/log;

public function main() returns error? {
    check startClinicWorkers();
}

function startClinicWorkers() returns error? {
    if monitoredFolders.keys().length() == 0 {
        log:printWarn("No monitored folders configured for processing. Skipping worker startup.");
        return;
    }

    future<error?>[] workerFutures = [];

    foreach string clinicName in monitoredFolders.keys() {
        string? folderPathOpt = monitoredFolders[clinicName];
        if folderPathOpt is () {
            log:printWarn("Missing folder path for clinic. Skipping worker.",
                properties = {clinicName: clinicName});
            continue;
        }

        string sanitizedPath = sanitizeClinicPath(folderPathOpt);
        if sanitizedPath.length() == 0 {
            log:printWarn("Empty folder path encountered for clinic. Skipping worker.",
                properties = {clinicName: clinicName});
            continue;
        }

        future<error?> workerFuture = start processClinicWorker(clinicName, sanitizedPath);
        workerFutures.push(workerFuture);
        log:printInfo("Started clinic worker.",
            properties = {clinicName: clinicName, clinicFolderPath: sanitizedPath});
    }

    if workerFutures.length() == 0 {
        log:printWarn("No clinic workers were started. Verify monitored folder configuration.");
        return;
    }

    foreach future<error?> workerFuture in workerFutures {
        error? workerOutcome = wait workerFuture;
        if workerOutcome is error {
            return workerOutcome;
        }
    }

    log:printInfo("All clinic workers completed successfully.",
        properties = {workerCount: workerFutures.length()});
}

function processClinicWorker(string clinicName, string clinicFolderPath) returns error? {
    error? result = processClinicDirectory(clinicName, clinicFolderPath);
    if result is error {
        return result;
    }
}

function sanitizeClinicPath(string folderPath) returns string {
    string trimmed = strings:trim(folderPath);
    if trimmed.length() == 0 {
        return "";
    }
    return ensureLeadingSlash(normalizeDirectoryPath(trimmed));
}

