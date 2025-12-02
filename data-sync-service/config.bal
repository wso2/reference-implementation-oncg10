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

// SFTP connection configuration
configurable string sftpHost = ?;
configurable int sftpPort = 22;
configurable string sftpUsername = ?;
configurable string sftpPassword = ?;

// Mapping from clinic name to the corresponding folder path to monitor
configurable map<string> monitoredFolders = ?;

// Mapping from clinic name to resolver configuration for FHIR connector
configurable map<ClinicFhirConnectorConfig> clinicFhirConfigs = ?;
