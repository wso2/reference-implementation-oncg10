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

import ballerina/io;
import ballerina/lang.runtime;

public function main() returns error? {
    io:println("SFTP listeners started for monitoring folders...");
    io:println(string `Monitoring ${folderPaths.length()} folder(s)`);
    
    foreach string folderPath in folderPaths {
        io:println(string `  - ${folderPath}`);
    }
    
    // Initialize and start FTP listeners
    check startFtpListeners();
    
    io:println("All SFTP listeners are active and monitoring for file changes...");
    
    // Keep the program running so listeners can continue monitoring
    future<error?> blocker = start keepAlive();
    check wait blocker;
}

function keepAlive() returns error? {
    // Block indefinitely - this keeps main() from returning
    while true {
        // Infinite loop to keep the program alive
        // In practice, the listeners handle the actual work
        runtime:sleep(1000); // Sleep for 1 second to avoid CPU-intensive busy wait
    }
}
