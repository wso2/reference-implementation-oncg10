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
import ballerina/ftp;
import ballerina/io;

// SFTP file monitoring service object
final ftp:Service sftpService = service object {
    remote function onFileChange(ftp:WatchEvent & readonly fileEvent, ftp:Caller caller) returns error? {
        io:println("onFileChange triggered!");
        io:println(string `Received file event - Added: ${fileEvent.addedFiles.length()}, Deleted: ${fileEvent.deletedFiles.length()}`);
        check processFileChange(fileEvent, caller);
    }
};

// Process file change events
function processFileChange(ftp:WatchEvent & readonly fileEvent, ftp:Caller caller) returns error? {
    foreach ftp:FileInfo addedFile in fileEvent.addedFiles {
        io:println(string `File added: ${addedFile.name} at path: ${addedFile.path}`);
        
        // Read file content
        stream<byte[] & readonly, io:Error?> fileStream = check caller->get(path = addedFile.path);
        byte[] fileContent = check readFileContent(fileStream);
        
        io:println(string `File size: ${fileContent.length()} bytes`);
        
        check processCcdaDocument(addedFile.path, fileContent);
    }
    
    foreach string deletedFile in fileEvent.deletedFiles {
        io:println(string `File deleted: ${deletedFile}`);
    }
}

// Read complete file content from stream
function readFileContent(stream<byte[] & readonly, io:Error?> fileStream) returns byte[]|error {
    byte[] completeContent = [];
    
    check fileStream.forEach(function(byte[] & readonly chunk) {
        foreach byte byteValue in chunk {
            completeContent.push(byteValue);
        }
    });
    
    return completeContent;
}
