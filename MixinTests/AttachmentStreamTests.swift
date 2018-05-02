import XCTest

class AttachmentStreamTests: XCTestCase {
    
    let numberOfTestPairs = 48
    
    var plains = [Data]()
    
    let plainFolderName = "plain"
    let decryptedFolderName = "decrypted"
    
    override func setUp() {
        super.setUp()
        
        for fileSize in 0...numberOfTestPairs {
            let content = Array(repeating: 0, count: fileSize).map({ String($0) }).joined()
            let data = content.data(using: .utf8)!
            plains.append(data)
        }
        
        print("Did setup testing on folder: \(fileURL(forFolder: nil, name: nil).path)\n")
    }
    
    func testEncryption() {
        // Make folder
        let plainFolder = fileURL(forFolder: plainFolderName, name: nil)
        if FileManager.default.fileExists(atPath: plainFolder.path) {
            try! FileManager.default.removeItem(at: plainFolder)
        }
        try! FileManager.default.createDirectory(at: plainFolder, withIntermediateDirectories: false, attributes: nil)
        // Make files and datas
        var plainFileURLs = [URL]()
        for i in 0...numberOfTestPairs {
            let url = fileURL(forFolder: plainFolderName, name: "\(i).bin")
            try! plains[i].write(to: url)
            plainFileURLs.append(url)
        }
        // Test
        for readingChunkSize in [128, 4096] {
            let encryptingStreams = plainFileURLs.flatMap{ AttachmentEncryptingInputStream(url: $0) }
            XCTAssertEqual(encryptingStreams.count, plainFileURLs.count)
            XCTAssertEqual(encryptingStreams.count, plains.count)
            for (index, stream) in encryptingStreams.enumerated() {
                let encrypted = Data(reading: stream, bufferSize: readingChunkSize)
                var error: NSError?
                let originalData = plains[index]
                let decrypted = Cryptography.decryptAttachment(encrypted, withKey: stream.key!, digest: stream.digest, unpaddedSize: UInt32(originalData.count), error: &error)
                XCTAssertNil(error)
                XCTAssertEqual(decrypted, originalData)
            }
        }
    }
    
    func testDecryption() {
        // Make folder
        let decryptedFolder = fileURL(forFolder: decryptedFolderName, name: nil)
        if FileManager.default.fileExists(atPath: decryptedFolder.path) {
            try! FileManager.default.removeItem(at: decryptedFolder)
        }
        try! FileManager.default.createDirectory(at: decryptedFolder, withIntermediateDirectories: false, attributes: nil)
        // Make datas
        var ciphers = [Data]()
        var keys = [Data]()
        var digests = [Data]()
        var decryptedFileURLs = [URL]()
        for i in 0...numberOfTestPairs {
            var key: NSData?
            var digest: NSData?
            let encrypted = Cryptography.encryptAttachmentData(plains[i], outKey: &key, outDigest: &digest)
            if case let key? = key as Data?, case let digest? = digest as Data? {
                ciphers.append(encrypted)
                keys.append(key)
                digests.append(digest)
                decryptedFileURLs.append(fileURL(forFolder: decryptedFolderName, name: "\(i).bin"))
            }
        }
        // Test
        for writingChunkSize in [128, 4096] {
            let decryptingStreams = decryptedFileURLs.enumerated().flatMap({
                AttachmentDecryptingOutputStream(url: $0.element, key: keys[$0.offset], digest: digests[$0.offset])
            })
            XCTAssertEqual(decryptingStreams.count, decryptedFileURLs.count)
            for (index, stream) in decryptingStreams.enumerated() {
                stream.open()
                let cipher = ciphers[index]
                var position = 0
                while position < cipher.count {
                    let startIndex = cipher.startIndex.advanced(by: position)
                    let endIndex = min(cipher.endIndex, startIndex.advanced(by: writingChunkSize))
                    let data = cipher[startIndex..<endIndex]
                    _ = data.withUnsafeBytes {
                        stream.write($0, maxLength: data.count)
                    }
                    position += writingChunkSize
                }
                stream.close()
                let decrypted = try! Data(contentsOf: decryptedFileURLs[index])
                XCTAssertNil(stream.streamError)
                XCTAssertEqual(decrypted, plains[index])
            }
        }
    }
    
    private func fileURL(forFolder folder: String?, name: String?) -> URL {
        let path = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        let filename: String
        if let folder = folder {
            if let name = name {
                filename = folder + "/" + name
            } else {
                filename = folder
            }
        } else {
            filename = (name ?? "")
        }
        return path.appendingPathComponent(filename)
    }
    
}

extension Data {
    
    init(reading input: InputStream, bufferSize: Int) {
        self.init()
        input.open()
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        while input.hasBytesAvailable {
            let read = input.read(buffer, maxLength: bufferSize)
            self.append(buffer, count: read)
        }
        buffer.deallocate(capacity: bufferSize)
        input.close()
    }
    
}
