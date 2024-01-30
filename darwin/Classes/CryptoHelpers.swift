/// MIT License
/// 
/// Copyright (c) 2016 Soyer
/// 
/// Permission is hereby granted, free of charge, to any person obtaining a
/// copy of this software and associated documentation files (the "Software"),
/// to deal in the Software without restriction, including without limitation
/// the rights to use, copy, modify, merge, publish, distribute, sublicense,
/// and/or sell copies of the Software, and to permit persons to whom the
/// Software is furnished to do so, subject to the following conditions:
/// 
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
/// 
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
/// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
/// DEALINGS IN THE SOFTWARE.

import Foundation

public enum SwError: Error {
    case invalidKey
    case badPassphrase
    case keyNotEncrypted
    case parse(String)
}

public struct SwKeyConvert {

    public struct PrivateKey {

        public static func pemToPKCS1DER(_ pemKey: String) throws -> Data {
            guard let derKey = try? PEM.PrivateKey.toDER(pemKey) else {
                throw SwError.invalidKey
            }
            guard let pkcs1DERKey = PKCS8.PrivateKey.stripHeaderIfAny(derKey) else {
                throw SwError.invalidKey
            }
            return pkcs1DERKey
        }

    }

}

private struct PKCS8 {

    struct PrivateKey {

        // https://lapo.it/asn1js/
        static func getPKCS1DEROffset(_ derKey: Data) -> Int? {
            let bytes = derKey.bytesView

            var offset = 0
            guard bytes.length > offset else { return nil }
            guard bytes[offset] == 0x30 else { return nil }

            offset += 1

            guard bytes.length > offset else { return nil }
            if bytes[offset] > 0x80 {
                offset += Int(bytes[offset]) - 0x80
            }
            offset += 1

            guard bytes.length > offset else { return nil }
            guard bytes[offset] == 0x02 else { return nil }

            offset += 3

            // without PKCS8 header
            guard bytes.length > offset else { return nil }
            if bytes[offset] == 0x02 {
                return 0
            }

            let OID: [UInt8] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                                0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]

            guard bytes.length > offset + OID.count else { return nil }
            let slice = derKey.bytesViewRange(NSRange(location: offset, length: OID.count))

            guard OID.elementsEqual(slice) else { return nil }

            offset += OID.count

            guard bytes.length > offset else { return nil }
            guard bytes[offset] == 0x04 else { return nil }

            offset += 1

            guard bytes.length > offset else { return nil }
            if bytes[offset] > 0x80 {
                offset += Int(bytes[offset]) - 0x80
            }
            offset += 1

            guard bytes.length > offset else { return nil }
            guard bytes[offset] == 0x30 else { return nil }

            return offset
        }

        static func stripHeaderIfAny(_ derKey: Data) -> Data? {
            guard let offset = getPKCS1DEROffset(derKey) else {
                return nil
            }
            return derKey.subdata(in: offset..<derKey.count)
        }

        static func hasCorrectHeader(_ derKey: Data) -> Bool {
            return getPKCS1DEROffset(derKey) != nil
        }

    }

}

private struct PEM {

    struct PrivateKey {

        static func toDER(_ pemKey: String) throws -> Data {
            guard let strippedKey = stripHeader(pemKey) else {
                throw SwError.parse("header")
            }
            guard let data = PEM.base64Decode(strippedKey) else {
                throw SwError.parse("base64decode")
            }
            return data
        }

        static let prefix = "-----BEGIN PRIVATE KEY-----\n"
        static let suffix = "\n-----END PRIVATE KEY-----"
        static let rsaPrefix = "-----BEGIN RSA PRIVATE KEY-----\n"
        static let rsaSuffix = "\n-----END RSA PRIVATE KEY-----"

        static func stripHeader(_ pemKey: String) -> String? {
            return PEM.stripHeaderFooter(pemKey, header: prefix, footer: suffix) ??
                PEM.stripHeaderFooter(pemKey, header: rsaPrefix, footer: rsaSuffix)
        }

    }

    static func stripHeaderFooter(_ data: String, header: String, footer: String) -> String? {
        guard data.hasPrefix(header) else {
            return nil
        }
        guard let r = data.range(of: footer) else {
            return nil
        }
        return String(data[header.endIndex ..< r.lowerBound])
    }

    static func base64Decode(_ base64Data: String) -> Data? {
        return Data(base64Encoded: base64Data, options: [.ignoreUnknownCharacters])
    }

}

private extension Data {

    var bytesView: BytesView { return BytesView(self) }

    func bytesViewRange(_ range: NSRange) -> BytesView {
        return BytesView(self, range: range)
    }

    struct BytesView: Collection {
        // The view retains the Data. That's on purpose.
        // Data doesn't retain the view, so there's no loop.
        let data: Data
        init(_ data: Data) {
            self.data = data
            self.startIndex = 0
            self.endIndex = data.count
        }

        init(_ data: Data, range: NSRange ) {
            self.data = data
            self.startIndex = range.location
            self.endIndex = range.location + range.length
        }

        subscript (position: Int) -> UInt8 {
            return data.withUnsafeBytes({ dataBytes -> UInt8 in
                dataBytes.bindMemory(to: UInt8.self)[position]
            })
        }
        subscript (bounds: Range<Int>) -> Data {
            return data.subdata(in: bounds)
        }
        fileprivate func formIndex(after i: inout Int) {
            i += 1
        }
        fileprivate func index(after i: Int) -> Int {
            return i + 1
        }
        var startIndex: Int
        var endIndex: Int
        var length: Int { return endIndex - startIndex }
    }

}
