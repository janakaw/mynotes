import Foundation

/// 160-bit random recovery code, shown as 32 Crockford base32 characters in groups of 4.
/// Example: 7Q2M-K9XA-…  Decoding ignores case, spaces and dashes, and maps O→0, I/L→1.
public enum RecoveryCode {
    public static let byteCount = 20
    private static let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")

    public static func encode(_ bytes: [UInt8]) -> String {
        var value = 0
        var bits = 0
        var chars: [Character] = []
        for byte in bytes {
            value = (value << 8) | Int(byte)
            bits += 8
            while bits >= 5 {
                bits -= 5
                chars.append(alphabet[(value >> bits) & 31])
            }
            value &= (1 << bits) - 1
        }
        if bits > 0 {
            chars.append(alphabet[(value << (5 - bits)) & 31])
        }
        var grouped = ""
        for (index, char) in chars.enumerated() {
            if index > 0 && index % 4 == 0 { grouped.append("-") }
            grouped.append(char)
        }
        return grouped
    }

    public static func decode(_ text: String) -> [UInt8]? {
        var value = 0
        var bits = 0
        var out: [UInt8] = []
        for raw in text.uppercased() {
            if raw == "-" || raw.isWhitespace { continue }
            let char: Character
            switch raw {
            case "O": char = "0"
            case "I", "L": char = "1"
            default: char = raw
            }
            guard let index = alphabet.firstIndex(of: char) else { return nil }
            value = (value << 5) | index
            bits += 5
            if bits >= 8 {
                bits -= 8
                out.append(UInt8((value >> bits) & 0xFF))
                value &= (1 << bits) - 1
            }
        }
        return out.count == byteCount ? out : nil
    }
}
