//
//  BitcoinKitPrivateSwift.swift
//
//  Copyright © 2019 BitcoinKit developers
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
//

import Foundation
import Msecp256k1
import ripemd160
import CryptoSwift

// swiftlint:disable:next type_name
class _SwiftKey {
	public static func computePublicKey(fromPrivateKey privateKey: Data, compression: Bool) -> Data {
		guard let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN)) else {
			return Data()
		}
		defer { secp256k1_context_destroy(ctx) }
		var pubkey = secp256k1_pubkey()
		var seckey: [UInt8] = privateKey.map { $0 }
		if seckey.count != 32 {
			return Data()
		}
		if secp256k1_ec_pubkey_create(ctx, &pubkey, &seckey) == 0 {
			return Data()
		}
		if compression {
			var serializedPubkey = [UInt8](repeating: 0, count: 33)
			var outputlen = 33
			if secp256k1_ec_pubkey_serialize(ctx, &serializedPubkey, &outputlen, &pubkey, UInt32(SECP256K1_EC_COMPRESSED)) == 0 {
				return Data()
			}
			if outputlen != 33 {
				return Data()
			}
			return Data(serializedPubkey)
		} else {
    		var serializedPubkey = [UInt8](repeating: 0, count: 65)
    		var outputlen = 65
    		if secp256k1_ec_pubkey_serialize(ctx, &serializedPubkey, &outputlen, &pubkey, UInt32(SECP256K1_EC_UNCOMPRESSED)) == 0 {
    			return Data()
    		}
    		if outputlen != 65 {
    			return Data()
    		}
    		return Data(serializedPubkey)
		}
	}
}

// swiftlint:disable:next type_name
class _HDKey {
	private(set) var privateKey: Data?
	private(set) var publicKey: Data
	private(set) var chainCode: Data
	private(set) var depth: UInt8
	private(set) var fingerprint: UInt32
	private(set) var childIndex: UInt32

	init(privateKey: Data?, publicKey: Data, chainCode: Data, depth: UInt8, fingerprint: UInt32, childIndex: UInt32) {
		self.privateKey = privateKey
		self.publicKey = publicKey
		self.chainCode = chainCode
		self.depth = depth
		self.fingerprint = fingerprint
		self.childIndex = childIndex
	}

	func derived(at childIndex: UInt32, hardened: Bool) -> _HDKey? {
		var data = Data()
		if hardened {
			data.append(0)
			guard let privateKey = self.privateKey else {
				return nil
			}
			data.append(privateKey)
		} else {
			data.append(publicKey)
		}
		var childIndex = CFSwapInt32HostToBig(hardened ? (0x80000000 as UInt32) | childIndex : childIndex)
		data.append(Data(bytes: &childIndex, count: MemoryLayout<UInt32>.size))
        guard var digest = _Hash.hmacsha512(data, key: self.chainCode) else { return nil }
		let derivedPrivateKey: [UInt8] = digest[0..<32].map { $0 }
		let derivedChainCode: [UInt8] = digest[32..<64].map { $0 }
		var result: Data
		if let privateKey = self.privateKey {
			guard let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN)) else {
				return nil
			}
			defer { secp256k1_context_destroy(ctx) }
			var privateKeyBytes = privateKey.map { $0 }
			var derivedPrivateKeyBytes = derivedPrivateKey.map { $0 }
			if secp256k1_ec_privkey_tweak_add(ctx, &privateKeyBytes, &derivedPrivateKeyBytes) == 0 {
				return nil
			}
			result = Data(privateKeyBytes)
		} else {
			guard let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_VERIFY)) else {
				return nil
			}
			defer { secp256k1_context_destroy(ctx) }
			let publicKeyBytes: [UInt8] = publicKey.map { $0 }
			var secpPubkey = secp256k1_pubkey()
			if secp256k1_ec_pubkey_parse(ctx, &secpPubkey, publicKeyBytes, publicKeyBytes.count) == 0 {
				return nil
			}
			if secp256k1_ec_pubkey_tweak_add(ctx, &secpPubkey, derivedPrivateKey) == 0 {
				return nil
			}
			var compressedPublicKeyBytes = [UInt8](repeating: 0, count: 33)
			var compressedPublicKeyBytesLen = 33
			if secp256k1_ec_pubkey_serialize(ctx, &compressedPublicKeyBytes, &compressedPublicKeyBytesLen, &secpPubkey, UInt32(SECP256K1_EC_COMPRESSED)) == 0 {
				return nil
			}
			result = Data(compressedPublicKeyBytes)
		}
	    let fingerPrint: UInt32 = _Hash.sha256ripemd160(publicKey).to(type: UInt32.self)
		return _HDKey(privateKey: result, publicKey: result, chainCode: Data(derivedChainCode), depth: self.depth + 1, fingerprint: fingerPrint, childIndex: childIndex)
	}
}

public class _Hash {
    public static func sha256(_ data: Data) -> Data {
        data.sha256()
    }

    public static func ripemd160(_ data: Data) -> Data {
        Data(Ripemd160.digest(data.bytes))
    }

    public static func sha256ripemd160(_ data: Data) -> Data {
        return ripemd160(sha256(data))
    }

    public static func hmacsha512(_ data: Data, key: Data) -> Data? {
//        HMAC(key: Array(key), variant: .sha2(.sha512)).authenticate(Array(data))
//        HKDF(password: Array(key), variant: .sha2(.sha512)).calculate()
        let hmac = HMAC(key: key.bytes, variant: .sha2(.sha512))
        guard let entropy = try? hmac.authenticate(data.bytes), entropy.count == 64 else { return nil }
        return Data(entropy)
    }
}

public class _Crypto {
    public static func signMessage(_ data: Data, withPrivateKey privateKey: Data) throws -> Data {
        let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN))!
        defer { secp256k1_context_destroy(ctx) }

        let signature = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 1)
        defer { signature.deallocate() }
        let status = data.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) in
            privateKey.withUnsafeBytes {
                secp256k1_ecdsa_sign(
                    ctx,
                    signature,
                    ptr.bindMemory(to: UInt8.self).baseAddress.unsafelyUnwrapped,
                    $0.bindMemory(to: UInt8.self).baseAddress.unsafelyUnwrapped,
                    nil,
                    nil
                )
            }
        }
        guard status == 1 else { throw CryptoError.signFailed }

        let normalizedsig = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 1)
        defer { normalizedsig.deallocate() }
        secp256k1_ecdsa_signature_normalize(ctx, normalizedsig, signature)

        var length: size_t = 128
        var der = Data(count: length)
        guard der.withUnsafeMutableBytes({
            return secp256k1_ecdsa_signature_serialize_der(
                ctx,
                $0.bindMemory(to: UInt8.self).baseAddress.unsafelyUnwrapped,
                &length,
                normalizedsig
            ) }) == 1 else { throw CryptoError.noEnoughSpace }
        der.count = length

        return der
    }

    public static func verifySignature(_ signature: Data, message: Data, publicKey: Data) throws -> Bool {
        let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_VERIFY))!
        defer { secp256k1_context_destroy(ctx) }

        let signaturePointer = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 1)
        defer { signaturePointer.deallocate() }
        guard signature.withUnsafeBytes({
            secp256k1_ecdsa_signature_parse_der(
                ctx,
                signaturePointer,
                $0.bindMemory(to: UInt8.self).baseAddress.unsafelyUnwrapped,
                signature.count
            )
        }) == 1 else {
            throw CryptoError.signatureParseFailed
        }

        let pubkeyPointer = UnsafeMutablePointer<secp256k1_pubkey>.allocate(capacity: 1)
        defer { pubkeyPointer.deallocate() }
        guard publicKey.withUnsafeBytes({
            secp256k1_ec_pubkey_parse(
                ctx,
                pubkeyPointer,
                $0.bindMemory(to: UInt8.self).baseAddress.unsafelyUnwrapped,
                publicKey.count
            ) }) == 1 else {
            throw CryptoError.publicKeyParseFailed
        }

        guard message.withUnsafeBytes ({
            secp256k1_ecdsa_verify(
                ctx,
                signaturePointer,
                $0.bindMemory(to: UInt8.self).baseAddress.unsafelyUnwrapped,
                pubkeyPointer) }) == 1 else {
            return false
        }

        return true
    }

    public enum CryptoError: Error {
        case signFailed
        case noEnoughSpace
        case signatureParseFailed
        case publicKeyParseFailed
    }
}
