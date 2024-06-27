# mrtd-ts

## Usage

Parse the EF.SOD element.

```
const pem = "MIIHhgYJKoZIhv ... 2lQaWKGlcudYPw==";
const contentInfo = AsnConvert.parse(Convert.FromBase64(pem), ContentInfo);
const signedData = AsnConvert.parse(contentInfo.content, SignedData);
const securityObject = AsnConvert.parse(signedData.encapContentInfo.eContent.single, LDSSecurityObject);

console.log(securityObject);
```

# Output

```
LDSSecurityObject {
  version: 0,
  hashAlgorithm: DigestAlgorithmIdentifier {
    algorithm: '2.16.840.1.101.3.4.2.1',
    parameters: null
  },
  dataGroupHashValues: [
    DataGroupHash {
      dataGroupNumber: 1,
      dataGroupHashValue: [Uint8Array]
    },
    DataGroupHash {
      dataGroupNumber: 2,
      dataGroupHashValue: [Uint8Array]
    },
    DataGroupHash {
      dataGroupNumber: 3,
      dataGroupHashValue: [Uint8Array]
    },
    DataGroupHash {
      dataGroupNumber: 14,
      dataGroupHashValue: [Uint8Array]
    },
    DataGroupHash {
      dataGroupNumber: 4,
      dataGroupHashValue: [Uint8Array]
    }
  ]
}
```