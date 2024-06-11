import { AsnProp, AsnPropTypes, AsnType, AsnTypeTypes, AsnArray, AsnConvert, AsnSerializer } from "@peculiar/asn1-schema";
import { DigestAlgorithmIdentifier, Attribute, SignedAttributes, ContentInfo,SignedData } from "@peculiar/asn1-cms";
import { expect } from "chai";
import "mocha";

import * as assert from "assert";
import { Convert } from "pvtsutils";
import { LDSSecurityObject, LDSSecurityObjectVersion, DataGroupHash, DataGroupNumber } from "../src/sod";

context("SOD", () => {

  it("parse SOD", () => {
    // from https://github.com/ZeroPass/pymrtd/blob/master/tests/ef/sod_test.py
    // stripped
    const pem = 
      "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" +
      "2lQaWKGlcudYPw==";

    console.log(Convert.ToHex(Convert.FromBase64(pem)));

    const contentInfo = AsnConvert.parse(Convert.FromBase64(pem), ContentInfo);
  /** 
      const ldsSecurityObject = new LDSSecurityObject();
      ldsSecurityObject.version = LDSSecurityObjectVersion.v0;
      ldsSecurityObject.hashAlgorithm = new DigestAlgorithmIdentifier({
        algorithm: "1.2.840.113549.1.1.11"
      });

      ldsSecurityObject.dataGroupHashValues = [
        new DataGroupHash({
          dataGroupNumber: DataGroupNumber.dataGroup1,
          dataGroupHashValue: new ArrayBuffer(0)
        })
      ];

      const s = Buffer.from(AsnSerializer.serialize(ldsSecurityObject)).toString("hex");
      console.log(s);

    const contentInfo = AsnConvert.parse(Convert.FromBase64(pem), ContentInfo);

    const signedData = AsnConvert.parse(contentInfo.content, SignedData);
    assert.strictEqual(!!signedData, true);

    const signer = signedData.signerInfos[0];
    assert.strictEqual(signer.version, 1);
    assert.ok(true);
    */
  });

});