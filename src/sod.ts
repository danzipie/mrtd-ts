import { AsnProp, AsnPropTypes, AsnType, AsnTypeTypes, AsnArray } from "@peculiar/asn1-schema";
import { DigestAlgorithmIdentifier, Attribute } from "@peculiar/asn1-cms";
import { DataGroupNumber, LDSSecurityObjectVersion } from "./types";

export const id_ldsSecurityObject = '2.23.136.1.1.1';

/**
 * ```asn
 * AttributeSet ::= SET OF Attribute
 * ```
 */
@AsnType({type: AsnTypeTypes.Set, itemType: Attribute})
export class AttributeSet extends AsnArray<Attribute> {

  constructor(items?: Attribute[]) {
    super(items);

    // Set the prototype explicitly.
    Object.setPrototypeOf(this, AttributeSet.prototype);
  }

}

@AsnType({type: AsnTypeTypes.Choice})
export class LdsSecurityObjectIdentifier {
  @AsnProp({ type: AsnPropTypes.ObjectIdentifier })
  public value: string = '';

  constructor(value?: string) {
    if (value) {
      if (typeof value === "string") {
        this.value = value;
      } else {
        Object.assign(this, value);
      }
    }
  }
}

/**
 * DataGroupHash ::= SEQUENCE {
 *  dataGroupNumber DataGroupNumber,
 *  dataGroupHashValue OCTET STRING }
 */
export class DataGroupHash {
  @AsnProp({ type: AsnPropTypes.Integer })
  public dataGroupNumber: DataGroupNumber = DataGroupNumber.dataGroup1;

  @AsnProp({ type: AsnPropTypes.OctetString })
  public dataGroupHashValue: ArrayBuffer = new ArrayBuffer(0);

  public constructor(params: Partial<DataGroupHash> = {}) {
    Object.assign(this, params);
  }
}

/**
 * LDSSecurityObject ::= SEQUENCE {
 * version LDSSecurityObjectVersion,
 * hashAlgorithm DigestAlgorithmIdentifier,
 * dataGroupHashValues SEQUENCE SIZE (2..ub-DataGroups) OF
 * DataGroupHash}
 */
export class LDSSecurityObject {
    @AsnProp({ type: AsnPropTypes.Integer })
    public version: LDSSecurityObjectVersion = LDSSecurityObjectVersion.v1;
  
    @AsnProp({ type: DigestAlgorithmIdentifier })
    public hashAlgorithm: DigestAlgorithmIdentifier = new DigestAlgorithmIdentifier()
  
    @AsnProp({ type: DataGroupHash, repeated: "sequence" })
    public dataGroupHashValues: DataGroupHash[] = [];
  
    public constructor(params: Partial<LDSSecurityObject> = {}) {
      Object.assign(this, params);
    }
}
