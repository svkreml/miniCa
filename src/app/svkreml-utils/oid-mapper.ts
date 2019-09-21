import {ObjectIdentifier} from 'asn1-ts';
import {BERtypes} from '../gost-crypto/gost-asn1/structure/BERTypes';

export class OidInfo {
    oid: ObjectIdentifier;
    tag: number;
    symbol: string;
    name: string;

    constructor(oid: ObjectIdentifier, tag: number, symbol: string, name: string) {
        this.oid = oid;
        this.tag = tag;
        this.symbol = symbol;
        this.name = name;
    }

    get oidString(): string {
        return this.oid.dotDelimitedNotation;
    }
}

export class OidMapper {
    static commonName = new OidInfo(new ObjectIdentifier([2, 5, 4, 3]), BERtypes.UTF8String, 'CN', 'Common Name');
    static countryName = new OidInfo(new ObjectIdentifier([2, 5, 4, 6]), BERtypes.PrintableString, 'CN', 'Country Name');
    static streetAddress = new OidInfo(new ObjectIdentifier([2, 5, 4, 9]), BERtypes.UTF8String, 'STREET', 'Street Address');
    // TODO and Much more...
}




/*
* 	    protected ASN1Encodable encodeStringValue(ASN1ObjectIdentifier oid,
    		String value) {
    	if (oid.equals(EmailAddress) || oid.equals(DC))
        {
            return new DERIA5String(value);
        }
        else if (oid.equals(DATE_OF_BIRTH))  // accept time string as well as # (for compatibility)
        {
            return new ASN1GeneralizedTime(value);
        }
        else if (oid.equals(C) || oid.equals(SN) || oid.equals(DN_QUALIFIER)
            || oid.equals(TELEPHONE_NUMBER))
        {
            return new DERPrintableString(value);
        }

    	return super.encodeStringValue(oid, value);
    }
*
* */
