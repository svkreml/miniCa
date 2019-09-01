
export class ASN1Object {
    public tagNumber; // see BERTypes
    public object: ASN1Object[] | any;
    tagClass: number;
    header: any;
    content: any;
    tagConstructed: any;
}
