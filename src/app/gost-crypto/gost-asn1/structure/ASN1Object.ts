
export class ASN1Object {
    public tagNumber;
    public object: ASN1Object[] | any;
    tagClass: number;
    header: any;
    content: any;
    tagConstructed: any;
}
