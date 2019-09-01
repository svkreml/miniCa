import {BER, Chars, Hex, PEM} from '../gost-coding/gost-coding';
import {GostSecurity} from '../gost-security/gost-security';
import {GostAsn1} from '../gost-asn1/gost-asn1';
import {BERtypes} from '../gost-asn1/structure/BERTypes';
import {ASN1Object} from '../gost-asn1/structure/ASN1Object';


export class Syntax {

}



export class GostViewer {






    static asn1 = new GostAsn1();

    static gostSecurity: GostSecurity = new GostSecurity();

    constructor() {
    }

    printASN1(value) {

        function hex(start, buffer: ArrayBuffer) {
            let s = '';
            let d = new Uint8Array(buffer);
            for (let i = 0; i < d.length; i++) {
                s += (i % 16 === 0 ? (i > 0 ? '' : '') + '\r\n' + start + '' : ' ') +
                    ('00' + d[i].toString(16)).slice(-2);
            }
            return s ? s + '' : '';
        }

        function childs(block: ASN1Object, offset: number, ident: string) {
            let s = '';
            let start = '             : ';
            if (block.object.length > 0) {
                s += ' {\r\n';
                block.object.forEach((child) => {
                    s += process(child, offset, ident + ' ');
                    offset += child.header.length + child.content.length;
                });
                s += start + ident + '}';
            } else {
                s += ' {}';
            }
            return s;
        }

        function process(block: ASN1Object, offset: number, ident: string) {
            if (block.tagClass > 2) {
                throw new Error('Private and Application tags is not supported');
            }
            offset = offset || 0;
            ident = ident || '';
            // type name
            let typeName: string;
            switch (block.tagClass) {
                case 0:
                    typeName = BERtypes[block.tagNumber] || 'Universal_' + block.tagNumber.toString();
                    break;
                case 1:
                    typeName = 'Application_' + block.tagNumber;
                    break;
                case 2:
                    typeName = '[' + block.tagNumber.toString() + ']'; // context-specific
                    break;
                case 3:
                    typeName = 'Private_' + block.tagNumber;
                    break;
                default:
                    throw new Error('Tag number must be in [0;3], but block.tagNumber=' + block.tagNumber);
            }

            let start = '             : ';
            let s = ('     ' + offset).slice(-5) +
                ' ' + ('00' + block.header[0].toString(16)).slice(-2) +
                ('     ' + block.content.length).slice(-5) + ': ' +
                ident + typeName;
            if (block.tagConstructed) {
                s += childs(block, offset + block.header.length, ident);
            } else {
                switch (typeName.toUpperCase()) {
                    case 'OBJECT IDENTIFIER':
                        let id = block.object;
                        let name = GostViewer.gostSecurity.names[id];
                        s += ' ' + (name ? name : '?') + ' (' + id + ')';
                        break;
                    case 'INTEGER':
                    case 'ENUMERATED':
                        if (typeof block.object === 'number') {
                            s += ' ' + block.object + '';
                        } else {
                            s += hex(start + ident + ' ', block.content);
                        }
                        break;
                    case 'GENERALIZEDTIME':
                    case 'UTCTIME':
                        s += ' ' + block.object + '';
                        break;
                    case 'PRINTABLESTRING':
                    case 'IA5STRING':
                    case 'VISIBLESTRING':
                    case 'VIDEOTEXSTRING':
                    case 'NUMERICSTRING':
                    case 'BMPSTRING':
                    case 'UTF8STRING':
                    case 'UNIVERSALSTRING':
                        s += ' "' + block.object + '"';
                        break;
                    case 'BOOLEAN':
                        s += ' ' + (block.object ? 'true' : 'false') + '';
                        break;
                    case 'OCTET STRING':
                        try {
                            s += ', encapsulates' + childs({object: [BER.decode(block.content)]} as ASN1Object,
                                offset + block.header.length, ident);
                        } catch (e) {
                            s += hex(start + ident + ' ', block.content);
                        }
                        break;
                    case 'BIT STRING':
                        s += ', unused ' + block.content[0] + ' bits';
                        if (block.object instanceof ArrayBuffer) {
                            try {
                                s += ', encapsulates' + childs({object: [BER.decode(block.object)]} as ASN1Object,
                                    offset + block.header.length, ident);
                            } catch (e) {
                                s += hex(start + ident + ' ', block.object);
                            }
                        } else {
                            s += '\r\n' + start + ident + ' ' + block.object + 'B';
                        }
                        break;
                    default:
                        try {
                            s += ', encapsulates' + childs({object: [BER.decode(block.content)]} as ASN1Object,
                                offset + block.header.length, ident);
                        } catch (e) {
                            s += hex(start + ident + ' ', block.content);
                        }
                }
            }
            return s + '\r\n';
        }


        if (typeof value === 'string') { // text
            let t = /([A-Fa-f0-9\s]+)/g.exec(value);
            if (t && t[1].length === value.length) // Hex format
            {
                value = Hex.decode(value, undefined);
            } else // PEM format
            {
                value = PEM.decode(value, undefined, undefined, undefined);
            }
        } else { // binary
            try {
                value = PEM.decode(Chars.encode(value, 'ascii'), undefined, undefined, undefined);
            } catch (e) {
            }
        }
        return process(BER.decode(value), undefined, undefined);
    }

    printSyntax(value, type: string) {

        function process(value: ASN1Object, ident) {
            ident = ident || '';
            if (typeof value === 'undefined') {
                return 'undefined';
            } else if (value instanceof Array) {
                let r = [];
                let l = 0;
                for (let i = 0, n = value.length; i < n; i++) {
                    r[i] = process(value[i], ident + '    ');
                    l += r[i].replace(/\<[^\>]+\>/g, '').length + 2;
                }
                if (l > 80) {
                    let s = '[';
                    let m = 0;
                    for (let i = 0, n = r.length; i < n; i++) {
                        s += (i > 0 ? ', ' : '') +
                            (m === 0 && l > 80 ? '\r\n' + ident + '    ' : ' ') + r[i];
                        m += r[i].replace(/\<[^\>]+\>/g, '').length + 2;
                        if (m > 80) {
                            m = 0;
                        }
                    }
                    s += l > 80 ? '\r\n' + ident + ']' : ' ]';
                    return s;
                } else {
                    return '[ ' + r.join(', ') + ' ]';
                }
            } else if (typeof value === 'string' || value instanceof String) {
                if (value.toString() === '') // null
                {
                    return 'null';
                } else {
                    return '"' + value.replace(/([\"])/g, '\\$1') + '"';
                }
            } else if (typeof value === 'number' || value instanceof Number) {
                return '' + value + '';
            } else if (value instanceof Date) {
                return '' + JSON.stringify(value) + '';
            } else if (typeof value === 'boolean' || value instanceof Boolean) {
                return '' + value + '';
            } else if (value instanceof ArrayBuffer || value instanceof Uint8Array) {
                let d = new Uint8Array(value);
                let s = '';
                for (let i = 0, n = d.length; i < n; i++) {
                    s += (i > 0 && i % 16 === 0 ? '\r\n' + ident + '    ' : ' ') +
                        '0x' + ('00' + d[i].toString(16)).slice(-2) + '' +
                        (i < n - 1 ? ',' : '');
                }
                if (d.length > 16) {
                    return '[\r\n' + ident + '   ' + s + '\r\n' + ident + ']';
                } else {
                    return '[' + s + ' ]';
                }
            } else if (typeof value === 'object') {
                let first = true;
                let s = '{';
                for (let name in value) {
                    if (typeof value[name] === 'function' || value[name] === undefined) {
                        continue;
                    }
                    let norm = /^[a-zA-Z\_][a-zA-Z0-9\_]*$/.test(name);
                    if (first) {
                        first = false;
                    } else {
                        s += ',';
                    }
                    s += '\r\n' + ident + '    ' +
                        (norm ? '' : '"') + name + (norm ? '' : '"') + ': ' +
                        process(value[name], ident + '    ');
                }
                s += (first ? '' : '\r\n' + ident) + '}';
                return s;
            }
            return 'unrecognized';
        }

        {
            if (typeof value === 'string') { // text
                let t = /([A-Fa-f0-9\s]+)/g.exec(value);
                if (t && t[1].length === value.length) // Hex format
                {
                    value = Hex.decode(value, undefined);
                } else // PEM format
                {
                    value = PEM.decode(value, undefined, undefined, undefined);
                }
            } else { // binary
                try {
                    value = PEM.decode(Chars.encode(value, 'ascii'), undefined, undefined, undefined);
                } catch (e) {
                }
            }
            if (type) {
                return process(GostViewer.asn1[type].decode(value), undefined);
            } else {
                return process(BER.decode(value), undefined);
            }


        }
    }

    /*open(header, content, item) {
         let el = document.getElementById('print');
         if (el)
             el.parentNode.removeChild(el);
         el = document.createElement('div');
         el.id = 'print';
         el.innerHTML =
             '<span class="label">' + header + '</span>' +
             '<pre class="encoded">' + content + '</pre>' +
             '<button onclick="(function(x){x.parentNode.removeChild(x);})(document.getElementById(\'print\'))">Close View</button>';
         let next = item.nextElementSibling;
         while (next.nodeName.toLowerCase() === 'button')
             next = next.nextElementSibling;
         next.parentNode.insertBefore(el, next);
     }

     openASN1(item) {
         open('ASN.1 Data', this.printASN1(item.textContent), item);
     }

     openSyntax(item, type) {
         open('Syntax ' + (type ? 'gostCrypto.asn1.' + type + '.decode(value):' :
             'gostCrypto.coding.PEM.decode(value):'), this.printSyntax(item.textContent, type), item);
     }*/
}

