import {BERtypes} from '../../gost-viewer/BERTypes';
import {GostAsn1} from '../gost-asn1';
import {BERElement} from 'asn1-ts';
import {Asn1ServiceFunctions} from '../Asn1ServiceFunctions';


export class ASN1Object {
    public tagNumber;
    public object: ASN1Object[] | any;
    tagClass: number;
    header: any;
    content: any;
    tagConstructed: any;


    set(object) {

    }

    get(object) {

    }

    encode(): ASN1Object[] | any {
        return this.object;
    }

    decode(source) {
        return new ASN1Object();
    }
}

export class PRIMITIVE extends ASN1Object {

    constructor(tagNumber) {
        super();
        this.tagNumber = tagNumber;
    }
}
export class IA5String extends PRIMITIVE{

    constructor(object) {
        super(0x16);
        this.object = object;
    }

}
// tslint:disable-next-line:class-name
export class PRIMITIVE_CODE extends PRIMITIVE {

    constructor(tagNumber) {
        super(tagNumber);
    }

    /*
    *         // Base class primitive
        var Class = extend(PRIMITIVE(tagNumber), function (object) {
            if (this instanceof Class)
                Class.super.apply(this, arguments);
            else
                return CODE(object);
        });

        // Create Class with encoded
        function CODE(structure) {
            // Structured class
            return extend(PRIMITIVE(tagNumber), function (object) {
                Class.super.call(this, object);
            }, {
                // Transformation to code values
                encode: function (format) {
                    return encode(format, structure[this.object], tagNumber);
                }
            }, {
                decode: function (source) {
                    var id = decode(source, tagNumber);
                    for (var name in structure)
                        if (id === structure[name])
                            return new this(name);
                    assert(true);
                }
            });
        }*/
}

// tslint:disable-next-line:class-name
export class OCTET_STRING extends PRIMITIVE {
    constructor() {
        super(0x04);
    }

    /*
    *         function WRAPPING(WrappedClass) {
            if (WrappedClass) {
                return extend(WrappedClass, {
                    encode: function (format) {
                        return encode(format, WrappedClass.method('encode').call(this, true), 0x04);
                    }
                }, {
                    decode: function (source) {
                        return WrappedClass.decode.call(this, decode(source, 0x04));
                    }
                });
            } else
                return Class;
        }
        return Class;
    }*/
}

// tslint:disable-next-line:class-name
export class BIT_STRING extends PRIMITIVE {
    constructor() {
        super(0x03);
    }

    /*
        // Create new class for a mask
        function MASK(structure) {
            // Bit string masked class
            return extend(ASN1Object, function (object, numbits) {
                ASN1Object.call(this, object);
                this.numbits = numbits || 0;
            }, {
                encode: function (format) {
                    var object = this.object, data = [];
                    if (object instanceof Array) {
                        for (var i = 0, n = object.length; i < n; i++) {
                            var j = structure[object[i]];
                            if (j !== undefined)
                                data[j] = '1';
                        }
                        for (var i = 0, n = Math.max(data.length, this.numbits); i < n; i++)
                            if (!data[i])
                                data[i] = '0';
                        data = data.join('');
                    } else
                        data = '0';
                    return encode(format, data, 0x03);
                }
            }, {
                // Transformation to array of values
                decode: function (source) {
                    var data = decode(source, 0x03), object = [];
                    for (var name in structure) {
                        var i = structure[name];
                        if (data.charAt(i) === '1')
                            object.push(name);
                    }
                    return new this(object, data.length);
                }
            });
        }

        return Class;
    })();
    * */
}

export class SEQUENCE<T> extends PRIMITIVE {


    constructor(value: T) {
        super(BERtypes.SEQUENCE);

        for (let name in value) {
            let name1 = value[name].constructor.name;
            this.object.push(new GostAsn1[name1](value[name]));
        }
    }

    static decode(value) {


    }
}


/*
export class ATTRIBUTE extends SEQUENCE {

}
*/

// tslint:disable-next-line:class-name
export class OBJECT_IDENTIFIER extends ASN1Object {

}

export class IMPLICIT {

}

export class EXPLICIT {

}

export class CTX {

}

export class ENCLOSURE extends ASN1Object {

}

// tslint:disable-next-line:class-name
export class ARRAY_OF extends ASN1Object {

    constructor(tagNumber) {
        super();
        this.tagNumber = tagNumber;
    }
}// tslint:disable-next-line:class-name
export class CHOICE extends ASN1Object {

    constructor(tagNumber) {
        super();
        this.tagNumber = tagNumber;
    }
}




export class OPTIONAL<T> {
    object: T;
    constructor(object: T) {
        this.object = object;
    }

    static decode(extElem1: any) {
        return (extElem1) ? new OPTIONAL(extElem1) : undefined;
    }
}
/*
    // Call set method for a class property
    _set: function (Class, propName, value) {
        Class.property(propName).set.call(this, value);
    },
// Call get method for a class property
    _get: function (Class, propName) {
        return Class.property(propName).get.call(this);
    },
// Call method for a class
    _call: function (Class, methodName, args) {
        return Class.method(methodName).apply(this, args);
    },
    hasProperty: function (propName) {
        return this.hasOwnProperty(propName) ||
            !!this.constructor.property(propName);
    },
    encode: function () {
        return this.object;
    }
}, {
    decode: function (source) {
        return new this(source);
    },*/
















