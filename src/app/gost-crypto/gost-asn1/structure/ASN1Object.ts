export class ASN1Object {
    public tagNumber;
    public object: ASN1Object[]| any;
    tagClass: number;
    header: any;
    content: any;
    tagConstructed: any;

    set(object) {

    }
    get(object) {

    }

    encode(){

    }

    decode(){

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
}















