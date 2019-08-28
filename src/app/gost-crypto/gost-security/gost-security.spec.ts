import {GostSecurity} from './gost-security';

describe('GostSecurity', () => {
    it('should create an instance', () => {
        expect(new GostSecurity()).toBeTruthy();
    });


    it('iterate', () => {
        const gostSecurity = new GostSecurity();
        console.log('---------names----------');

        let names = 0;
        let identifiers = 0;
        // tslint:disable-next-line:forin
        for (const id in gostSecurity.names) {
            console.log(id + ' : ' + gostSecurity.names[id]);
            names++;
        }
        console.log('---------identifiers----------');

        // tslint:disable-next-line:forin
        for (const id in gostSecurity.identifiers) {
            console.log(id + ' : ' + gostSecurity.identifiers[id]);
            identifiers++;
        }

        expect(identifiers === names).toBeTruthy();
    });
});
