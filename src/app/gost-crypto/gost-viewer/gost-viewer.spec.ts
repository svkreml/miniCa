import {GostViewer} from './gost-viewer';

describe('GostViewer', () => {
    let cert: string = '-----BEGIN CERTIFICATE-----\n' +
        'MIIEdjCCBCOgAwIBAgIBATAKBggqhQMHAQEDAjCB8TELMAkGA1UEBhMCUlUxKjAoBgNVBAgMIdCh0LDQvdC60YLRii3Qn9C1\n' +
        '0YLQtdGA0LHRg9GA0LPRijEuMCwGA1UECgwl0JbRg9GA0L3QsNC7ICLQodC+0LLRgNC10LzQtdC90L3QuNC6IjEfMB0GA1UE\n' +
        'CwwW0KDRg9C60L7QstC+0LTRgdGC0LLQvjEoMCYGA1UEDAwf0JPQu9Cw0LLQvdGL0Lkg0YDQtdC00LDQutGC0L7RgDE7MDkG\n' +
        'A1UEAwwy0JDQu9C10LrRgdCw0L3QtNGAINCh0LXRgNCz0LXQtdCy0LjRhyDQn9GD0YjQutC40L0wHhcNMTQxMjA0MjEwMDAw\n' +
        'WhcNMzQxMjA0MjEwMDAwWjCB8TELMAkGA1UEBhMCUlUxKjAoBgNVBAgMIdCh0LDQvdC60YLRii3Qn9C10YLQtdGA0LHRg9GA\n' +
        '0LPRijEuMCwGA1UECgwl0JbRg9GA0L3QsNC7ICLQodC+0LLRgNC10LzQtdC90L3QuNC6IjEfMB0GA1UECwwW0KDRg9C60L7Q\n' +
        'stC+0LTRgdGC0LLQvjEoMCYGA1UEDAwf0JPQu9Cw0LLQvdGL0Lkg0YDQtdC00LDQutGC0L7RgDE7MDkGA1UEAwwy0JDQu9C1\n' +
        '0LrRgdCw0L3QtNGAINCh0LXRgNCz0LXQtdCy0LjRhyDQn9GD0YjQutC40L0wZjAfBggqhQMHAQEBATATBgcqhQMCAiQABggq\n' +
        'hQMHAQECAgNDAARAQUCQNg5eYYIcxtaREQRxu/DjXzHflHl+6V0k62fEOKHFqiPC/zO6lSd5Nm6an8Z28owrasJdYX/B8xBQ\n' +
        'NDVnG6OCAZswggGXMA4GA1UdDwEBAQQEAwIB/jAxBgNVHSUEKjAoBggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMDBggr\n' +
        'BgEFBQcDBDAPBgNVHRMBAQEEBTADAQEBMB0GA1UdDgQWBBSdYVnKqBWdaajYbstN3tOx3IvQszCCASAGA1UdIwSCARcwggET\n' +
        'gBSdYVnKqBWdaajYbstN3tOx3IvQs6GB96SB9DCB8TELMAkGA1UEBhMCUlUxKjAoBgNVBAgMIdCh0LDQvdC60YLRii3Qn9C1\n' +
        '0YLQtdGA0LHRg9GA0LPRijEuMCwGA1UECgwl0JbRg9GA0L3QsNC7ICLQodC+0LLRgNC10LzQtdC90L3QuNC6IjEfMB0GA1UE\n' +
        'CwwW0KDRg9C60L7QstC+0LTRgdGC0LLQvjEoMCYGA1UEDAwf0JPQu9Cw0LLQvdGL0Lkg0YDQtdC00LDQutGC0L7RgDE7MDkG\n' +
        'A1UEAwwy0JDQu9C10LrRgdCw0L3QtNGAINCh0LXRgNCz0LXQtdCy0LjRhyDQn9GD0YjQutC40L2CAQEwCgYIKoUDBwEBAwID\n' +
        'QQAEv5zJHKm0mhANAf+AtQ0c73VAvtldxhH2rUBxUBt5BDc2OZBpjsw7uFnK0W6EXRmrEVuVzcspeGIsjYOtTBNa\n' +
        '-----END CERTIFICATE-----';

    it('should create an instance', () => {
        expect(new GostViewer()).toBeTruthy();
    });


    it('print cert asn1', () => {
        let gostViewer: GostViewer = new GostViewer();

        console.log('\n' + gostViewer.printASN1(cert));
        expect(new GostViewer()).toBeTruthy();
    });

    it('print cert json', () => {
        let gostViewer: GostViewer = new GostViewer();
        let printSyntax = gostViewer.printSyntax(cert, undefined);
        console.log('\n' + printSyntax);
        expect(new GostViewer()).toBeTruthy();
    });
});
