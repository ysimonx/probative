import XCTest

@testable import AttestedCaptureCore

/// Conformité de l'encodeur aux exemples normatifs (RFC 8949, annexe A).
/// Les vecteurs d'or du vérificateur couvrent le format réel ; ces cas
/// couvrent les frontières que le format n'exerce pas encore.
final class CborTests: XCTestCase {

    private func hex(_ value: CborValue) -> String {
        Cbor.encode(value).map { String(format: "%02x", $0) }.joined()
    }

    func testEntiersEnFormeLaPlusCourte() {
        XCTAssertEqual(hex(0), "00")
        XCTAssertEqual(hex(23), "17")
        XCTAssertEqual(hex(24), "1818")
        XCTAssertEqual(hex(100), "1864")
        XCTAssertEqual(hex(1_000_000), "1a000f4240")
        XCTAssertEqual(hex(1_000_000_000_000), "1b000000e8d4a51000")
        XCTAssertEqual(hex(-1), "20")
        XCTAssertEqual(hex(-1000), "3903e7")
    }

    func testFlottantsEnFormeLaPlusCourte() {
        XCTAssertEqual(hex(0.0), "f90000")
        XCTAssertEqual(hex(.double(-0.0)), "f98000")
        XCTAssertEqual(hex(1.0), "f93c00")
        XCTAssertEqual(hex(1.5), "f93e00")
        XCTAssertEqual(hex(65504.0), "f97bff")
        XCTAssertEqual(hex(.double(5.960464477539063e-8)), "f90001")
        XCTAssertEqual(hex(.double(0.00006103515625)), "f90400")
        XCTAssertEqual(hex(.double(-4.0)), "f9c400")
        XCTAssertEqual(hex(100000.0), "fa47c35000")
        XCTAssertEqual(hex(.double(3.4028234663852886e38)), "fa7f7fffff")
        XCTAssertEqual(hex(1.1), "fb3ff199999999999a")
        XCTAssertEqual(hex(.double(.infinity)), "f97c00")
        XCTAssertEqual(hex(.double(-.infinity)), "f9fc00")
        XCTAssertEqual(hex(.double(.nan)), "f97e00")
    }

    func testChainesOctetsTableaux() {
        XCTAssertEqual(hex(""), "60")
        XCTAssertEqual(hex("IETF"), "6449455446")
        XCTAssertEqual(hex(.bytes(Data([1, 2, 3, 4]))), "4401020304")
        XCTAssertEqual(hex([]), "80")
        XCTAssertEqual(hex([1, 2, 3]), "83010203")
    }

    func testMapsTrieesParOctetsDEncodage() {
        XCTAssertEqual(hex([:]), "a0")
        // Deux clés dont l'ordre numérique et l'ordre d'insertion diffèrent :
        // le tri canonique doit primer.
        XCTAssertEqual(hex([100: 1, 10: 2]), "a20a02186401")
    }

    func testTagTransparent() {
        XCTAssertEqual(hex(.tag(18, [])), "d280")
    }
}
