import XCTest
import Keychain

class KeychainTests: XCTestCase {

	/**
		- warning:
			The test will actually create an entry in your default Keychain. It
			will remove the entry again, if the test succeeds. In case of
			failure, the entry needs to be manually removed. The name of the
			entry is "KeychainTest". To avoid clashes with existing entries, a
			unique account name is chosen for each execution.
	*/
    func testGenericPasswords() {
		let account = UUID().uuidString
		let password1 = "foo".data(using: .utf8)!
		let password2 = "bar".data(using: .utf8)!
		let item = GenericPasswordItem(for: "KeychainTest", using: account)

		// Store password1
		XCTAssertNoThrow(try Keychain.store(password: password1, in: item))

		// Retrieve password1
		do {
			let actualPassword = try Keychain.retrievePassword(for: item)
			XCTAssertEqual(actualPassword, password1)
		} catch {
			XCTFail("Error occurred: \(error)")
		}

		// Update password1 to password2
		XCTAssertNoThrow(try Keychain.update(password: password2, for: item))

		// Retrieve password2
		do {
			let actualPassword = try Keychain.retrievePassword(for: item)
			XCTAssertEqual(actualPassword, password2)
		} catch {
			XCTFail("Error occurred: \(error)")
		}

		// Delete item
		XCTAssertNoThrow(try Keychain.delete(item: item))
    }

}
