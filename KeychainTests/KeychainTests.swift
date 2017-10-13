import XCTest
import Keychain

extension Keychain.Error: Equatable {
	public static func ==(lhs: Keychain.Error, rhs: Keychain.Error) -> Bool {
		switch (lhs, rhs) {
			case (.itemNotFound, .itemNotFound): fallthrough
			case (.itemAlreadyExists, .itemAlreadyExists):
				return true
			case (.unhandledError(let lhsStatus), .unhandledError(let rhsStatus)):
				return lhsStatus == rhsStatus
			default:
				return false
		}
	}
}

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
		let password1 = "foo"
		let password2 = "bar"
		let item = GenericPasswordItem(for: "KeychainTest", using: account)

		var actualPassword: String! = nil

		// Retrieve non-existing password
		XCTAssertThrowsError(actualPassword = try Keychain.retrievePassword(for: item)) {
			XCTAssertEqual($0 as? Keychain.Error, Keychain.Error.itemNotFound)
		}

		// Update non-existing password
		XCTAssertThrowsError(try Keychain.update(password: password1, for: item)) {
			XCTAssertEqual($0 as? Keychain.Error, Keychain.Error.itemNotFound)
		}

		// Delete non-existing password
		XCTAssertThrowsError(try Keychain.delete(item: item)) {
			XCTAssertEqual($0 as? Keychain.Error, Keychain.Error.itemNotFound)
		}

		// Store password1
		XCTAssertNoThrow(try Keychain.store(password: password1, in: item))

		// Store existing password
		XCTAssertThrowsError(try Keychain.store(password: password2, in: item)) {
			XCTAssertEqual($0 as? Keychain.Error, Keychain.Error.itemAlreadyExists)
		}

		// Retrieve password1
		actualPassword = nil
		XCTAssertNoThrow(actualPassword = try Keychain.retrievePassword(for: item))
		XCTAssertEqual(actualPassword, password1)

		// Update password1 to password2
		XCTAssertNoThrow(try Keychain.update(password: password2, for: item))

		// Retrieve password2
		actualPassword = nil
		XCTAssertNoThrow(actualPassword = try Keychain.retrievePassword(for: item))
		XCTAssertEqual(actualPassword, password2)

		// Delete item
		XCTAssertNoThrow(try Keychain.delete(item: item))

		// Retrieve non-existing password
		XCTAssertThrowsError(actualPassword = try Keychain.retrievePassword(for: item)) {
			XCTAssertEqual($0 as? Keychain.Error, Keychain.Error.itemNotFound)
		}

		// Create a new password
		XCTAssertNoThrow(try Keychain.updateOrCreate(password: password1, for: item))

		// Retrieve password
		actualPassword = nil
		XCTAssertNoThrow(actualPassword = try Keychain.retrievePassword(for: item))
		XCTAssertEqual(actualPassword, password1)

		// Update password1
		XCTAssertNoThrow(try Keychain.updateOrCreate(password: password2, for: item))

		// Retrieve password2
		actualPassword = nil
		XCTAssertNoThrow(actualPassword = try Keychain.retrievePassword(for: item))
		XCTAssertEqual(actualPassword, password2)

		// Delete item
		XCTAssertNoThrow(try Keychain.delete(item: item))
    }

}
