import Foundation
import Security

/**
	A dictionary used for querying Keychain items.
*/
public typealias KeychainQuery = [String: AnyObject]

/**
	Convenience function for setting specific values for Keychain queries.

	If the value is `nil`, the attribute will not be added.

	- parameters:
		- query: The query, for which an attribute should be set.
		- key: The key/name of the attribute.
		- value: The value of the attribute.
*/
fileprivate func set<T>(_ query: inout KeychainQuery, key: CFString, value: T?) {
	if let value = value {
		query[key as String] = value as AnyObject?
	}
}

/**
	Convenience function for getting specific values for Keychain queries.

	- parameters:
		- query: The query, from which a value should be retrieved.
		- key: The key/name of the attribute, whoose value should be retrieved.

	- returns:
		The value for the attribute with the name/key `key` if `key` exists,
		`nil` else.
*/
fileprivate func get(_ query: KeychainQuery, key: CFString) -> AnyObject? {
	return query[key as String]
}

/**
	A general API for Keychain items.
*/
public protocol KeychainItem {

	/**
		The class/type of the Keychain item.
	
		- see: [`kSecClass`](https://developer.apple.com/documentation/security/ksecclass)
	*/
	var type: CFString { get }

	/**
		The query to identify the Keychain item(s).
	*/
	var query: KeychainQuery { get }

}

/**
	This class implements common functionality for Keychain password items.
	Attributes defined in this class are available for generic and internet
	passwords.
*/
public class AbstractPasswordItem {

	/**
		The account used with a given service or on a given web site, for which
		for which the password is used.
	
		- see: [`kSecAttrAccount`](https://developer.apple.com/documentation/security/ksecattraccount)
	*/
	public let account: String?

	/**
		A comment for the item stored in the Keychain. This value is not stored
		securely and can be read without authorization.
	
		- see: [`kSecAttrComment`](https://developer.apple.com/documentation/security/ksecattrcomment)
	*/
	public let comment: String?

	/**
		A description or purpose of the Keychain item. In the macOS Keychain
		Access application the description will be shown in the "Kind" field of
		items. The default value shown there depends on the items `type`, e.g.,
		"application password" for generic passwords, or "Internet password" for
		internet passwords.
	
		- see: [`kSecAttrDescription`](https://developer.apple.com/documentation/security/ksecattrdescription)
	*/
	public let description: String?

	/**
		Initializes attributes shared between Keychain password items.

		- parameters:
			- account: The account for which the password is used.
			- description: A description or purpose of the item.
			- comment: A comment.
	*/
	public init(for account: String? = nil, with description: String? = nil, and comment: String? = nil) {
		self.account = account
		self.comment = comment
		self.description = description
	}

	/**
		Helper function to construct the Keychain query.

		- parameters:
			- query: The query, where attributes should be added.

		- returns:
			The `query` with additional attributes added.
	*/
	fileprivate func addAttributes(to query: KeychainQuery) -> KeychainQuery {
		var query = query

		set(&query, key: kSecAttrAccount, value: account)
		set(&query, key: kSecAttrComment, value: comment)
		set(&query, key: kSecAttrDescription, value: description)

		return query
	}

}

/**
	A generic password, that can be persisted securely in the systems Keychain.

	A generic password is always used for a specified service, which can be your
	application itself. It might be tied to or used by an account.

	Two generic password items are considered equal if their `service` and
	`account` values are equal.

	- note:
		For internet passwords use `InternetPassword` instead.
*/
public class GenericPasswordItem: AbstractPasswordItem {

	/**
		The service for which the password is used. This can simply be your
		application.
	
		- see: [`kSecAttrService`](https://developer.apple.com/documentation/security/ksecattrservice)
	*/
	public let service: String

	/**
		Initialize a generic password Keychain item.

		- parameters:
			- service: A service, e.g., your application name.
			- account: The account for which the password is used.
			- description: A description or purpose of the item.
			- comment: A comment.
	*/
	public init(for service: String, using account: String? = nil, with description: String? = nil, and comment: String? = nil) {
		self.service = service

		super.init(for: account, with: description, and: comment)
	}

	/**
		Helper function to construct the Keychain query.

		- parameters:
			- query: The query, where attributes should be added.

		- returns:
			The `query` with additional attributes added.
	*/
	fileprivate override func addAttributes(to query: KeychainQuery) -> KeychainQuery {
		var query = super.addAttributes(to: query)

		set(&query, key: kSecAttrService, value: service)

		return query
	}

}

extension GenericPasswordItem: KeychainItem {
	/**
		The Keychain type of a generic password, which is
		[`kSecClassGenericPassword`](https://developer.apple.com/documentation/security/ksecclassgenericpassword)
	*/
	public var type: CFString { get { return kSecClassGenericPassword } }

	/**
		Constructs a keychain query for a generic password.
	*/
	public var query: [String: AnyObject] {
		get {
			var result = [String: AnyObject]()

			set(&result, key: kSecClass, value: type)

			return addAttributes(to: result)
		}
	}
}

/**
	This class offers an interface to the Keychain services.

	They Keychain basically is a collection of items with attributes. Some
	attributes are stored securely and require user authorization to be
	accessed.
*/
public class Keychain {

	/**
		Defines errors that might occur during interaction with the systems
		Keychain service.
	*/
	public enum Error: Swift.Error {
		/**
			This error indicates that a given item does not exist in the
			Keychain. It should be created first by calling
			`store(password:in:with:)`.
		*/
		case itemNotFound

		/**
			This error indicates that a given item already exists. Please update
			it by calling `update(password:for:)` if you intend to change it.
		
			- note: The error might also indicate that a mandatory attribute was
				not set.
		*/
		case itemAlreadyExists

		/**
			This error indicates that response from the Keychain service did not
			match the expectations. If you see this error, this might indicate a
			bug in this framework. Please report it in
			[the issue tracker](https://github.com/blochberger/Keychain/issues).
		*/
		case unexpectedQueryData

		/**
			This error indicates that the actual password value did not match
			the expected format. If you see this error, this might indicate a
			bug in this framework. Please report it in
			[the issue tracker](https://github.com/blochberger/Keychain/issues).
		*/
		case unexpectedPasswordData

		/**
			This is a generic error that has not been observed during
			development of the framework. If you see this error, please report
			the circumstances in
			[the issue tracker](https://github.com/blochberger/Keychain/issues).
		*/
		case unhandledError(status: OSStatus)
	}

	/**
		Helper function, that determines the type-safe errors from status codes
		of calls to the Keychain services.

		- parameters:
			- status: The status code of a Keychain service function call.
	
		- returns:
			The `Error` corresponding to the given status code, `nil` else.

		- postcondition:
			The return value is `nil` if and only if `status` is `noErr` (0).
	*/
	private static func error(from status: OSStatus) -> Error? {
		switch status {
			case noErr:
				return nil
			case errSecItemNotFound:
				return .itemNotFound
			case errSecDuplicateItem:
				/*
					This error could also mean, that some mandatory attribute
					was not set, e.g., if the `kSecAttrService` was not set for
					items of class `kSecClassGenericPassword`.
				*/
				return .itemAlreadyExists
			default:
				return .unhandledError(status: status)
		}
	}

	/**
		Adds a new generic password to the Keychain.
	
		If the item already exists the `itemAlreadyExists` error will be thrown.

		- parameters:
			- password: The actual password that should be stored securely.
			- item: The item that should contain the password.
			- label: A label for the item.
	*/
	public static func store(password: Data, in item: GenericPasswordItem, with label: String? = nil) throws {
		var query = item.query

		set(&query, key: kSecValueData, value: password)
		set(&query, key: kSecAttrLabel, value: label)

		let status = SecItemAdd(query as CFDictionary, nil)

		guard status == noErr else {
			throw error(from: status)!
		}
	}

	/**
		Updates the generic password for a given item.
	
		- parameters:
			- password: The new password.
			- item: The item, that should be updated.
	*/
	public static func update(password: Data, for item: GenericPasswordItem) throws {
		var attributesToUpdate = KeychainQuery()

		set(&attributesToUpdate, key: kSecValueData, value: password)

		let status = SecItemUpdate(item.query as CFDictionary, attributesToUpdate as CFDictionary)

		guard status == noErr else {
			throw error(from: status)!
		}
	}

	/**
		Retrieve a generic password for a given item.
	
		- parameters:
			- item: The item, for which the password should be retrieved.
	
		- returns:
			The password stored for the given item.
	*/
	public static func retrievePassword(for item: GenericPasswordItem) throws -> Data {
		var query = item.query

		set(&query, key: kSecMatchLimit, value: kSecMatchLimitOne)
		set(&query, key: kSecReturnAttributes, value: kCFBooleanTrue)
		set(&query, key: kSecReturnData, value: kCFBooleanTrue)

		var queryResult: AnyObject?
		let status = withUnsafeMutablePointer(to: &queryResult) {
			SecItemCopyMatching(query as CFDictionary, UnsafeMutablePointer($0))
		}

		guard status == noErr else {
			throw error(from: status)!
		}

		guard let retrievedItem = queryResult as? KeychainQuery else {
			throw Error.unexpectedQueryData
		}

		guard let password = get(retrievedItem, key: kSecValueData) as? Data else {
			throw Error.unexpectedPasswordData
		}

		return password
	}

	/**
		Removes an item from the Keychain.

		- parameters:
			- item: The item that should be removed.
	*/
	public static func delete(item: KeychainItem) throws {
		let status = SecItemDelete(item.query as CFDictionary)

		guard status == noErr else {
			throw error(from: status)!
		}
	}

	/**
		This class offers only static functions, hence the constructor is
		disabled.
	*/
	private init() { }
}
