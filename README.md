# Keychain

![Coverage](https://blochberger.github.io/Keychain/macos/coverage.svg) [![Documentation](https://blochberger.github.io/Keychain/macos/public/badge.svg)](https://blochberger.github.io/Keychain)

Convenient Swift bindings for the [Keychain services](https://developer.apple.com/documentation/security/keychain_services).

The project is not supporting many Keychain features. If you want more, create or vote for an issue, or create a pull request. Before creating pull requests, you can discuss the intended change by creating an issue first.

- Repository: https://github.com/blochberger/Keychain
- Documentation: https://blochberger.github.io/Keychain
  - macOS: [public](https://blochberger.github.io/Keychain/macos/public), [internal](https://blochberger.github.io/Keychain/macos/internal), [private](https://blochberger.github.io/Keychain/macos/private)
  - iOS: [public](https://blochberger.github.io/Keychain/iphone/public), [internal](https://blochberger.github.io/Keychain/iphone/internal), [private](https://blochberger.github.io/Keychain/iphone/private)
- Issues: https://github.com/blochberger/Keychain/issues

## Examples

### Generic Passwords

```swift
import Keychain

let account = "user" // A user account, for which the password is used
let service = "service" // A service, e.g., your app name
let label = "\(account)@\(service)" // Descriptive name

let item = GenericPasswordItem(for: service, using: account, with: label)

// Store password
try Keychain.store(password: Data("foo".utf8), in: item)

// Retrieve password
let password = try Keychain.retrievePassword(for: item)

// Update password
try Keychain.update(password: Data("bar".utf8), for: item)

// Delete item
try Keychain.delete(item: item)
```
