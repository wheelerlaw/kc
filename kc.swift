import Foundation
import Security
import Darwin

let prog = "kc"

let EX_USAGE: Int32 = 64
let EX_NOTFOUND: Int32 = 44   // matches `security` (errSecItemNotFound as exit code)
let EX_DUPLICATE: Int32 = 45  // matches `security` (errSecDuplicateItem as exit code)

let usageText = """
Usage: kc <command> [options]

Commands:
  set     Store a secret (read from stdin, or prompted interactively)
  get     Print a stored secret to stdout
  delete  Remove a stored secret

Options:
  -s <service>   Service name (required unless -a given)
  -a <account>   Account name (required unless -s given)
  -l <label>     Item label (set only; defaults to service)
  -j <comment>   Item comment (set only)
  -D <kind>      Item kind (set only)
  -U             Update the item if it already exists (set only;
                 existing access list is kept)
  -T <app_path>  Trust an additional application (set only; repeatable)
  -A             Allow any application to read without warning (set only)
  -k <keychain>  Target keychain file (default: user's default keychain)

Other:
  kc --version   Print version
  kc -h|--help|help   Show this help
"""

func usageStdout() -> Never { FileHandle.standardOutput.write(Data(usageText.utf8)); exit(0) }
func usageStderr() -> Never { FileHandle.standardError.write(Data(usageText.utf8)); exit(EX_USAGE) }

func die(_ msg: String, _ code: Int32 = 1) -> Never {
    FileHandle.standardError.write(Data("\(prog): \(msg)\n".utf8))
    exit(code)
}

func dieStatus(_ status: OSStatus) -> Never {
    if status == errSecItemNotFound { die("item not found", EX_NOTFOUND) }
    let msg = SecCopyErrorMessageString(status, nil) as String? ?? "error \(status)"
    die(msg, 1)
}

// MARK: - Secret input (never on argv)

// Terminal state to restore if we are interrupted mid-prompt.
var gTtyFd: Int32 = -1
var gOrigTermios = termios()

func restoreTerminalAndExit(_ sig: Int32) {
    if gTtyFd >= 0 { tcsetattr(gTtyFd, TCSANOW, &gOrigTermios) }
    signal(sig, SIG_DFL)
    _exit(128 + sig)
}

func promptNoEcho(_ prompt: String, ttyFd: Int32, tty: UnsafeMutablePointer<FILE>) -> Data {
    fputs(prompt, tty)
    fflush(tty)
    var buf = Data()
    var c: UInt8 = 0
    // Non-canonical mode is active: read byte-by-byte so secrets can exceed
    // the 1024-byte MAX_CANON line limit.
    while read(ttyFd, &c, 1) == 1 {
        switch c {
        case 0x0D, 0x0A:                        // CR / LF ends input
            fputs("\n", tty)
            fflush(tty)
            return buf
        case 0x15:                              // Ctrl-U clears
            buf.removeAll()
        case 0x04:                              // Ctrl-D on empty buffer = EOF
            if buf.isEmpty {
                fputs("\n", tty)
                fflush(tty)
                return buf
            }
        case 0x7F, 0x08:                        // Backspace: drop last UTF-8 char
            if !buf.isEmpty {
                buf.removeLast()
                while let last = buf.last, (last & 0xC0) == 0x80 { buf.removeLast() }
            }
        default:
            buf.append(c)
        }
    }
    fputs("\n", tty)
    fflush(tty)
    return buf
}

func readSecret() -> Data {
    if isatty(STDIN_FILENO) == 0 {
        // Piped/redirected: read all of stdin, strip exactly one trailing newline.
        var data = FileHandle.standardInput.readDataToEndOfFile()
        if data.last == 0x0A { data.removeLast() }
        if data.isEmpty { die("empty secret") }
        return data
    }
    guard let tty = fopen("/dev/tty", "r+") else { die("cannot open /dev/tty") }
    defer { fclose(tty) }
    let fd = fileno(tty)
    tcgetattr(fd, &gOrigTermios)
    gTtyFd = fd
    signal(SIGINT, restoreTerminalAndExit)
    signal(SIGTERM, restoreTerminalAndExit)
    signal(SIGHUP, restoreTerminalAndExit)
    var noEcho = gOrigTermios
    noEcho.c_lflag &= ~tcflag_t(ECHO | ICANON)
    noEcho.c_cc.16 = 1   // VMIN
    noEcho.c_cc.17 = 0   // VTIME
    tcsetattr(fd, TCSANOW, &noEcho)
    let first = promptNoEcho("Password: ", ttyFd: fd, tty: tty)
    let second = promptNoEcho("Retype password: ", ttyFd: fd, tty: tty)
    tcsetattr(fd, TCSANOW, &gOrigTermios)
    gTtyFd = -1
    if first != second { die("passwords do not match") }
    if first.isEmpty { die("empty secret") }
    return first
}

// MARK: - Keychain helpers

func openKeychain(_ path: String?) -> SecKeychain? {
    guard let path = path else { return nil }
    var keychain: SecKeychain?
    let status = SecKeychainOpen(path, &keychain)
    guard status == errSecSuccess, let keychain = keychain else {
        dieStatus(status == errSecSuccess ? errSecInvalidKeychain : status)
    }
    return keychain
}

func makeAccess(label: String, trustedPaths: [String], anyApp: Bool) -> SecAccess {
    var apps: [SecTrustedApplication] = []
    var selfApp: SecTrustedApplication?
    if SecTrustedApplicationCreateFromPath(nil, &selfApp) == errSecSuccess, let selfApp = selfApp {
        apps.append(selfApp)
    }
    for path in ["/usr/bin/security"] + trustedPaths {
        var app: SecTrustedApplication?
        if SecTrustedApplicationCreateFromPath(path, &app) == errSecSuccess, let app = app {
            apps.append(app)
        } else {
            FileHandle.standardError.write(Data("\(prog): warning: cannot trust \(path)\n".utf8))
        }
    }
    var access: SecAccess?
    var status = SecAccessCreate(label as CFString, apps as CFArray, &access)
    guard status == errSecSuccess, let access = access else { dieStatus(status) }
    if anyApp {
        // Mirror `security -A`: set every ACL's application list to nil.
        var aclList: CFArray?
        status = SecAccessCopyACLList(access, &aclList)
        guard status == errSecSuccess, let acls = aclList as? [SecACL] else { dieStatus(status) }
        for acl in acls {
            var appList: CFArray?
            var desc: CFString?
            var prompt = SecKeychainPromptSelector()
            let s0 = SecACLCopyContents(acl, &appList, &desc, &prompt)
            if s0 != errSecSuccess { dieStatus(s0) }
            let s = SecACLSetContents(acl, nil, desc ?? (label as CFString), prompt)
            if s != errSecSuccess { dieStatus(s) }
        }
    }
    return access
}

func query(service: String?, account: String?, keychain: SecKeychain?) -> [String: Any] {
    var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword]
    if let service = service { q[kSecAttrService as String] = service }
    if let account = account { q[kSecAttrAccount as String] = account }
    if let keychain = keychain {
        q[kSecMatchSearchList as String] = [keychain]
    }
    return q
}

// MARK: - Commands

func cmdSet(service: String?, account: String?, label: String?, comment: String?, kind: String?,
            update: Bool, trustedPaths: [String], anyApp: Bool, keychainPath: String?) {
    let secret = readSecret()
    let keychain = openKeychain(keychainPath)
    let svc = service ?? ""
    let acct = account ?? ""
    let itemLabel = label ?? svc

    var attrs: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: svc,
        kSecAttrAccount as String: acct,
        kSecValueData as String: secret,
        kSecAttrLabel as String: itemLabel,
        kSecAttrAccess as String: makeAccess(label: itemLabel, trustedPaths: trustedPaths, anyApp: anyApp),
    ]
    if let comment = comment { attrs[kSecAttrComment as String] = comment }
    if let kind = kind { attrs[kSecAttrDescription as String] = kind }
    if let keychain = keychain { attrs[kSecUseKeychain as String] = keychain }

    var status = SecItemAdd(attrs as CFDictionary, nil)
    if status == errSecDuplicateItem {
        if !update { die("item already exists (use -U to update)", EX_DUPLICATE) }
        var updateAttrs: [String: Any] = [kSecValueData as String: secret]
        if let label = label { updateAttrs[kSecAttrLabel as String] = label }
        if let comment = comment { updateAttrs[kSecAttrComment as String] = comment }
        if let kind = kind { updateAttrs[kSecAttrDescription as String] = kind }
        status = SecItemUpdate(query(service: svc, account: acct, keychain: keychain) as CFDictionary,
                               updateAttrs as CFDictionary)
    }
    guard status == errSecSuccess else { dieStatus(status) }
}

func cmdGet(service: String?, account: String?, keychainPath: String?) {
    let keychain = openKeychain(keychainPath)
    var q = query(service: service, account: account, keychain: keychain)
    q[kSecReturnData as String] = true
    q[kSecMatchLimit as String] = kSecMatchLimitOne
    var item: CFTypeRef?
    let status = SecItemCopyMatching(q as CFDictionary, &item)
    guard status == errSecSuccess, let data = item as? Data else { dieStatus(status) }
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data([0x0A]))
}

func cmdDelete(service: String?, account: String?, keychainPath: String?) {
    let keychain = openKeychain(keychainPath)
    // Find exactly one matching item and delete it by reference, so partial
    // filters can never remove more than a single item.
    var q = query(service: service, account: account, keychain: keychain)
    q[kSecReturnRef as String] = true
    q[kSecMatchLimit as String] = kSecMatchLimitOne
    var item: CFTypeRef?
    var status = SecItemCopyMatching(q as CFDictionary, &item)
    guard status == errSecSuccess, let item = item else { dieStatus(status) }
    status = SecItemDelete([kSecClass as String: kSecClassGenericPassword,
                            kSecValueRef as String: item] as CFDictionary)
    guard status == errSecSuccess else { dieStatus(status) }
}

// MARK: - Argument parsing

@main
struct KC {
    static func main() {
        var args = Array(CommandLine.arguments.dropFirst())
        guard let cmd = args.first else { usageStderr() }
        args.removeFirst()

        switch cmd {
        case "-h", "--help", "help": usageStdout()
        case "--version": print(kcVersion); return
        case "set", "get", "delete": break
        default: usageStderr()
        }

        var service: String?, account: String?, label: String?, comment: String?, kind: String?
        var keychainPath: String?
        var update = false, anyApp = false
        var trustedPaths: [String] = []

        func takeValue(_ i: inout Int) -> String {
            i += 1
            guard i < args.count else { usageStderr() }
            return args[i]
        }

        var i = 0
        while i < args.count {
            switch args[i] {
            case "-s": service = takeValue(&i)
            case "-a": account = takeValue(&i)
            case "-l": label = takeValue(&i)
            case "-j": comment = takeValue(&i)
            case "-D": kind = takeValue(&i)
            case "-U": update = true
            case "-T": trustedPaths.append(takeValue(&i))
            case "-A": anyApp = true
            case "-k": keychainPath = takeValue(&i)
            case "-h", "--help": usageStdout()
            default: usageStderr()
            }
            i += 1
        }

        if cmd != "set" {
            // get/delete accept only -s, -a, -k
            if label != nil || comment != nil || kind != nil || update || anyApp || !trustedPaths.isEmpty { usageStderr() }
        }

        if service == nil && account == nil { usageStderr() }

        switch cmd {
        case "set":
            cmdSet(service: service, account: account, label: label, comment: comment, kind: kind,
                   update: update, trustedPaths: trustedPaths, anyApp: anyApp, keychainPath: keychainPath)
        case "get":
            cmdGet(service: service, account: account, keychainPath: keychainPath)
        default:
            cmdDelete(service: service, account: account, keychainPath: keychainPath)
        }
    }
}
