import SwiftUI

struct ContentView: View {
    @State private var logs: [String] = []
    @State private var results: [String: TOCTOUResultRow] = [:]
    @State private var running = false
    @State private var customPath = ""

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {

                    header
                    runButtons
                    customPathField
                    resultsList
                    logPanel
                }
                .padding()
            }
            .navigationTitle("Sandbox TOCTOU")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("sanbox_extension TOCTOU")
                .font(.headline)
            Text("deterministic · no race timing")
                .font(.caption).foregroundColor(.secondary)
        }
    }

    private var runButtons: some View {
        VStack(spacing: 8) {
            Button {
                runAll()
            } label: {
                HStack {
                    Image(systemName: "play.fill")
                    Text(running ? "Running…" : "Run All Default Targets")
                    Spacer()
                }
                .padding()
                .background(Color.green.opacity(0.25))
                .cornerRadius(10)
            }
            .disabled(running)

            Button {
                runSingle(customPath)
            } label: {
                HStack {
                    Image(systemName: "target")
                    Text("Run Custom Path")
                    Spacer()
                }
                .padding()
                .background(Color.blue.opacity(0.25))
                .cornerRadius(10)
            }
            .disabled(running || customPath.isEmpty)
        }
    }

    private var customPathField: some View {
        TextField("/path/to/file", text: $customPath)
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
            .font(.system(.body, design: .monospaced))
            .padding()
            .background(Color.white.opacity(0.06))
            .cornerRadius(10)
    }

    private var resultsList: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(TOCTOUPoC.defaultTargets, id: \.self) { path in
                let row = results[path]
                HStack(alignment: .top) {
                    Image(systemName: row?.success == true ? "checkmark.seal.fill" :
                             row?.success == false ? "xmark.seal.fill" : "circle")
                        .foregroundColor(row?.success == true ? .green :
                                         row?.success == false ? .red : .gray)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(path)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(.cyan)
                        if let r = row {
                            Text(r.success
                                 ? "\(r.bytes)B · \(r.preview.prefix(60))"
                                 : (r.error ?? "failed"))
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundColor(r.success ? .green : .red)
                                .lineLimit(2)
                        }
                    }
                    Spacer()
                }
                .padding(.vertical, 3)
            }
        }
        .padding(10)
        .background(Color.white.opacity(0.04))
        .cornerRadius(10)
    }

    private var logPanel: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 1) {
                ForEach(Array(logs.enumerated()), id: \.offset) { _, l in
                    Text(l)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.green)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .padding(8)
        }
        .frame(height: 220)
        .background(Color.black)
        .cornerRadius(10)
    }

    // MARK: actions

    private func runAll() {
        running = true
        results.removeAll()
        logs.removeAll()
        DispatchQueue.global(qos: .userInitiated).async {
            TOCTOUPoC.runAll(
                onLog: { line in
                    DispatchQueue.main.async { logs.append(line) }
                },
                onResult: { r in
                    DispatchQueue.main.async {
                        results[r.path] = TOCTOUResultRow(success: r.success,
                                                          bytes: r.bytes,
                                                          preview: r.preview,
                                                          error: r.error)
                    }
                }
            )
            DispatchQueue.main.async { running = false }
        }
    }

    private func runSingle(_ path: String) {
        running = true
        logs.removeAll()
        DispatchQueue.global(qos: .userInitiated).async {
            let workDir = FileManager.default.temporaryDirectory
                .appendingPathComponent("toctou", isDirectory: true)
            try? FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
            let r = TOCTOUPoC.read(targetPath: path, workDir: workDir, onLog: { line in
                DispatchQueue.main.async { logs.append(line) }
            })
            DispatchQueue.main.async {
                results[path] = TOCTOUResultRow(success: r.success,
                                                bytes: r.bytes,
                                                preview: r.preview,
                                                error: r.error)
                running = false
            }
        }
    }
}

struct TOCTOUResultRow {
    let success: Bool
    let bytes: Int
    let preview: String
    let error: String?
}
