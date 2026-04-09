//
//  ProcessManager.swift
//  ACP
//
//  Manages subprocess lifecycle, I/O pipes, and message serialization.
//  Uses posix_spawn with POSIX_SPAWN_CLOEXEC_DEFAULT to prevent FD inheritance.
//

#if os(macOS)
import Foundation
import Darwin
import os.log
import ACPModel

actor ACPProcessManager {
    // MARK: - Properties

    private var childPid: pid_t = 0
    private var processGroupId: pid_t?
    private var stdinPipe: Pipe?
    private var stdoutPipe: Pipe?
    private var stderrPipe: Pipe?

    private var readBuffer: Data = Data()
    private var largeBufferDumpCount: Int = 0
    private var lastLargeBufferDumpSize: Int = 0

    private let encoder: JSONEncoder
    private let decoder: JSONDecoder
    private let logger: Logger

    private static let largeBufferWarningThreshold = 200000
    private static let largeBufferDumpMinGrowth = 8192
    private static let maxLargeBufferDumps = 3

    private var onDataReceived: ((Data) async -> Void)?
    private var onTermination: ((Int32) async -> Void)?
    private var terminationMonitorTask: Task<Void, Never>?

    // MARK: - Initialization

    init(encoder: JSONEncoder, decoder: JSONDecoder) {
        self.encoder = encoder
        self.decoder = decoder
        self.logger = Logger.forCategory("ACPProcessManager")
    }

    // MARK: - Process Lifecycle

    func launch(agentPath: String, arguments: [String] = [], workingDirectory: String? = nil, environment customEnvironment: [String: String]? = nil) throws {
        guard childPid == 0 else {
            throw ClientError.invalidResponse
        }

        // Resolve executable path
        let resolvedPath = (try? FileManager.default.destinationOfSymbolicLink(atPath: agentPath)) ?? agentPath
        let actualPath = resolvedPath.hasPrefix("/") ? resolvedPath : ((agentPath as NSString).deletingLastPathComponent as NSString).appendingPathComponent(resolvedPath)

        let isNodeScript: Bool = {
            guard let handle = FileHandle(forReadingAtPath: actualPath) else { return false }
            defer { try? handle.close() }
            guard let data = try? handle.read(upToCount: 64),
                  let firstLine = String(data: data, encoding: .utf8) else { return false }
            return firstLine.hasPrefix("#!/usr/bin/env node")
        }()

        var execPath: String
        var allArgs: [String]

        if isNodeScript {
            let searchPaths = [
                (agentPath as NSString).deletingLastPathComponent,
                (actualPath as NSString).deletingLastPathComponent,
                "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"
            ]
            let foundNode = searchPaths
                .map { ($0 as NSString).appendingPathComponent("node") }
                .first { FileManager.default.fileExists(atPath: $0) }

            if let nodePath = foundNode {
                execPath = nodePath
                allArgs = [nodePath, actualPath] + arguments
            } else {
                execPath = agentPath
                allArgs = [agentPath] + arguments
            }
        } else {
            execPath = agentPath
            allArgs = [agentPath] + arguments
        }

        // Build environment
        var environment = ShellEnvironment.loadUserShellEnvironment()
        if let customEnvironment {
            for (key, value) in customEnvironment { environment[key] = value }
        }
        if let workingDirectory, !workingDirectory.isEmpty {
            environment["PWD"] = workingDirectory
            environment["OLDPWD"] = workingDirectory
        }
        let agentDir = (agentPath as NSString).deletingLastPathComponent
        environment["PATH"] = environment["PATH"].map { "\(agentDir):\($0)" } ?? agentDir

        // Create pipes
        let stdinPipe = Pipe()
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        self.stdinPipe = stdinPipe
        self.stdoutPipe = stdoutPipe
        self.stderrPipe = stderrPipe

        // Spawn using posix_spawn with POSIX_SPAWN_CLOEXEC_DEFAULT
        let pid = try Self.spawnProcess(
            execPath: execPath,
            args: allArgs,
            environment: environment,
            workingDirectory: workingDirectory,
            stdinReadFD: stdinPipe.fileHandleForReading.fileDescriptor,
            stdoutWriteFD: stdoutPipe.fileHandleForWriting.fileDescriptor,
            stderrWriteFD: stderrPipe.fileHandleForWriting.fileDescriptor
        )

        childPid = pid
        processGroupId = pid

        // Close pipe ends the parent doesn't need
        try? stdinPipe.fileHandleForReading.close()
        try? stdoutPipe.fileHandleForWriting.close()
        try? stderrPipe.fileHandleForWriting.close()

        Task {
            await ProcessRegistry.shared.recordProcess(pid: pid, pgid: pid, agentPath: actualPath)
        }

        startTerminationMonitor()
        startReading()
        startReadingStderr()
    }

    /// Spawns a child process using posix_spawn with POSIX_SPAWN_CLOEXEC_DEFAULT.
    ///
    /// CLOEXEC_DEFAULT ensures the child only inherits the explicitly mapped
    /// file descriptors (stdin/stdout/stderr pipes), not any FDs from the parent
    /// process (e.g. terminal FDs when launched from swift-bundler run).
    private static func spawnProcess(
        execPath: String,
        args: [String],
        environment: [String: String],
        workingDirectory: String?,
        stdinReadFD: Int32,
        stdoutWriteFD: Int32,
        stderrWriteFD: Int32
    ) throws -> pid_t {
        // Spawn attributes: CLOEXEC_DEFAULT + new session
        var attrs: posix_spawnattr_t?
        posix_spawnattr_init(&attrs)
        defer { posix_spawnattr_destroy(&attrs) }
        posix_spawnattr_setflags(&attrs, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSID))

        // File actions: wire pipes to child's stdio
        var fileActions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&fileActions)
        defer { posix_spawn_file_actions_destroy(&fileActions) }
        posix_spawn_file_actions_adddup2(&fileActions, stdinReadFD, STDIN_FILENO)
        posix_spawn_file_actions_adddup2(&fileActions, stdoutWriteFD, STDOUT_FILENO)
        posix_spawn_file_actions_adddup2(&fileActions, stderrWriteFD, STDERR_FILENO)

        if let workingDirectory, !workingDirectory.isEmpty {
            posix_spawn_file_actions_addchdir_np(&fileActions, workingDirectory)
        }

        // Build null-terminated C arrays for argv and envp
        var pid: pid_t = 0
        let result: Int32 = args.withCStrings { argv in
            environment.map { "\($0.key)=\($0.value)" }.withCStrings { envp in
                posix_spawn(&pid, execPath, &fileActions, &attrs, argv, envp)
            }
        }

        guard result == 0 else {
            throw ClientError.transportError(
                "posix_spawn failed: \(String(cString: strerror(result)))"
            )
        }
        return pid
    }

    func isRunning() -> Bool {
        childPid > 0 && kill(childPid, 0) == 0
    }

    func terminate() async {
        let pid = childPid
        let pgid = processGroupId

        terminationMonitorTask?.cancel()
        terminationMonitorTask = nil

        stdoutPipe?.fileHandleForReading.readabilityHandler = nil
        stderrPipe?.fileHandleForReading.readabilityHandler = nil

        try? stdinPipe?.fileHandleForWriting.close()
        try? stdoutPipe?.fileHandleForReading.close()
        try? stderrPipe?.fileHandleForReading.close()

        if pid > 0, kill(pid, 0) == 0 {
            _ = pgid.map { killpg($0, SIGTERM) } ?? kill(pid, SIGTERM)
        }

        if pid > 0 {
            let exited = await waitForExit(pid, timeout: 2.0)
            if !exited {
                _ = pgid.map { killpg($0, SIGKILL) } ?? kill(pid, SIGKILL)
            }
        }

        await ProcessRegistry.shared.removeProcess(pid: pid, pgid: pgid)
        childPid = 0
        processGroupId = nil
        stdinPipe = nil
        stdoutPipe = nil
        stderrPipe = nil
        readBuffer.removeAll()
    }

    // MARK: - I/O Operations

    func writeMessage<T: Encodable>(_ message: T) async throws {
        guard let stdin = stdinPipe?.fileHandleForWriting else {
            throw ClientError.processNotRunning
        }
        let data = try encoder.encode(message)
        var lineData = data
        lineData.append(0x0A)
        try stdin.write(contentsOf: lineData)
    }

    // MARK: - Callbacks

    func setDataReceivedCallback(_ callback: @escaping (Data) async -> Void) {
        self.onDataReceived = callback
    }

    func setTerminationCallback(_ callback: @escaping (Int32) async -> Void) {
        self.onTermination = callback
    }

    // MARK: - Private Methods

    private func startTerminationMonitor() {
        terminationMonitorTask = Task { [weak self] in
            guard let self else { return }
            let pid = await self.childPid
            guard pid > 0 else { return }

            let exitCode: Int32 = await withCheckedContinuation { continuation in
                DispatchQueue.global().async {
                    var status: Int32 = 0
                    _ = waitpid(pid, &status, 0)
                    let code: Int32 = ((status & 0x7f) == 0) ? Int32((status >> 8) & 0xff) : -1
                    continuation.resume(returning: code)
                }
            }
            await self.handleTermination(exitCode: exitCode)
        }
    }

    private func startReading() {
        guard let stdout = stdoutPipe?.fileHandleForReading else { return }
        stdout.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else {
                handle.readabilityHandler = nil
                return
            }
            Task { await self?.processIncomingData(data) }
        }
    }

    private func startReadingStderr() {
        guard let stderr = stderrPipe?.fileHandleForReading else { return }
        stderr.readabilityHandler = { handle in
            let data = handle.availableData
            guard !data.isEmpty else {
                handle.readabilityHandler = nil
                return
            }
        }
    }

    private func processIncomingData(_ data: Data) async {
        readBuffer.append(data)
        await drainBufferedMessages()
    }

    private func handleTermination(exitCode: Int32) async {
        let pid = childPid
        let pgid = processGroupId
        await drainAndClosePipes()
        logger.info("Agent process terminated with code: \(exitCode)")
        await ProcessRegistry.shared.removeProcess(pid: pid, pgid: pgid)
        await onTermination?(exitCode)
    }

    private func drainAndClosePipes() async {
        if let stdoutHandle = stdoutPipe?.fileHandleForReading {
            stdoutHandle.readabilityHandler = nil
            do {
                while true {
                    guard let chunk = try stdoutHandle.read(upToCount: 65536), !chunk.isEmpty else { break }
                    await processIncomingData(chunk)
                }
            } catch {}
            try? stdoutHandle.close()
        }
        if let stderrHandle = stderrPipe?.fileHandleForReading {
            stderrHandle.readabilityHandler = nil
            do {
                while true {
                    guard let chunk = try stderrHandle.read(upToCount: 65536), !chunk.isEmpty else { break }
                    _ = chunk
                }
            } catch {}
            try? stderrHandle.close()
        }
        await flushRemainingBufferIfNeeded()
        try? stdinPipe?.fileHandleForWriting.close()
        stdinPipe = nil
        stdoutPipe = nil
        stderrPipe = nil
        childPid = 0
        processGroupId = nil
        readBuffer.removeAll()
    }

    // MARK: - JSON Message Parsing

    private func drainBufferedMessages() async {
        while let message = popNextMessage() {
            await onDataReceived?(message)
        }
    }

    private func popNextMessage() -> Data? {
        let whitespace: Set<UInt8> = [0x20, 0x09, 0x0D, 0x0A]
        parseLoop: while true {
            while let first = readBuffer.first, whitespace.contains(first) { readBuffer.removeFirst() }
            guard !readBuffer.isEmpty else { return nil }
            guard let first = readBuffer.first else { return nil }

            if first != 0x7B && first != 0x5B {
                if let jsonStart = readBuffer.firstIndex(where: { $0 == 0x7B || $0 == 0x5B }) {
                    let dropCount = readBuffer.distance(from: readBuffer.startIndex, to: jsonStart)
                    if dropCount > 0 {
                        readBuffer.removeFirst(min(dropCount, readBuffer.count))
                        logger.debug("Discarded \(dropCount) non-JSON prefix bytes")
                    }
                    continue
                }
                if let newline = readBuffer.firstIndex(of: 0x0A) {
                    let removeCount = readBuffer.distance(from: readBuffer.startIndex, to: newline) + 1
                    readBuffer.removeFirst(min(removeCount, readBuffer.count))
                    continue
                }
                if readBuffer.count > 4096 {
                    self.readBuffer.removeAll(keepingCapacity: true)
                }
                return nil
            }

            let bytes = Array(readBuffer)
            var depth = 0, inString = false, escaped = false
            for endIndex in 0..<bytes.count {
                let byte = bytes[endIndex]
                if inString {
                    if escaped { escaped = false; continue }
                    if byte == 0x5C { escaped = true; continue }
                    if byte == 0x22 { inString = false }
                    continue
                }
                if byte == 0x22 { inString = true; continue }
                if byte == 0x7B || byte == 0x5B { depth += 1 }
                else if byte == 0x7D || byte == 0x5D {
                    depth -= 1
                    if depth == 0 {
                        let candidate = Data(bytes[0...endIndex])
                        if isValidJSONObjectMessage(candidate) {
                            readBuffer.removeFirst(min(endIndex + 1, readBuffer.count))
                            return candidate
                        }
                        readBuffer.removeFirst(min(1, readBuffer.count))
                        continue parseLoop
                    }
                }
            }

            if let newline = readBuffer.firstIndex(of: 0x0A) {
                let line = Data(readBuffer.prefix(upTo: newline))
                if !line.isEmpty, !isValidJSONObjectMessage(line) {
                    let removeCount = readBuffer.distance(from: readBuffer.startIndex, to: newline) + 1
                    readBuffer.removeFirst(min(removeCount, readBuffer.count))
                    continue
                }
            }
            return nil
        }
    }

    private func isValidJSONObjectMessage(_ data: Data) -> Bool {
        guard let object = try? JSONSerialization.jsonObject(with: data) else { return false }
        return object is [String: Any] || object is [Any]
    }

    private func flushRemainingBufferIfNeeded() async {
        await drainBufferedMessages()
        if !readBuffer.isEmpty {
            let remaining = readBuffer
            readBuffer.removeAll(keepingCapacity: true)
            if !remaining.isEmpty { await onDataReceived?(remaining) }
        }
    }

    private func waitForExit(_ pid: pid_t, timeout: TimeInterval) async -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while kill(pid, 0) == 0, Date() < deadline {
            try? await Task.sleep(nanoseconds: 50_000_000)
        }
        return kill(pid, 0) != 0
    }
}

// MARK: - C String Array Helper

private extension Array where Element == String {
    /// Calls the closure with a C-compatible null-terminated array (argv/envp style).
    func withCStrings<R>(_ body: (UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) -> R) -> R {
        let cStrings = self.map { strdup($0)! }
        defer { cStrings.forEach { free($0) } }
        var ptrs = cStrings.map { Optional(UnsafeMutablePointer($0)) }
        ptrs.append(nil)
        return ptrs.withUnsafeMutableBufferPointer { body($0.baseAddress!) }
    }
}
#endif
