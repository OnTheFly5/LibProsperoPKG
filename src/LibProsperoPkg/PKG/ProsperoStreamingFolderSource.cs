// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
#nullable enable
using LibProsperoPkg.Content;
using LibProsperoPkg.PFS;
using LibProsperoPkg.PlayGo;
using LibProsperoPkg.Util;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace LibProsperoPkg.PKG;

/// <summary>
/// Read-only catalog for an already-prepared game folder. Payloads are opened lazily and read through
/// bounded streams; generated auxiliary metadata is held in memory. Raw ELF conversion is not provided.
/// </summary>
public sealed class ProsperoStreamingFolderSource
{
    /// <summary>Maximum size of one UCP file materialized for digest repair.</summary>
    public const int MaximumUcpOverlaySize = 16 * 1024 * 1024;
    /// <summary>Maximum total retained generated/repaired auxiliary-file bytes.</summary>
    public const int MaximumOverlayBytes = 64 * 1024 * 1024;

    public string SourceFolder { get; }
    public IReadOnlyList<ProsperoPs5InnerFileSource> Files { get; }

    private ProsperoStreamingFolderSource(string folder, IReadOnlyList<ProsperoPs5InnerFileSource> files)
    {
        SourceFolder = folder;
        Files = files;
    }

    /// <summary>
    /// Catalogs the selected root and rejects descendant links/reparse points and ambiguous names.
    /// Excludes GP4/GP5 files and sce_sys members assigned to the outer CNT, matching BuildInnerTree.
    /// Missing keystone/right.sprx and repaired small UCP archives are overlays, never source writes.
    /// Directories with no files are not representable by the current inner-source descriptor API.
    /// Sources must remain stable; length/timestamp checks detect ordinary mutations, not equal-length
    /// replacements with restored metadata. This API is not a filesystem security sandbox.
    /// </summary>
    public static ProsperoStreamingFolderSource Create(string folder, string passcode,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(folder);
        if (passcode is null || passcode.Length != 32 || passcode.Any(c => c > 0x7f))
            throw new ArgumentException("A 32-character ASCII passcode is required.", nameof(passcode));
        string root = Path.GetFullPath(folder);
        if (!Directory.Exists(root)) throw new DirectoryNotFoundException("Prepared game folder does not exist.");
        CheckDirectory(root);
        var entries = new Dictionary<string, Entry>(StringComparer.Ordinal);
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void Walk(string directory, string relative)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CheckDirectory(directory);
            foreach (string path in Directory.EnumerateFileSystemEntries(directory).OrderBy(p => Path.GetFileName(p), StringComparer.Ordinal))
            {
                cancellationToken.ThrowIfCancellationRequested();
                string name = Path.GetFileName(path);
                ValidateComponent(name);
                string rel = relative.Length == 0 ? name : relative + "/" + name;
                if (!paths.Add(rel)) throw new ArgumentException("Case-insensitive source path collision: " + rel, nameof(folder));
                var attributes = File.GetAttributes(path);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                    throw new NotSupportedException("Source links/reparse points are not supported: " + rel);
                if ((attributes & FileAttributes.Directory) != 0)
                {
                    Walk(path, rel);
                    continue;
                }
                if (name.EndsWith(".gp4", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".gp5", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (rel.StartsWith("sce_sys/", StringComparison.Ordinal))
                {
                    string sysName = rel[8..];
                    if (sysName == "param.json" || ProsperoCntEntryNames.NameToId.ContainsKey(sysName)) continue;
                }
                entries.Add(rel, new Entry(root, path, rel));
            }
        }
        Walk(root, "");
        // The format profile uses this exact spelling. Do not reinterpret a case variant as a second tree.
        string system = Path.Combine(root, "sce_sys");
        if (!Directory.Exists(system) || !paths.Any(path => string.Equals(path, "sce_sys", StringComparison.Ordinal)))
            throw new ArgumentException("Prepared source requires a sce_sys directory.", nameof(folder));
        int overlayBytes = 0;
        var overlays = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        void Overlay(string name, byte[] bytes)
        {
            if (overlayBytes > MaximumOverlayBytes - bytes.Length)
                throw new NotSupportedException("Generated source metadata exceeds the bounded overlay budget.");
            overlayBytes += bytes.Length;
            overlays.Add(name, bytes);
        }
        if (!entries.ContainsKey("sce_sys/keystone")) Overlay("sce_sys/keystone", Crypto.CreateKeystone(passcode));
        if (!entries.ContainsKey("sce_sys/about/right.sprx"))
        {
            byte[]? right = ProsperoPlayGo.GetRightSprx();
            if (right is { Length: > 0 }) Overlay("sce_sys/about/right.sprx", right);
        }
        foreach (var entry in entries.Values.Where(e => IsRepairCandidate(e.Relative)))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (entry.Length > MaximumUcpOverlaySize)
                throw new NotSupportedException("UCP metadata exceeds the bounded repair limit: " + entry.Relative);
            using var stream = entry.OpenRaw();
            byte[] bytes = new byte[checked((int)entry.Length)];
            stream.ReadExactly(bytes);
            if (stream.ReadByte() != -1) throw new InvalidDataException("Source grew: " + entry.Relative);
            entry.Validate();
            if (ProsperoUcp.IsUcp(bytes) && !ProsperoUcp.VerifyDigest(bytes))
                Overlay(entry.Relative, ProsperoUcp.WithRepairedDigest(bytes));
        }
        var files = new List<ProsperoPs5InnerFileSource>();
        foreach (var entry in entries.Values.OrderBy(e => e.Relative, StringComparer.Ordinal))
        {
            if (overlays.ContainsKey(entry.Relative)) continue;
            files.Add(new ProsperoPs5InnerFileSource
            {
                Path = "/" + entry.Relative, Length = entry.Length,
                OpenRead = () => entry.OpenPrepared(cancellationToken),
            });
        }
        foreach (var pair in overlays.OrderBy(p => p.Key, StringComparer.Ordinal))
        {
            // A generated path cannot replace an existing directory or case variant unnoticed.
            foreach (string path in paths)
                if ((string.Equals(path, pair.Key, StringComparison.OrdinalIgnoreCase) && !entries.ContainsKey(pair.Key)) ||
                    pair.Key.StartsWith(path + "/", StringComparison.OrdinalIgnoreCase) &&
                    (entries.ContainsKey(path) || !pair.Key.StartsWith(path + "/", StringComparison.Ordinal)))
                    throw new ArgumentException("Generated metadata conflicts with a source path: " + pair.Key, nameof(folder));
            byte[] bytes = pair.Value;
            Entry? original = entries.GetValueOrDefault(pair.Key);
            files.Add(new ProsperoPs5InnerFileSource
            {
                Path = "/" + pair.Key, Length = bytes.LongLength,
                OpenRead = () =>
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    CheckDirectory(root);
                    if (original is not null) original.Validate();
                    else
                    {
                        string target = Path.Combine(root, pair.Key.Replace('/', Path.DirectorySeparatorChar));
                        if (File.Exists(target) || Directory.Exists(target))
                            throw new InvalidDataException("Source gained generated metadata after cataloging: " + pair.Key);
                        string? parent = Path.GetDirectoryName(target);
                        while (parent is not null && parent.Length >= root.Length)
                        {
                            if (Directory.Exists(parent)) CheckDirectory(parent);
                            if (string.Equals(parent, root, StringComparison.Ordinal)) break;
                            parent = Path.GetDirectoryName(parent);
                        }
                    }
                    return new MemoryStream(bytes, writable: false);
                },
            });
        }
        cancellationToken.ThrowIfCancellationRequested();
        return new ProsperoStreamingFolderSource(root, Array.AsReadOnly(files.OrderBy(f => f.Path, StringComparer.Ordinal).ToArray()));
    }

    private static bool IsRepairCandidate(string path)
    {
        string prefix = path.StartsWith("sce_sys/trophy2/", StringComparison.Ordinal) ? "sce_sys/trophy2/"
            : path.StartsWith("sce_sys/uds/", StringComparison.Ordinal) ? "sce_sys/uds/" : "";
        return prefix.Length > 0 && path[prefix.Length..].IndexOf('/') < 0 && path.EndsWith(".ucp", StringComparison.OrdinalIgnoreCase);
    }

    private static void ValidateComponent(string name)
    {
        if (name.Length == 0 || name.Length > 255 || name == "." || name == ".." ||
            name.Any(c => c > 0x7f || char.IsControl(c) || c is '/' or '\\'))
            throw new NotSupportedException("Source names require ASCII components of at most 255 bytes: " + name);
    }

    private static void CheckDirectory(string path)
    {
        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.Directory) == 0 || (attributes & FileAttributes.ReparsePoint) != 0)
            throw new NotSupportedException("Source directory is missing or is a link/reparse point: " + path);
    }

    private sealed class Entry
    {
        private readonly string root;
        private readonly string path;
        private readonly DateTime modified;
        private readonly DateTime created;
        internal string Relative { get; }
        internal long Length { get; }
        internal Entry(string root, string path, string relative)
        {
            this.root = root; this.path = path; Relative = relative;
            var info = new FileInfo(path);
            Length = info.Length; modified = info.LastWriteTimeUtc; created = info.CreationTimeUtc;
        }
        internal void Validate()
        {
            CheckDirectory(root);
            string? parent = Path.GetDirectoryName(path);
            while (parent is not null && parent.Length >= root.Length)
            {
                CheckDirectory(parent);
                if (string.Equals(parent, root, StringComparison.Ordinal)) break;
                parent = Path.GetDirectoryName(parent);
            }
            var info = new FileInfo(path);
            if (!info.Exists || (info.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0 ||
                info.Length != Length || info.LastWriteTimeUtc != modified || info.CreationTimeUtc != created)
                throw new InvalidDataException("Source changed after cataloging: " + Relative);
        }
        internal FileStream OpenRaw()
        {
            Validate();
            var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.SequentialScan);
            try { Validate(); if (stream.Length != Length) throw new InvalidDataException("Source length changed: " + Relative); }
            catch { stream.Dispose(); throw; }
            return stream;
        }
        internal Stream OpenPrepared(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var stream = OpenRaw();
            try
            {
                byte[] header = new byte[(int)Math.Min(Length, ProsperoInnerFileClassifier.HeaderLength)];
                stream.ReadExactly(header);
                bool elfMagic = header.Length >= 4 && header[0] == 0x7f && header[1] == (byte)'E' && header[2] == (byte)'L' && header[3] == (byte)'F';
                if (ProsperoInnerFileClassifier.Classify(header) == ProsperoInnerFilePolicy.RequiresModuleConversion ||
                    elfMagic && header.Length < ProsperoInnerFileClassifier.HeaderLength)
                    throw new NotSupportedException("Raw ELF requires a prepared signed module before streaming: " + Relative);
                return new PreparedReader(header, stream, Validate, cancellationToken);
            }
            catch { stream.Dispose(); throw; }
        }
    }

    private sealed class PreparedReader(byte[] header, Stream source, Action validate, CancellationToken cancellationToken) : Stream
    {
        private int cursor;
        private bool disposed;
        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
        public override int Read(Span<byte> buffer)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            cancellationToken.ThrowIfCancellationRequested();
            if (buffer.Length == 0) return 0;
            if (cursor < header.Length)
            {
                int n = Math.Min(buffer.Length, header.Length - cursor);
                header.AsSpan(cursor, n).CopyTo(buffer);
                cursor += n;
                return n;
            }
            int read = source.Read(buffer);
            if (read == 0) validate();
            return read;
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing && !disposed) { disposed = true; source.Dispose(); }
            base.Dispose(disposing);
        }
        public override bool CanRead => !disposed;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
