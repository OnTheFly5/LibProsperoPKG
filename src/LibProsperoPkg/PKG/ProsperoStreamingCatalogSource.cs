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

/// <summary>Transforms a generic original source tree into prepared inner-image inputs.</summary>
public static class ProsperoStreamingCatalogSource
{
    public static IReadOnlyList<ProsperoPs5InnerFileSource> Create(ProsperoSourceCatalog catalog, string passcode,
        CancellationToken cancellationToken = default, bool signExecutableModules = false)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        if (passcode is null || passcode.Length != 32 || passcode.Any(c => c > 0x7f))
            throw new ArgumentException("A 32-character ASCII passcode is required.", nameof(passcode));
        cancellationToken.ThrowIfCancellationRequested();
        catalog.Validate();
        if (!catalog.Directories.Any(d => d.Path == "/sce_sys"))
            throw new ArgumentException("Prepared source requires a sce_sys directory.", nameof(catalog));
        var files = catalog.Files.Where(file =>
        {
            string path = file.Path[1..];
            string name = path[(path.LastIndexOf('/') + 1)..];
            if (name.EndsWith(".gp4", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".gp5", StringComparison.OrdinalIgnoreCase)) return false;
            if (!path.StartsWith("sce_sys/", StringComparison.Ordinal)) return true;
            string sys = path[8..];
            return sys != "param.json" && !ProsperoCntEntryNames.NameToId.ContainsKey(sys);
        }).ToDictionary(f => f.Path, StringComparer.Ordinal);
        var overlays = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        int total = 0;
        void AddOverlay(string path, byte[] bytes)
        {
            if (total > ProsperoStreamingFolderSource.MaximumOverlayBytes - bytes.Length)
                throw new NotSupportedException("Generated source metadata exceeds the bounded overlay budget.");
            total += bytes.Length;
            overlays.Add(path, bytes);
        }
        if (!files.ContainsKey("/sce_sys/keystone")) AddOverlay("/sce_sys/keystone", Crypto.CreateKeystone(passcode));
        if (!files.ContainsKey("/sce_sys/about/right.sprx"))
        {
            byte[]? right = ProsperoPlayGo.GetRightSprx();
            if (right is { Length: > 0 }) AddOverlay("/sce_sys/about/right.sprx", right);
        }
        foreach (var file in files.Values.Where(f => IsRepairCandidate(f.Path)))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (file.Length > ProsperoStreamingFolderSource.MaximumUcpOverlaySize)
                throw new NotSupportedException("UCP metadata exceeds the bounded repair limit: " + file.Path);
            using var stream = file.OpenRead();
            byte[] bytes = new byte[checked((int)file.Length)];
            stream.ReadExactly(bytes);
            if (stream.ReadByte() != -1) throw new InvalidDataException("Source grew: " + file.Path);
            if (ProsperoUcp.IsUcp(bytes) && !ProsperoUcp.VerifyDigest(bytes))
                AddOverlay(file.Path, ProsperoUcp.WithRepairedDigest(bytes));
        }
        var result = new List<ProsperoPs5InnerFileSource>();
        foreach (var file in files.Values)
        {
            if (overlays.ContainsKey(file.Path)) continue;
            ProsperoStreamingFself? converted = null;
            if (signExecutableModules)
            {
                cancellationToken.ThrowIfCancellationRequested();
                using var reader = file.OpenRead();
                byte[] header = new byte[(int)Math.Min(file.Length, ProsperoInnerFileClassifier.HeaderLength)];
                reader.ReadExactly(header);
                bool elf = header.Length >= 4 && header[0] == 0x7f && header[1] == (byte)'E' && header[2] == (byte)'L' && header[3] == (byte)'F';
                if (ProsperoInnerFileClassifier.Classify(header) == ProsperoInnerFilePolicy.RequiresModuleConversion ||
                    elf && header.Length < ProsperoInnerFileClassifier.HeaderLength)
                    converted = ProsperoStreamingFself.Create(file, cancellationToken);
            }
            if (converted is null)
                result.Add(new ProsperoPs5InnerFileSource { Path = file.Path, Length = file.Length,
                    OpenRead = () => OpenPrepared(file, cancellationToken) });
            else
                result.Add(new ProsperoPs5InnerFileSource { Path = file.Path, Length = converted.Length,
                    OpenRead = () => converted.OpenRead(cancellationToken) });
        }
        foreach (var (path, bytes) in overlays)
        {
            foreach (var directory in catalog.Directories)
                if (string.Equals(directory.Path, path, StringComparison.OrdinalIgnoreCase) ||
                    path.StartsWith(directory.Path + "/", StringComparison.OrdinalIgnoreCase) &&
                    !path.StartsWith(directory.Path + "/", StringComparison.Ordinal))
                    throw new ArgumentException("Generated metadata conflicts with a source path: " + path, nameof(catalog));
            foreach (var file in catalog.Files)
                if ((string.Equals(file.Path, path, StringComparison.OrdinalIgnoreCase) && !files.ContainsKey(path)) ||
                    path.StartsWith(file.Path + "/", StringComparison.OrdinalIgnoreCase))
                    throw new ArgumentException("Generated metadata conflicts with a source path: " + path, nameof(catalog));
            files.TryGetValue(path, out var original);
            result.Add(new ProsperoPs5InnerFileSource { Path = path, Length = bytes.LongLength, OpenRead = () =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (original is null) catalog.Validate();
                else original.Validate();
                return new MemoryStream(bytes, writable: false);
            }});
        }
        return Array.AsReadOnly(result.OrderBy(f => f.Path, StringComparer.Ordinal).ToArray());
    }

    private static bool IsRepairCandidate(string path)
    {
        string prefix = path.StartsWith("/sce_sys/trophy2/", StringComparison.Ordinal) ? "/sce_sys/trophy2/"
            : path.StartsWith("/sce_sys/uds/", StringComparison.Ordinal) ? "/sce_sys/uds/" : "";
        return prefix.Length > 0 && path[prefix.Length..].IndexOf('/') < 0 && path.EndsWith(".ucp", StringComparison.OrdinalIgnoreCase);
    }

    private static Stream OpenPrepared(ProsperoSourceFile file, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        Stream source = file.OpenRead();
        try
        {
            byte[] header = new byte[(int)Math.Min(file.Length, ProsperoInnerFileClassifier.HeaderLength)];
            source.ReadExactly(header);
            bool elf = header.Length >= 4 && header[0] == 0x7f && header[1] == (byte)'E' && header[2] == (byte)'L' && header[3] == (byte)'F';
            if (ProsperoInnerFileClassifier.Classify(header) == ProsperoInnerFilePolicy.RequiresModuleConversion ||
                elf && header.Length < ProsperoInnerFileClassifier.HeaderLength)
                throw new NotSupportedException("Raw ELF requires a prepared signed module before streaming: " + file.Path);
            return new PreparedReader(header, source, token);
        }
        catch { source.Dispose(); throw; }
    }

    private sealed class PreparedReader(byte[] header, Stream source, CancellationToken token) : Stream
    {
        private int cursor;
        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
        public override int Read(Span<byte> buffer)
        {
            token.ThrowIfCancellationRequested();
            if (buffer.Length == 0) return 0;
            if (cursor < header.Length)
            {
                int n = Math.Min(buffer.Length, header.Length - cursor);
                header.AsSpan(cursor, n).CopyTo(buffer);
                cursor += n;
                return n;
            }
            return source.Read(buffer);
        }
        protected override void Dispose(bool disposing) { if (disposing) source.Dispose(); base.Dispose(disposing); }
        public override bool CanRead => source.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
