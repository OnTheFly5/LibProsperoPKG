// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace LibProsperoPkg.PKG;

/// <summary>A source file's normalized absolute path, stable length and reader.</summary>
public sealed class ProsperoSourceFile
{
    public required string Path { get; init; }
    public required long Length { get; init; }
    /// <summary>Open a new reader over the original bytes. The caller owns the stream.</summary>
    public required Func<Stream> OpenRead { get; init; }
    /// <summary>Throw if the source changed since cataloging.</summary>
    public required Action Validate { get; init; }
}

/// <summary>A source directory, including directories with no files.</summary>
public sealed class ProsperoSourceDirectory
{
    public required string Path { get; init; }
    public required Action Validate { get; init; }
}

/// <summary>
/// Immutable source-tree metadata. Paths are absolute, slash-separated and case-sensitive;
/// case-insensitive collisions are rejected. The provider owns mutation detection. Readers
/// also check their declared length and validate at EOF. No payload is retained.
/// </summary>
public sealed class ProsperoSourceCatalog
{
    private readonly Action? validateRoot;
    public IReadOnlyList<ProsperoSourceDirectory> Directories { get; }
    public IReadOnlyList<ProsperoSourceFile> Files { get; }

    public ProsperoSourceCatalog(IEnumerable<ProsperoSourceDirectory> directories, IEnumerable<ProsperoSourceFile> files, Action? validateRoot = null)
    {
        this.validateRoot = validateRoot;
        ArgumentNullException.ThrowIfNull(directories);
        ArgumentNullException.ThrowIfNull(files);
        var paths = new Dictionary<string, (string Path, bool Directory)>(StringComparer.OrdinalIgnoreCase);
        var dirs = new List<ProsperoSourceDirectory>();
        var entries = new List<ProsperoSourceFile>();
        void Add(string path, bool directory)
        {
            if (string.IsNullOrEmpty(path) || path[0] != '/' || path.Length == 1 ||
                path[1..].Split('/').Any(component => component.Length == 0 || component.Length > 255 ||
                    component is "." or ".." || component.Any(c => c > 0x7f || char.IsControl(c) || c == '\\')))
                throw new ArgumentException("Invalid source catalog path: " + path);
            if (!paths.TryAdd(path, (path, directory)))
                throw new ArgumentException("Case-insensitive source path collision: " + path);
        }
        foreach (var dir in directories)
        {
            ArgumentNullException.ThrowIfNull(dir);
            ArgumentNullException.ThrowIfNull(dir.Validate);
            Add(dir.Path, true);
            dirs.Add(new ProsperoSourceDirectory { Path = dir.Path, Validate = dir.Validate });
        }
        foreach (var file in files)
        {
            ArgumentNullException.ThrowIfNull(file);
            ArgumentOutOfRangeException.ThrowIfNegative(file.Length);
            ArgumentNullException.ThrowIfNull(file.OpenRead);
            ArgumentNullException.ThrowIfNull(file.Validate);
            Add(file.Path, false);
            var captured = file;
            entries.Add(new ProsperoSourceFile { Path = file.Path, Length = file.Length, Validate = file.Validate,
                OpenRead = () => OpenChecked(captured) });
        }
        foreach (string path in paths.Keys)
        {
            int slash = path.LastIndexOf('/');
            if (slash > 0 && (!paths.TryGetValue(path[..slash], out var parent) || !parent.Directory ||
                !string.Equals(parent.Path, path[..slash], StringComparison.Ordinal)))
                throw new ArgumentException("Source parent directory is missing or has different case: " + path);
        }
        Directories = Array.AsReadOnly(dirs.OrderBy(d => d.Path, StringComparer.Ordinal).ToArray());
        Files = Array.AsReadOnly(entries.OrderBy(f => f.Path, StringComparer.Ordinal).ToArray());
    }

    /// <summary>Validate all captured entries, including empty directories.</summary>
    public void Validate()
    {
        validateRoot?.Invoke();
        foreach (var directory in Directories) directory.Validate();
        foreach (var file in Files) file.Validate();
    }

    private static Stream OpenChecked(ProsperoSourceFile file)
    {
        file.Validate();
        Stream source = file.OpenRead() ?? throw new InvalidDataException("Source reader is null: " + file.Path);
        try
        {
            if (!source.CanRead) throw new InvalidDataException("Source reader is not readable: " + file.Path);
            file.Validate();
            return new CheckedReader(source, file.Length, file.Validate, file.Path);
        }
        catch { source.Dispose(); throw; }
    }

    private sealed class CheckedReader(Stream source, long length, Action validate, string path) : Stream
    {
        private long count;
        private bool finished;
        public override int Read(byte[] buffer, int offset, int length) => Read(buffer.AsSpan(offset, length));
        public override int Read(Span<byte> buffer)
        {
            if (buffer.IsEmpty || finished) return 0;
            int read = source.Read(buffer);
            count = checked(count + read);
            if (count > length) throw new InvalidDataException("Source grew after cataloging: " + path);
            if (read == 0)
            {
                if (count != length) throw new InvalidDataException("Source shrank after cataloging: " + path);
                validate();
                finished = true;
            }
            return read;
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
