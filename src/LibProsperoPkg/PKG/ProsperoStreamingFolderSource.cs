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
    /// <summary>Complete unmodified source tree, including CNT metadata and empty directories.</summary>
    public ProsperoSourceCatalog Catalog { get; }

    private ProsperoStreamingFolderSource(string folder, IReadOnlyList<ProsperoPs5InnerFileSource> files, ProsperoSourceCatalog catalog)
    {
        SourceFolder = folder;
        Files = files;
        Catalog = catalog;
    }

    /// <summary>Inspect the original folder without generating package metadata.</summary>
    public static ProsperoSourceCatalog Inspect(string folder, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(folder);
        string root = Path.GetFullPath(folder);
        if (!Directory.Exists(root)) throw new DirectoryNotFoundException("Prepared game folder does not exist.");
        CheckDirectory(root);
        var rootInfo = new DirectoryInfo(root);
        DateTime rootModified = rootInfo.LastWriteTimeUtc;
        DateTime rootCreated = rootInfo.CreationTimeUtc;
        void ValidateRoot()
        {
            CheckDirectory(root);
            var current = new DirectoryInfo(root);
            if (current.LastWriteTimeUtc != rootModified || current.CreationTimeUtc != rootCreated)
                throw new InvalidDataException("Source root changed after cataloging.");
        }
        var allEntries = new List<Entry>();
        var directories = new List<ProsperoSourceDirectory>();
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
                    var dirInfo = new DirectoryInfo(path);
                    DateTime modified = dirInfo.LastWriteTimeUtc;
                    DateTime created = dirInfo.CreationTimeUtc;
                    directories.Add(new ProsperoSourceDirectory { Path = "/" + rel, Validate = () =>
                    {
                        ValidateRoot();
                        string? parent = Path.GetDirectoryName(path);
                        while (parent is not null && parent.Length >= root.Length)
                        {
                            CheckDirectory(parent);
                            if (string.Equals(parent, root, StringComparison.Ordinal)) break;
                            parent = Path.GetDirectoryName(parent);
                        }
                        CheckDirectory(path);
                        var current = new DirectoryInfo(path);
                        if (current.LastWriteTimeUtc != modified || current.CreationTimeUtc != created)
                            throw new InvalidDataException("Source directory changed after cataloging: " + rel);
                    }});
                    Walk(path, rel);
                    continue;
                }
                var entry = new Entry(root, path, rel);
                allEntries.Add(entry);

            }
        }
        Walk(root, "");
        var catalog = new ProsperoSourceCatalog(directories, allEntries.Select(entry => new ProsperoSourceFile
        {
            Path = "/" + entry.Relative, Length = entry.Length, OpenRead = entry.OpenRaw, Validate = entry.Validate,
        }), ValidateRoot);
        catalog.Validate();
        return catalog;
    }

    /// <summary>Prepare a folder for inner-image generation, retaining source bytes unchanged.</summary>
    public static ProsperoStreamingFolderSource Create(string folder, string passcode,
        CancellationToken cancellationToken = default)
    {
        var catalog = Inspect(folder, cancellationToken);
        var files = ProsperoStreamingCatalogSource.Create(catalog, passcode, cancellationToken);
        return new ProsperoStreamingFolderSource(Path.GetFullPath(folder), files, catalog);
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
    }
}
