// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
#nullable enable
using LibProsperoPkg.Metadata;
using LibProsperoPkg.PFS;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace LibProsperoPkg.PKG;

/// <summary>Options for prepared-folder debug FPKG generation without intermediate images.</summary>
public sealed class ProsperoStreamingPackageOptions
{
    /// <summary>Required for folder generation; unused by the catalog overload.</summary>
    public string SourceFolder { get; init; } = "";
    /// <summary>Local destination for BuildLocalStreaming; an opaque result label for WriteStreaming.</summary>
    public required string OutputPath { get; init; }
    /// <summary>Defaults to the supplied param.json contentId. An override is applied only in memory.</summary>
    public string? ContentId { get; init; }
    public string Passcode { get; init; } = new('0', 32);
    public ProsperoVolumeType VolumeType { get; init; } = ProsperoVolumeType.Application;
    public bool UseKraken { get; init; } = true;
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
    /// <summary>Optional fixed 16-byte outer seed for reproducible image geometry/encryption.</summary>
    public byte[]? ImageSeed { get; init; }
    /// <summary>Small CNT metadata replacements relative to sce_sys; source files remain untouched.</summary>
    public IReadOnlyDictionary<string, byte[]>? MetadataOverrides { get; init; }
}

public readonly record struct ProsperoStreamingProgress(string Stage, long BytesWritten);

/// <summary>
/// Generated package summary, retaining no payload or block tables. BuildLocalStreaming returns
/// after publication; WriteStreaming leaves validation/publication to its caller.
/// </summary>
public sealed class ProsperoStreamingPackageResult
{
    public required string OutputPath { get; init; }
    public required string ContentId { get; init; }
    public required long PackageSize { get; init; }
    public required long MountSize { get; init; }
    public required long PfsSize { get; init; }
    public required long InnerStoredSize { get; init; }
    public required long InnerLogicalSize { get; init; }
    public required int SourceFileCount { get; init; }
}

public static partial class ProsperoPkgBuilder
{
    /// <summary>
    /// Streams a prepared folder to the selected local .part file, finalizes its CNT/FIH, reads that
    /// same file once for SI integrity, appends SI, validates structure, and publishes without overwrite.
    /// Raw executable conversion, RAR, FTP and large-game SI profiles are separate facilities.
    /// </summary>
    public static ProsperoStreamingPackageResult BuildLocalStreaming(ProsperoStreamingPackageOptions options,
        Func<string, bool>? confirmDeleteExistingPart = null,
        Action<ProsperoStreamingProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.SourceFolder);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.OutputPath);
        string outputPath = Path.GetFullPath(options.OutputPath);
        RequireOutputOutsideSource(Path.GetFullPath(options.SourceFolder), outputPath);
        var generate = PrepareStreamingPackage(options, outputPath, progress, cancellationToken);
        return ProsperoLocalPackageOutput.Write(outputPath, (file, token) =>
        {
            var result = generate(new LocalStreamingPackageOutput(file));
            token.ThrowIfCancellationRequested();
            progress?.Invoke(new("Validating package", result.PackageSize));
            var report = ProsperoPkgValidator.Validate(ProsperoPkgReader.Read(file), result.ContentId);
            if (!report.Accepted)
                throw new InvalidDataException("Generated package failed structural validation: " +
                    string.Join("; ", report.Checks.Where(c => c.Status == ProsperoCheckStatus.Fail).Select(c => c.Detail)));
            token.ThrowIfCancellationRequested();
            return result;
        }, confirmDeleteExistingPart, cancellationToken);
    }

    /// <summary>
    /// Generates a prepared-folder package through append/patch/integrity operations. OutputPath is
    /// only a result label here, never a local path opened by this method. The caller owns exclusive
    /// output creation, source/output separation, validation, publication and failure cleanup.
    /// A returned summary means generation completed, not that a remote package was published.
    /// </summary>
    public static ProsperoStreamingPackageResult WriteStreaming(ProsperoStreamingPackageOptions options,
        IProsperoStreamingPackageOutput output, Action<ProsperoStreamingProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(output);
        return PrepareStreamingPackage(options, options.OutputPath, progress, cancellationToken)(output);
    }

    /// <summary>Generate from a caller-provided source catalog, without using SourceFolder.</summary>
    public static ProsperoStreamingPackageResult WriteStreaming(ProsperoStreamingPackageOptions options,
        ProsperoSourceCatalog source, IProsperoStreamingPackageOutput output,
        Action<ProsperoStreamingProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(output);
        return PrepareStreamingPackage(options, options.OutputPath, progress, cancellationToken, source)(output);
    }

    private static Func<IProsperoStreamingPackageOutput, ProsperoStreamingPackageResult> PrepareStreamingPackage(
        ProsperoStreamingPackageOptions options, string outputPath,
        Action<ProsperoStreamingProgress>? progress, CancellationToken cancellationToken, ProsperoSourceCatalog? source = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (source is null) ArgumentException.ThrowIfNullOrWhiteSpace(options.SourceFolder);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.OutputPath);
        if (options.Passcode is not { Length: 32 }) throw new ArgumentException("Passcode must contain 32 characters.", nameof(options));
        if (!Enum.IsDefined(options.VolumeType)) throw new ArgumentOutOfRangeException(nameof(options));
        if (options.ImageSeed is not null && options.ImageSeed.Length != 16)
            throw new ArgumentException("Image seed must contain 16 bytes.", nameof(options));
        string sourceFolder = source is null ? Path.GetFullPath(options.SourceFolder) : "";
        cancellationToken.ThrowIfCancellationRequested();
        progress?.Invoke(new("Inspecting source", 0));
        var catalog = source ?? ProsperoStreamingFolderSource.Inspect(sourceFolder, cancellationToken);
        var innerFiles = ProsperoStreamingCatalogSource.Create(catalog, options.Passcode, cancellationToken);
        if (options.VolumeType == ProsperoVolumeType.Application && !innerFiles.Any(f => f.Path == "/eboot.bin"))
            throw new InvalidDataException("Prepared application source requires eboot.bin.");
        var overrides = SnapshotStreamingOverrides(options.MetadataOverrides);
        SnapshotStreamingMetadata(catalog, overrides, cancellationToken);
        byte[] paramBytes = overrides.TryGetValue("param.json", out var supplied)
            ? supplied : throw new FileNotFoundException("Prepared source requires sce_sys/param.json.");
        if (paramBytes.Length > 4 * 1024 * 1024) throw new InvalidDataException("param.json exceeds the 4 MiB metadata limit.");
        var param = ProsperoParam.Parse(Encoding.UTF8.GetString(paramBytes));
        string contentId = options.ContentId ?? param.ContentId
            ?? throw new InvalidDataException("param.json has no contentId; supply one explicitly.");
        if (contentId.Length != 36) throw new ArgumentException("Content id must contain 36 characters.", nameof(options));
        if (options.ContentId is not null)
        {
            param.ContentId = contentId;
            paramBytes = Encoding.UTF8.GetBytes(param.ToJson());
        }
        overrides["param.json"] = paramBytes;
        byte[] seed = options.ImageSeed?.ToArray() ?? RandomNumberGenerator.GetBytes(16);
        byte[] ekpfs = ProsperoPfsKeys.DeriveEkpfs(contentId, options.Passcode);
        long seconds = options.Timestamp.ToUnixTimeSeconds();
        var props = new ProsperoPkgBuildProperties
        {
            SourceFolder = sourceFolder, ContentId = contentId, Passcode = options.Passcode,
            TimeStamp = options.Timestamp.UtcDateTime, VolumeType = options.VolumeType,
        };
        var assembler = new ProsperoPs5InnerImageAssembler(seconds, 0, options.UseKraken);
        return output =>
        {
            var token = cancellationToken;
            using var file = new StreamingPackageAppendStream(output, token);
            // Reserve only the fixed FIH block. All variable-sized metadata follows the data-first PFS.
            file.Write(new byte[BlockSize]);
            progress?.Invoke(new("Writing PFS", file.Position));
            ProsperoPs5InnerImageLayout? inner = null;
            byte[]? naps = null;
            using var imageOutput = new StreamingImageOutput(file, token, progress);
            var outer = ProsperoOuterPfsBuilder.WriteForPackage(imageOutput, new[]
            {
                new ProsperoOuterFileProducer
                {
                    Name = "pfs_image.dat", WritePayload = sink =>
                    {
                        inner = assembler.Write(sink, innerFiles, token);
                        return checked(inner.Ndblock * BlockSize);
                    },
                },
                new ProsperoOuterFileProducer
                {
                    Name = "naps_pkg_layout.dat", Signed = true, WritePayload = sink =>
                    {
                        token.ThrowIfCancellationRequested();
                        naps = ProsperoNwonlyNapsGenerator.Generate(inner!);
                        sink.Write(naps);
                        return null;
                    },
                },
            }, new ProsperoOuterPfsBuildParameters { Seed = seed, TimestampSeconds = seconds }, ekpfs, token);
            token.ThrowIfCancellationRequested();
            progress?.Invoke(new("Finalizing CNT and FIH", file.Position));
            var layout = inner!;
            byte[] fih = ProsperoFihBuilder.BuildDebugHeader(new ProsperoFihHeaderMetadata
            {
                PfsSize = outer.PfsSize, SuperblockIndex = outer.SuperblockIndex,
                SuperblockDigest = outer.GetBlockDigest(outer.SuperblockIndex),
                InnerStoredBlockCount = outer.FileBlockCount[0], InnerLogicalBlockCount = layout.Ndblock,
                InnerMetadataBaseBlock = layout.MetaBaseLogical / BlockSize, NapsLength = naps!.LongLength,
                NapsDigest = ProsperoImageDigests.Sha3_256(naps),
                InnerContentInodes = layout.Nodes.Count(n => n.ParentInode >= 0),
                AppFileCount = layout.Nodes.Count(n => !n.IsDirectory && n.ParentInode >= 0 && n.Mode == NonSceSysFileMode),
                ContentVersionHi = ContentVersionHigh(param.ContentVersion ?? "01.000.000"),
            });
            var container = BuildEmbeddedContainer(props, outer, fih, seed,
                checked((uint)layout.Nodes.Count(n => !n.IsDirectory)), overrides, metadataSnapshotOnly: true);
            token.ThrowIfCancellationRequested();
            long cntOffset = checked(BlockSize + outer.PfsSize);
            if (file.Position != cntOffset) throw new InvalidDataException("Unexpected streamed outer image length.");
            file.Write(container.Bytes);
            long mountSize = file.Position;
            file.Flush();
            for (int offset = 0; offset < fih.Length; offset += 1024)
            {
                token.ThrowIfCancellationRequested();
                output.Patch(offset, fih.AsSpan(offset, Math.Min(1024, fih.Length - offset)));
            }
            file.Flush();
            progress?.Invoke(new("Hashing finalized mount", mountSize));
            var digests = output.FinalizeMount(mountSize,
                checked((outer.SuperblockIndex + 1L) * BlockSize), token);
            if (digests is null || digests.Length != mountSize)
                throw new InvalidDataException("Output integrity metadata does not cover the finalized mount.");
            if (!digests.SuperblockDigest.Span.SequenceEqual(outer.GetBlockDigest(outer.SuperblockIndex).Span))
                throw new InvalidDataException("Output integrity metadata has an unexpected superblock digest.");
            token.ThrowIfCancellationRequested();
            container.Xml.NestedInnerLayout = layout;
            container.Xml.ChunkInfo = new ProsperoChunkInfoModel
            {
                PlayGoChunkDatSize = container.PlayGoChunkDat?.Length ?? 0,
                TotalSize = cntOffset, Outer0Size = checked(outer.FileBlockCount[0] * (long)BlockSize),
                Outer1Size = cntOffset - checked(outer.FileBlockCount[0] * (long)BlockSize),
            };
            progress?.Invoke(new("Writing SI", mountSize));
            byte[] si = ProsperoSiArchive.BuildDebugSiSegmentFromDigests(container.Xml, container.PlayGoChunkDat, digests);
            token.ThrowIfCancellationRequested();
            if (file.Position != mountSize) throw new InvalidDataException("Mount hashing changed the output extent.");
            file.Write(si);
            long packageSize = file.Position;
            file.Flush();
            token.ThrowIfCancellationRequested();
            return new ProsperoStreamingPackageResult
            {
                OutputPath = outputPath, ContentId = contentId, PackageSize = packageSize,
                MountSize = mountSize, PfsSize = outer.PfsSize, InnerStoredSize = layout.OutputLength,
                InnerLogicalSize = checked(layout.Ndblock * BlockSize), SourceFileCount = innerFiles.Count,
            };
        };
    }

    private static Dictionary<string, byte[]> SnapshotStreamingOverrides(IReadOnlyDictionary<string, byte[]>? source)
    {
        var result = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        long total = 0;
        if (source is null) return result;
        foreach (var (name, bytes) in source)
        {
            if (bytes is null) throw new ArgumentException("Null metadata replacement.", nameof(source));
            total = checked(total + bytes.LongLength);
            if (total > 64 * 1024 * 1024) throw new InvalidDataException("CNT replacements exceed the 64 MiB metadata limit.");
            result.Add(name, bytes.ToArray());
        }
        return result;
    }

    // Freeze small CNT inputs before writing payloads. Construction must never fall back to disk:
    // a changed/new media file could otherwise be a link to the growing output or an unbounded file.
    private static void SnapshotStreamingMetadata(ProsperoSourceCatalog catalog, Dictionary<string, byte[]> snapshot,
        CancellationToken token)
    {
        const long limit = 64 * 1024 * 1024;
        long total = snapshot.Values.Sum(bytes => (long)bytes.Length);
        catalog.Validate();
        foreach (var file in catalog.Files)
        {
            token.ThrowIfCancellationRequested();
            if (!file.Path.StartsWith("/sce_sys/", StringComparison.Ordinal)) continue;
            string relative = file.Path[9..];
            bool param = relative == "param.json";
            if (!param && !ProsperoCntEntryNames.NameToId.ContainsKey(relative)) continue;
            if (relative is "imagedigs.dat" or "playgo-chunk.dat" or "playgo-hash-table.dat" or "playgo-ficm.dat") continue;
            if (snapshot.ContainsKey(relative)) continue;
            long available = param ? Math.Min(limit - total, 4 * 1024 * 1024) : limit - total;
            if (file.Length > available)
                throw new InvalidDataException("CNT source metadata exceeds its bounded snapshot budget: " + relative);
            using var reader = file.OpenRead();
            byte[] bytes = new byte[checked((int)file.Length)];
            reader.ReadExactly(bytes);
            if (reader.ReadByte() != -1) throw new InvalidDataException("Source metadata grew during inspection.");
            total += file.Length;
            snapshot.Add(relative, bytes);
        }
    }

    private static void RequireOutputOutsideSource(string source, string output)
    {
        static string Canonical(string path, int depth = 0)
        {
            if (depth > 64) throw new IOException("Too many symbolic path aliases.");
            string full = Path.GetFullPath(path);
            string root = Path.GetPathRoot(full)!;
            string current = root;
            foreach (string component in full[root.Length..].Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
            {
                current = Path.Combine(current, component);
                if (!File.Exists(current) && !Directory.Exists(current)) continue;
                var attributes = File.GetAttributes(current);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                {
                    FileSystemInfo info = (attributes & FileAttributes.Directory) != 0
                        ? new DirectoryInfo(current) : new FileInfo(current);
                    string target = info.ResolveLinkTarget(true)?.FullName
                        ?? throw new IOException("Cannot resolve an output/source path alias.");
                    current = Canonical(target, depth + 1);
                }
            }
            return Path.TrimEndingDirectorySeparator(current);
        }
        string root = Canonical(source);
        string destination = Canonical(output);
        var comparison = OperatingSystem.IsWindows() || OperatingSystem.IsMacOS()
            ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (destination.Equals(root, comparison) || destination.StartsWith(root + Path.DirectorySeparatorChar, comparison))
            throw new ArgumentException("Package output must be outside the source folder.", nameof(output));
    }

    private sealed class StreamingImageOutput(Stream destination, CancellationToken token,
        Action<ProsperoStreamingProgress>? progress) : Stream
    {
        private long written;
        private long reported;
        public override void Write(ReadOnlySpan<byte> bytes)
        {
            token.ThrowIfCancellationRequested();
            destination.Write(bytes);
            written = checked(written + bytes.Length);
            if (written - reported >= 4 * 1024 * 1024)
            {
                reported = written;
                progress?.Invoke(new("Writing PFS", checked(BlockSize + written)));
            }
        }
        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => destination.Flush();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
