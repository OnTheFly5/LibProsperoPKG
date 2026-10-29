using LibProsperoPkg.Content;
using LibProsperoPkg.Metadata;
using LibProsperoPkg.PFS;
using LibProsperoPkg.PKG;
using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace LibProsperoPkg.Tests;

internal static class PackageStreamingTests
{
    private const int B = 0x10000;
    private const string Id = "UP9000-PPSA99099_00-PROSPERO00000000";
    internal static void Run()
    {
        FolderToPackage();
        CallbackOutput();
        FailedJobsLeaveNoOutput();
        FrozenMetadataAndBudgets();
        ParamMetadataEdits();
        ManifestMetadataEdits();
    }

    private static byte[] Module()
    {
        var elf = new byte[0x180];
        new byte[] { 0x7f, (byte)'E', (byte)'L', (byte)'F', 2, 1, 1 }.CopyTo(elf, 0);
        BinaryPrimitives.WriteUInt16LittleEndian(elf.AsSpan(0x10), 2);
        BinaryPrimitives.WriteUInt16LittleEndian(elf.AsSpan(0x12), 62);
        BinaryPrimitives.WriteUInt32LittleEndian(elf.AsSpan(0x14), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(elf.AsSpan(0x20), 0x40);
        BinaryPrimitives.WriteUInt16LittleEndian(elf.AsSpan(0x34), 0x40);
        BinaryPrimitives.WriteUInt16LittleEndian(elf.AsSpan(0x36), 0x38);
        BinaryPrimitives.WriteUInt16LittleEndian(elf.AsSpan(0x38), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(elf.AsSpan(0x40), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(elf.AsSpan(0x44), 5);
        BinaryPrimitives.WriteUInt64LittleEndian(elf.AsSpan(0x48), 0x100);
        BinaryPrimitives.WriteUInt64LittleEndian(elf.AsSpan(0x50), 0x400000);
        BinaryPrimitives.WriteUInt64LittleEndian(elf.AsSpan(0x60), 0x80);
        BinaryPrimitives.WriteUInt64LittleEndian(elf.AsSpan(0x68), 0x80);
        BinaryPrimitives.WriteUInt64LittleEndian(elf.AsSpan(0x70), 0x1000);
        elf.AsSpan(0x100).Fill(0x90);
        return ProsperoFself.MakeFself(elf);
    }

    private static string Setup(string directory)
    {
        string source = Path.Combine(directory, "source");
        Directory.CreateDirectory(Path.Combine(source, "sce_sys"));
        File.WriteAllText(Path.Combine(source, "sce_sys", "param.json"),
            ProsperoParam.CreateDefault(Id, "PPSA99099", "Streaming fixture").ToJson());
        File.WriteAllBytes(Path.Combine(source, "eboot.bin"), Module());
        byte[] data = new byte[0x80000 + 123];
        new Random(71).NextBytes(data);
        data.AsSpan(0, 0x40000).Fill(0x55);
        Directory.CreateDirectory(Path.Combine(source, "assets"));
        File.WriteAllBytes(Path.Combine(source, "assets", "data.bin"), data);
        File.WriteAllBytes(Path.Combine(source, "empty"), Array.Empty<byte>());
        return source;
    }

    private static Dictionary<string, string> Snapshot(string folder) => Directory
        .EnumerateFiles(folder, "*", SearchOption.AllDirectories).ToDictionary(p => Path.GetRelativePath(folder, p),
            p => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(p))) + ":" + File.GetLastWriteTimeUtc(p).Ticks);

    private static void Same(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> actual, string context)
        => Program.Equal(true, expected.SequenceEqual(actual), context);

    private static void FolderToPackage()
    {
        string root = Path.Combine(Path.GetTempPath(), "prospero-pipeline-" + Guid.NewGuid());
        Directory.CreateDirectory(root);
        try
        {
            string source = Setup(root);
            var original = Snapshot(source);
            foreach (bool kraken in new[] { true, false })
            {
                string target = Path.Combine(root, kraken ? "compressed.pkg" : "stored.pkg");
                var stages = new List<string>();
                var result = ProsperoPkgBuilder.BuildLocalStreaming(new ProsperoStreamingPackageOptions
                {
                    SourceFolder = source, OutputPath = target, UseKraken = kraken,
                    ImageSeed = new byte[16], Timestamp = DateTimeOffset.FromUnixTimeSeconds(12345678),
                }, progress: p => stages.Add(p.Stage));
                Program.Equal(target, result.OutputPath, "published target path");
                Program.Equal(result.PackageSize, new FileInfo(target).Length, "final size includes SI");
                Program.Equal(false, File.Exists(target + ".part"), "part removed only after publication");
                Program.Equal(true, stages.Contains("Hashing finalized mount") && stages.Contains("Writing SI"), "complete finalization stages");
                foreach (var (path, state) in original) Program.Equal(state, Snapshot(source)[path], "source bytes and timestamps preserved");
                Program.Equal(original.Count, Snapshot(source).Count, "no generated files in source");
                VerifyPackage(target, source, result, kraken);
            }
            Program.Equal(2, Directory.GetFiles(root).Length, "only selected output packages are created");
            Program.Equal(1, Directory.GetDirectories(root).Length, "no staging directory");
        }
        finally { Directory.Delete(root, true); }
    }

    private static void VerifyPackage(string target, string source, ProsperoStreamingPackageResult result, bool kraken)
    {
        VerifyPackage(File.ReadAllBytes(target), source, result, kraken);
    }

    private static void VerifyPackage(byte[] package, string source, ProsperoStreamingPackageResult result, bool kraken)
    {
        using var packageReader = new MemoryStream(package, writable: false);
        var parsed = ProsperoPkgReader.Read(packageReader);
        Program.Equal(ProsperoPkgType.FullDebug, parsed.Type, "full FIH package parsed");
        Program.Equal(Id, parsed.Header!.ContentId, "source content id used");
        Program.Equal(true, ProsperoPkgValidator.Validate(parsed, Id).Accepted, "structural acceptance gate");
        int sbIndex = checked((int)(BinaryPrimitives.ReadUInt64LittleEndian(package.AsSpan(0x20)) / B - 1));
        int innerBlocks = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(package.AsSpan(0x90)));
        byte[] outer = package.AsSpan(B, (int)result.PfsSize).ToArray();
        var kinds = Enumerable.Range(0, outer.Length / B).Select(i => i == sbIndex ? ProsperoOuterBlockKind.Plaintext
            : i < innerBlocks ? ProsperoOuterBlockKind.Data : ProsperoOuterBlockKind.Signed).ToArray();
        var (tweak, dataKey) = ProsperoPfsKeys.DeriveImageEncryptionKeys(ProsperoPfsKeys.DeriveEkpfs(Id, new('0', 32)), new byte[16]);
        ProsperoOuterPfsImage.Transform(outer, tweak, dataKey, B, kinds, encrypt: false);
        using var inodeReader = new MemoryStream(outer);
        inodeReader.Position = (sbIndex + 1L) * B + 3 * ProsperoDinodeS32.SizeOf;
        var innerInode = ProsperoDinodeS32.ReadFromStream(inodeReader);
        var napsInode = ProsperoDinodeS32.ReadFromStream(inodeReader);
        byte[] inner = outer.AsSpan(innerInode.db[0].block * B, (int)innerInode.Size).ToArray();
        byte[] naps = outer.AsSpan(napsInode.db[0].block * B, (int)napsInode.Size).ToArray();
        Same(ProsperoImageDigests.Sha3_256(naps), package.AsSpan(0xb0, 32), "FIH records NAPS hash");
        var mount = ProsperoPs5InnerImageReader.ReconstructMount(inner, naps, result.InnerLogicalSize);
        var recoveredFiles = ProsperoPs5InnerImageReader.ReadFileTree(mount.Mount, mount.SuperblockOffset);
        foreach (var file in recoveredFiles)
        {
            string originalPath = Path.Combine(source, file.Path.TrimStart('/').Replace('/', Path.DirectorySeparatorChar));
            if (File.Exists(originalPath)) Same(File.ReadAllBytes(originalPath), mount.Mount.AsSpan((int)file.LogicalOffset, (int)file.Size), "recovered complete source payload");
        }
        Program.Equal(true, recoveredFiles.Any(f => f.Path.EndsWith("assets/data.bin")), "asset recovered from NAPS");
        var catalog = ProsperoStreamingFolderSource.Create(source, new('0', 32));
        var assembler = new ProsperoPs5InnerImageAssembler(12345678, 0, kraken);
        var buffered = assembler.Build(catalog.Files.Select(f =>
        {
            using var reader = f.OpenRead();
            using var output = new MemoryStream(); reader.CopyTo(output);
            return new ProsperoPs5InnerFile { Path = f.Path, Data = output.ToArray() };
        }).ToArray());
        Same(buffered.Image, inner, "pipeline equals buffered inner builder");
        if (!kraken)
        {
            Program.Equal(true, buffered.Placements.All(p => p.StoreRaw), "Kraken off stores every file");
            Program.Equal(true, buffered.MetadataBlocks.All(b => b.CompressedSize == b.UncompressedSize), "Kraken off stores metadata too");
        }
        // Every serialized descriptor digest authenticates the corresponding final plaintext outer block.
        var imageDigests = parsed.Entries.Single(e => e.RawId == 0x40a);
        long cnt = (long)parsed.Fih!.EmbeddedCntOffset;
        for (int i = 0; i < kinds.Length; i++)
        {
            byte[] expected = package.AsSpan((int)(cnt + (long)imageDigests.DataOffset + i * 32), 32).ToArray();
            Array.Reverse(expected);
            Same(expected, ProsperoImageDigests.Sha3_256(outer.AsSpan(i * B, B)), "complete output block digests");
        }
        using var zipSource = new MemoryStream(package, (int)result.MountSize, package.Length - (int)result.MountSize, writable: false);
        using var zip = new ZipArchive(zipSource, ZipArchiveMode.Read);
        Program.Equal(8, zip.Entries.Count, "complete SI member set");
        using var crcReader = zip.Entries.Single(e => e.FullName.EndsWith("playgo-chunk.crc")).Open();
        using var crc = new MemoryStream(); crcReader.CopyTo(crc);
        Same(LibProsperoPkg.PlayGo.ProsperoPlayGo.BuildChunkCrc(package.AsSpan(0, (int)result.MountSize)), crc.ToArray(), "SI CRCs cover final mount");
    }

    private static void FailedJobsLeaveNoOutput()
    {
        string root = Path.Combine(Path.GetTempPath(), "prospero-pipeline-fail-" + Guid.NewGuid());
        Directory.CreateDirectory(root);
        try
        {
            string source = Setup(root);
            string target = Path.Combine(root, "game.pkg");
            ProsperoStreamingPackageOptions Options(string output) => new() { SourceFolder = source, OutputPath = output };
            Program.Throws<ArgumentException>(() => ProsperoPkgBuilder.BuildLocalStreaming(Options(Path.Combine(source, "out.pkg"))));
            Program.Equal(false, File.Exists(Path.Combine(source, "out.pkg.part")), "source-contained output rejected before create");
            using var cancelled = new CancellationTokenSource();
            Program.Throws<OperationCanceledException>(() => ProsperoPkgBuilder.BuildLocalStreaming(Options(target),
                progress: p => { if (p.Stage == "Finalizing CNT and FIH") cancelled.Cancel(); }, cancellationToken: cancelled.Token));
            Program.Equal(false, File.Exists(target) || File.Exists(target + ".part"), "cancel removes owned partial");
            Program.Throws<InvalidOperationException>(() => ProsperoPkgBuilder.BuildLocalStreaming(Options(target),
                progress: p => { if (p.Stage == "Writing SI") throw new InvalidOperationException("injected late failure"); }));
            Program.Equal(false, File.Exists(target) || File.Exists(target + ".part"), "late failure removes owned partial");
            byte[] original = File.ReadAllBytes(Path.Combine(source, "eboot.bin"));
            File.WriteAllBytes(Path.Combine(source, "eboot.bin"), new byte[] { 0x7f, 69, 76, 70, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 62, 0 });
            Program.Throws<NotSupportedException>(() => ProsperoPkgBuilder.BuildLocalStreaming(Options(target)));
            Program.Equal(false, File.Exists(target) || File.Exists(target + ".part"), "raw module failure leaves no package");
            File.WriteAllBytes(Path.Combine(source, "eboot.bin"), original);
            string alias = Path.Combine(root, "source-alias");
            if (!OperatingSystem.IsWindows())
            {
                Directory.CreateSymbolicLink(alias, source);
                Program.Throws<ArgumentException>(() => ProsperoPkgBuilder.BuildLocalStreaming(Options(Path.Combine(alias, "out.pkg"))));
            }
        }
        finally { Directory.Delete(root, true); }
    }
    private static void FrozenMetadataAndBudgets()
    {
        string root = Path.Combine(Path.GetTempPath(), "prospero-snapshot-" + Guid.NewGuid());
        Directory.CreateDirectory(root);
        try
        {
            string source = Setup(root);
            string target = Path.Combine(root, "frozen.pkg");
            string icon = Path.Combine(source, "sce_sys", "icon0.png");
            byte[] captured = new byte[] { 7, 8, 9 };
            File.WriteAllBytes(icon, captured);
            bool changed = false;
            var result = ProsperoPkgBuilder.BuildLocalStreaming(new ProsperoStreamingPackageOptions
            {
                SourceFolder = source, OutputPath = target,
            }, progress: p =>
            {
                if (p.Stage != "Finalizing CNT and FIH" || changed) return;
                changed = true;
                File.Delete(icon);
                if (!OperatingSystem.IsWindows()) File.CreateSymbolicLink(icon, target + ".part");
                else File.WriteAllBytes(icon, new byte[] { 1, 2, 3 });
                using var unexpected = new FileStream(Path.Combine(source, "sce_sys", "icon0.dds"), FileMode.CreateNew);
                unexpected.SetLength(64L * 1024 * 1024 + 1); // Must never be opened by CNT finalization.
            });
            Program.Equal(true, changed, "test mutates source metadata only after snapshot");
            var parsed = ProsperoPkgReader.Read(target);
            byte[] pkg = File.ReadAllBytes(target);
            var entry = parsed.Entries.Single(e => e.RawId == 0x1200);
            Same(captured, pkg.AsSpan((int)((long)parsed.Fih!.EmbeddedCntOffset + (long)entry.DataOffset), (int)entry.DataSize),
                "CNT uses frozen metadata instead of a changed file/output symlink");
            Program.Equal(false, parsed.Entries.Any(e => e.RawId == 0x1280), "new source metadata is not read after snapshot");
            File.Delete(icon);
            string tooLarge = Path.Combine(source, "sce_sys", "icon0.dds");
            string rejected = Path.Combine(root, "oversized.pkg");
            Program.Throws<InvalidDataException>(() => ProsperoPkgBuilder.BuildLocalStreaming(new ProsperoStreamingPackageOptions
            {
                SourceFolder = source, OutputPath = rejected,
            }));
            Program.Equal(false, File.Exists(rejected) || File.Exists(rejected + ".part"), "oversized metadata rejected before output creation");
        }
        finally { Directory.Delete(root, true); }
    }

    private static void ParamMetadataEdits()
    {
        string root = Path.Combine(Path.GetTempPath(), "prospero-param-overlay-" + Guid.NewGuid());
        Directory.CreateDirectory(root);
        try
        {
            string source = Setup(root);
            string paramPath = Path.Combine(source, "sce_sys", "param.json");
            var original = Snapshot(source);
            var edits = new ProsperoStreamingMetadataEdits { TitleId = "PPSA11111", TitleName = "Edited title", Version = "02.34", DrmType = ProsperoDrmType.Free };
            string output = Path.Combine(root, "edited.pkg");
            ProsperoPkgBuilder.BuildLocalStreaming(new ProsperoStreamingPackageOptions { SourceFolder = source, OutputPath = output, MetadataEdits = edits });
            var parsed = ProsperoPkgReader.Read(output);
            var entry = parsed.Entries.Single(e => e.RawId == 0x2000);
            byte[] pkg = File.ReadAllBytes(output);
            var param = ProsperoParam.Parse(Encoding.UTF8.GetString(pkg.AsSpan((int)((long)parsed.Fih!.EmbeddedCntOffset + (long)entry.DataOffset), (int)entry.DataSize)).TrimEnd('\0'));
            Program.Equal("PPSA11111", param.TitleId, "edited title id in CNT");
            Program.Equal("Edited title", param.GetTitleName("en-US"), "edited title in CNT");
            Program.Equal("02.34", param.MasterVersion, "edited master version in CNT");
            Program.Equal("02.034.000", param.ContentVersion, "edited content version in CNT");
            Program.Equal("free", param.ApplicationDrmType, "edited DRM in CNT");
            foreach (var (path, state) in original) Program.Equal(state, Snapshot(source)[path], "metadata edits preserve source");
            File.Delete(paramPath);
            var generated = new ProsperoStreamingMetadataEdits { GenerateMissingParam = true, TitleId = "PPSA99099", TitleName = "Generated" };
            string generatedPath = Path.Combine(root, "generated.pkg");
            ProsperoPkgBuilder.BuildLocalStreaming(new ProsperoStreamingPackageOptions { SourceFolder = source, OutputPath = generatedPath, ContentId = Id, MetadataEdits = generated });
            Program.Equal(false, File.Exists(paramPath), "generated param stays out of source");
            parsed = ProsperoPkgReader.Read(generatedPath);
            entry = parsed.Entries.Single(e => e.RawId == 0x2000);
            pkg = File.ReadAllBytes(generatedPath);
            param = ProsperoParam.Parse(Encoding.UTF8.GetString(pkg.AsSpan((int)((long)parsed.Fih!.EmbeddedCntOffset + (long)entry.DataOffset), (int)entry.DataSize)).TrimEnd('\0'));
            Program.Equal("Generated", param.GetTitleName("en-US"), "generated param in CNT");
            Program.Throws<ArgumentException>(() => ProsperoPkgBuilder.BuildLocalStreaming(new ProsperoStreamingPackageOptions { SourceFolder = source, OutputPath = Path.Combine(root, "invalid.pkg"), ContentId = Id, MetadataEdits = new() { GenerateMissingParam = true } }));
        }
        finally { Directory.Delete(root, true); }
    }

    private static void ManifestMetadataEdits()
    {
        string root = Path.Combine(Path.GetTempPath(), "prospero-manifest-overlay-" + Guid.NewGuid());
        Directory.CreateDirectory(root);
        try
        {
            string source = Setup(root);
            string path = Path.Combine(source, "manifest.json");
            File.WriteAllText(path, "{\"applicationName\":\"Before\",\"custom\":123}");
            var snapshot = Snapshot(source);
            var edits = new ProsperoStreamingMetadataEdits { Manifest = new() { Path = "/manifest.json", ApplicationName = "After", TwinTurbo = true } };
            string target = Path.Combine(root, "manifest.pkg");
            var result = ProsperoPkgBuilder.BuildLocalStreaming(new ProsperoStreamingPackageOptions { SourceFolder = source, OutputPath = target, ImageSeed = new byte[16], MetadataEdits = edits });
            byte[] package = File.ReadAllBytes(target);
            int sbIndex = checked((int)(BinaryPrimitives.ReadUInt64LittleEndian(package.AsSpan(0x20)) / B - 1));
            int innerBlocks = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(package.AsSpan(0x90)));
            byte[] outer = package.AsSpan(B, (int)result.PfsSize).ToArray();
            var kinds = Enumerable.Range(0, outer.Length / B).Select(i => i == sbIndex ? ProsperoOuterBlockKind.Plaintext : i < innerBlocks ? ProsperoOuterBlockKind.Data : ProsperoOuterBlockKind.Signed).ToArray();
            var (tweak, key) = ProsperoPfsKeys.DeriveImageEncryptionKeys(ProsperoPfsKeys.DeriveEkpfs(Id, new('0', 32)), new byte[16]);
            ProsperoOuterPfsImage.Transform(outer, tweak, key, B, kinds, encrypt: false);
            using var reader = new MemoryStream(outer);
            reader.Position = (sbIndex + 1L) * B + 3 * ProsperoDinodeS32.SizeOf;
            var inner = ProsperoDinodeS32.ReadFromStream(reader);
            var naps = ProsperoDinodeS32.ReadFromStream(reader);
            var mount = ProsperoPs5InnerImageReader.ReconstructMount(outer.AsSpan(inner.db[0].block * B, (int)inner.Size).ToArray(), outer.AsSpan(naps.db[0].block * B, (int)naps.Size).ToArray(), result.InnerLogicalSize);
            var entry = ProsperoPs5InnerImageReader.ReadFileTree(mount.Mount, mount.SuperblockOffset).Single(f => f.Path == "manifest.json");
            var manifest = ProsperoManifest.Parse(Encoding.UTF8.GetString(mount.Mount.AsSpan((int)entry.LogicalOffset, (int)entry.Size)));
            Program.Equal("After", manifest.ApplicationName, "manifest overlay in inner image");
            Program.Equal(true, manifest.TwinTurbo, "manifest flag in inner image");
            Program.Equal(123, (int)manifest.Root["custom"]!, "unknown manifest field retained");
            foreach (var (name, state) in snapshot) Program.Equal(state, Snapshot(source)[name], "manifest source preserved");
            File.Delete(path);
            Program.Throws<ArgumentException>(() => ProsperoPkgBuilder.BuildLocalStreaming(new ProsperoStreamingPackageOptions { SourceFolder = source, OutputPath = Path.Combine(root, "missing.pkg"), MetadataEdits = edits }));
            var generated = new ProsperoStreamingMetadataEdits { Manifest = new() { Path = "/manifest.json", ApplicationName = "App", ApplicationVersion = "01.00", TitleId = "PPSA99099", RuntimeVersion = "1.0" } };
            ProsperoPkgBuilder.BuildLocalStreaming(new ProsperoStreamingPackageOptions { SourceFolder = source, OutputPath = Path.Combine(root, "generated-manifest.pkg"), MetadataEdits = generated });
            Program.Equal(false, File.Exists(path), "generated manifest stays out of source");
            Program.Throws<ArgumentException>(() => ProsperoPkgBuilder.BuildLocalStreaming(new ProsperoStreamingPackageOptions { SourceFolder = source, OutputPath = Path.Combine(root, "collision.pkg"), MetadataEdits = new() { Manifest = new() { Path = "/sce_sys/manifest.json" } } }));
        }
        finally { Directory.Delete(root, true); }
    }

    private sealed class CallbackSink : IProsperoStreamingPackageOutput, IDisposable
    {
        // Small fixture-only backing store. The production contract exposes no read/seek API.
        internal readonly MemoryStream Bytes = new();
        internal string? FailAt;
        internal bool BadLength, BadRoot;
        internal bool Hashed;
        internal int Patches, AppendsAfterHash;
        private bool pendingAppend;
        private void Fail(string operation)
        {
            if (FailAt == operation) throw new IOException("Injected " + operation + " failure");
        }
        public void Append(ReadOnlySpan<byte> bytes)
        {
            Fail("append");
            Program.Equal(true, bytes.Length <= B, "callback append is bounded");
            if (Hashed) AppendsAfterHash++;
            Bytes.Write(bytes);
            pendingAppend = true;
        }
        public void Flush() { Fail("flush"); pendingAppend = false; }
        public void Patch(long offset, ReadOnlySpan<byte> bytes)
        {
            Fail("patch");
            Program.Equal(false, pendingAppend, "upload finished before positional patches");
            Program.Equal(false, Hashed, "patches precede mount hashing");
            Program.Equal(true, bytes.Length <= 1024, "callback patch matches PWRITE cap");
            Program.Equal((long)Patches * 1024, offset, "ordered FIH patch coverage");
            long position = Bytes.Position;
            Bytes.Position = offset;
            Bytes.Write(bytes);
            Bytes.Position = position;
            Patches++;
        }
        public ProsperoFinalizedMountDigests FinalizeMount(long length, long superblockOffset,
            CancellationToken token)
        {
            Fail("hash");
            Program.Equal(false, pendingAppend, "patches flushed before hashing");
            Program.Equal(64, Patches, "entire FIH patched before hashing");
            Program.Equal(length, Bytes.Length, "SI absent during hashing");
            Hashed = true;
            Bytes.Position = 0;
            var digests = ProsperoFinalizedMountDigests.Compute(Bytes, length, superblockOffset,
                cancellationToken: token);
            if (BadLength) return new ProsperoFinalizedMountDigests(1, new byte[32], new byte[32], new byte[4]);
            if (BadRoot) return new ProsperoFinalizedMountDigests(length, digests.MountDigest.Span,
                new byte[32], digests.PlayGoChunkCrc.Span);
            return digests;
        }
        public void Dispose() => Bytes.Dispose();
    }

    private static void CallbackOutput()
    {
        string root = Path.Combine(Path.GetTempPath(), "prospero-output-" + Guid.NewGuid());
        Directory.CreateDirectory(root);
        try
        {
            string source = Setup(root);
            var snapshot = Snapshot(source);
            ProsperoStreamingPackageOptions Options(string output, bool kraken) => new()
            {
                SourceFolder = source, OutputPath = output, UseKraken = kraken,
                ImageSeed = new byte[16], Timestamp = DateTimeOffset.FromUnixTimeSeconds(12345678),
            };
            foreach (bool kraken in new[] { false, true })
            {
                string local = Path.Combine(root, "reference.pkg");
                var reference = ProsperoPkgBuilder.BuildLocalStreaming(Options(local, kraken));
                using var sink = new CallbackSink();
                // This path must remain a label: the generic writer must not open it on disk.
                string label = Path.Combine(root, "missing-parent", "remote.pkg");
                var result = ProsperoPkgBuilder.WriteStreaming(Options(label, kraken), sink);
                byte[] expected = File.ReadAllBytes(local), actual = sink.Bytes.ToArray();
                // CNT IMAGE_KEY uses intentionally randomized RSA padding. Its dependent header/SI
                // digests differ across builds, so compare the deterministic FIH/PFS extent exactly
                // and independently verify CNT, recovered payloads and SI against their own bytes.
                int fixedExtent = checked((int)(B + result.PfsSize));
                Same(expected.AsSpan(0, fixedExtent), actual.AsSpan(0, fixedExtent), "callback FIH/PFS matches local bytes");
                VerifyPackage(actual, source, result, kraken);
                var directories = Directory.EnumerateDirectories(source, "*", SearchOption.AllDirectories)
                    .Select(path => new ProsperoSourceDirectory
                    {
                        Path = "/" + Path.GetRelativePath(source, path).Replace('\\', '/'), Validate = () => { },
                    }).ToArray();
                bool genericChanged = false;
                var genericFiles = Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories)
                    .Select(path =>
                    {
                        byte[] bytes = File.ReadAllBytes(path);
                        return new ProsperoSourceFile
                        {
                            Path = "/" + Path.GetRelativePath(source, path).Replace('\\', '/'), Length = bytes.Length,
                            OpenRead = () => new MemoryStream(bytes, writable: false),
                            Validate = () => { if (genericChanged) throw new InvalidDataException("source changed"); },
                        };
                    }).ToArray();
                var generic = new ProsperoSourceCatalog(directories, genericFiles);
                using var genericSink = new CallbackSink();
                var genericResult = ProsperoPkgBuilder.WriteStreaming(new ProsperoStreamingPackageOptions
                {
                    OutputPath = "in-memory-source", UseKraken = kraken,
                    ImageSeed = new byte[16], Timestamp = DateTimeOffset.FromUnixTimeSeconds(12345678),
                }, generic, genericSink);
                byte[] genericPackage = genericSink.Bytes.ToArray();
                Same(expected.AsSpan(0, fixedExtent), genericPackage.AsSpan(0, fixedExtent), "generic source produces identical FIH/PFS");
                VerifyPackage(genericPackage, source, genericResult, kraken);
                using (var failedSink = new CallbackSink())
                {
                    Program.Throws<InvalidDataException>(() => ProsperoPkgBuilder.WriteStreaming(new ProsperoStreamingPackageOptions
                    {
                        OutputPath = "mutated", UseKraken = kraken,
                    }, generic, failedSink, progress: p => { if (p.Stage == "Writing PFS") genericChanged = true; }));
                    Program.Equal(0, failedSink.AppendsAfterHash, "mutated generic source does not append SI");
                }
                genericChanged = false;
                Program.Equal(reference.PackageSize, result.PackageSize, "callback summary package size");
                Program.Equal(label, result.OutputPath, "generic output label preserved");
                Program.Equal(true, sink.Hashed && sink.AppendsAfterHash > 0, "SI appended only after hashing");
                Program.Equal(false, Directory.Exists(Path.GetDirectoryName(label)), "generic output performs no local creation");
                Program.Equal(true, sink.Bytes.CanWrite, "writer leaves caller output open");
                sink.Bytes.Position = 0;
                Program.Equal(true, ProsperoPkgValidator.Validate(ProsperoPkgReader.Read(sink.Bytes), Id).Accepted,
                    "callback output parses and validates");
                File.Delete(local);
            }
            foreach (string failure in new[] { "append", "flush", "patch", "hash" })
            {
                using var sink = new CallbackSink { FailAt = failure };
                Program.Throws<IOException>(() => ProsperoPkgBuilder.WriteStreaming(Options("remote.pkg", false), sink));
                Program.Equal(0, sink.AppendsAfterHash, "failed output never receives SI");
                Program.Equal(true, sink.Bytes.CanWrite, "failed output lifetime stays with caller");
            }
            foreach (bool badRoot in new[] { false, true })
            {
                using var sink = new CallbackSink { BadLength = !badRoot, BadRoot = badRoot };
                Program.Throws<InvalidDataException>(() => ProsperoPkgBuilder.WriteStreaming(Options("remote.pkg", false), sink));
                Program.Equal(0, sink.AppendsAfterHash, "invalid integrity metadata cannot append SI");
            }
            using (var sink = new CallbackSink())
            using (var cancellation = new CancellationTokenSource())
            {
                Program.Throws<OperationCanceledException>(() => ProsperoPkgBuilder.WriteStreaming(Options("remote.pkg", false), sink,
                    progress: p => { if (p.Stage == "Writing SI") cancellation.Cancel(); }, cancellationToken: cancellation.Token));
                Program.Equal(0, sink.AppendsAfterHash, "cancellation before SI prevents append");
                Program.Equal(true, sink.Bytes.CanWrite, "cancellation leaves cleanup to caller");
            }
            var after = Snapshot(source);
            Program.Equal(snapshot.Count, after.Count, "callback builds add no source files");
            foreach (var (path, value) in snapshot) Program.Equal(value, after[path], "callback build preserves source bytes/times");
        }
        finally { Directory.Delete(root, true); }
    }

}
