using LibProsperoPkg.Content;
using LibProsperoPkg.PFS;
using LibProsperoPkg.PKG;
using LibProsperoPkg.PlayGo;
using System.Security.Cryptography;

namespace LibProsperoPkg.Tests;

internal static class FolderSourceTests
{
    private static readonly string Passcode = new('0', 32);
    internal static void Run()
    {
        GenericCatalog();
        CatalogAndOverlays();
        SuppliedAuxiliaryWins();
        InvalidInputsAndChanges();
        LinksAndNames();
    }

    private static void Same(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, string context)
        => Program.Equal(true, a.SequenceEqual(b), context);

    private static string CreateFolder()
    {
        string root = Path.Combine(Path.GetTempPath(), "prospero-folder-" + Guid.NewGuid());
        Directory.CreateDirectory(Path.Combine(root, "sce_sys"));
        File.WriteAllText(Path.Combine(root, "sce_sys", "param.json"), "{}");
        return root;
    }

    private static Dictionary<string, string> Snapshot(string root)
        => Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories).ToDictionary(
            file => Path.GetRelativePath(root, file),
            file => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(file))) + ":" + File.GetLastWriteTimeUtc(file).Ticks,
            StringComparer.Ordinal);

    private static byte[] Read(ProsperoPs5InnerFileSource source)
    {
        using Stream reader = source.OpenRead();
        using var bytes = new MemoryStream();
        reader.CopyTo(bytes);
        return bytes.ToArray();
    }

    private static void GenericCatalog()
    {
        bool changed = false;
        ProsperoSourceDirectory Dir(string path) => new() { Path = path, Validate = () => { } };
        ProsperoSourceFile File(string path, long length, byte[] data) => new()
        {
            Path = path, Length = length, OpenRead = () => new MemoryStream(data, writable: false),
            Validate = () => { if (changed) throw new InvalidDataException("mutated"); },
        };
        var catalog = new ProsperoSourceCatalog(new[] { Dir("/empty"), Dir("/data") },
            new[] { File("/data/a", 3, new byte[] { 1, 2, 3 }) });
        Program.Equal(2, catalog.Directories.Count, "generic catalog preserves empty directory");
        using (var reader = catalog.Files[0].OpenRead())
        {
            byte[] data = new byte[3]; reader.ReadExactly(data);
            Same(new byte[] { 1, 2, 3 }, data, "generic reader bytes");
            changed = true;
            Program.Throws<InvalidDataException>(() => reader.ReadByte());
        }
        Program.Throws<InvalidDataException>(() => catalog.Files[0].OpenRead());
        changed = false;
        Program.Throws<ArgumentException>(() => new ProsperoSourceCatalog(new[] { Dir("/data"), Dir("/DATA") }, Array.Empty<ProsperoSourceFile>()));
        Program.Throws<ArgumentException>(() => new ProsperoSourceCatalog(new[] { Dir("/data") }, new[] { File("/DATA/a", 0, Array.Empty<byte>()) }));
        Program.Throws<ArgumentException>(() => new ProsperoSourceCatalog(Array.Empty<ProsperoSourceDirectory>(), new[] { File("/a/b", 0, Array.Empty<byte>()) }));
        Program.Throws<ArgumentException>(() => new ProsperoSourceCatalog(Array.Empty<ProsperoSourceDirectory>(), new[] { File("/../a", 0, Array.Empty<byte>()) }));
        foreach (var (length, data) in new[] { (2L, new byte[] { 1 }), (1L, new byte[] { 1, 2 }) })
        {
            var invalid = new ProsperoSourceCatalog(Array.Empty<ProsperoSourceDirectory>(), new[] { File("/a", length, data) });
            using var reader = invalid.Files[0].OpenRead();
            Program.Throws<InvalidDataException>(() => reader.CopyTo(Stream.Null));
        }
    }

    private static void CatalogAndOverlays()
    {
        string root = CreateFolder();
        try
        {
            Directory.CreateDirectory(Path.Combine(root, "data"));
            Directory.CreateDirectory(Path.Combine(root, "empty"));
            byte[] data = new byte[0x40000 + 17]; new Random(42).NextBytes(data);
            File.WriteAllBytes(Path.Combine(root, "data", "asset.bin"), data);
            File.WriteAllText(Path.Combine(root, "ignored.gp5"), "project");
            File.WriteAllBytes(Path.Combine(root, "sce_sys", "icon0.png"), new byte[] { 1, 2, 3 });
            Directory.CreateDirectory(Path.Combine(root, "sce_sys", "uds"));
            byte[] ucp = ProsperoUcp.Build(new[] { new UcpEntry("asset", new byte[] { 7, 8, 9 }) });
            ucp[0x1c] ^= 1;
            string ucpPath = Path.Combine(root, "sce_sys", "uds", "uds00.ucp");
            File.WriteAllBytes(ucpPath, ucp);
            var before = Snapshot(root);
            var catalog = ProsperoStreamingFolderSource.Create(root, Passcode);
            Program.Equal(Path.GetFullPath(root), catalog.SourceFolder, "folder canonical path");
            Program.Equal(true, catalog.Catalog.Directories.Any(d => d.Path == "/empty"), "empty directory cataloged");
            Program.Equal(true, catalog.Catalog.Files.Any(f => f.Path == "/sce_sys/param.json"), "CNT metadata cataloged");
            catalog.Catalog.Validate();
            using (var original = catalog.Catalog.Files.Single(f => f.Path == "/data/asset.bin").OpenRead())
            using (var bytes = new MemoryStream()) { original.CopyTo(bytes); Same(data, bytes.ToArray(), "catalog original bytes"); }
            Program.Equal(false, catalog.Files.Any(f => f.Path.EndsWith("param.json") || f.Path.EndsWith("icon0.png") || f.Path.EndsWith("gp5")), "CNT/project files excluded");
            Same(data, Read(catalog.Files.Single(f => f.Path == "/data/asset.bin")), "folder payload bytes unchanged");
            byte[] keystone = Read(catalog.Files.Single(f => f.Path == "/sce_sys/keystone"));
            Program.Equal(96, keystone.Length, "generated keystone overlay");
            Program.Equal(false, File.Exists(Path.Combine(root, "sce_sys", "keystone")), "keystone never written to source");
            byte[]? right = ProsperoPlayGo.GetRightSprx();
            if (right is { Length: > 0 })
            {
                Same(right, Read(catalog.Files.Single(f => f.Path == "/sce_sys/about/right.sprx")), "generated about overlay");
                Program.Equal(false, Directory.Exists(Path.Combine(root, "sce_sys", "about")), "generated about directory not written");
            }
            byte[] repaired = Read(catalog.Files.Single(f => f.Path == "/sce_sys/uds/uds00.ucp"));
            Program.Equal(true, ProsperoUcp.VerifyDigest(repaired), "UCP digest repaired in overlay");
            Same(ucp, File.ReadAllBytes(ucpPath), "stale source UCP preserved");
            using var image = new MemoryStream();
            var layout = new ProsperoPs5InnerImageAssembler(12345, 0).Write(image, catalog.Files);
            Program.Equal(catalog.Files.Count, layout.Placements.Count, "catalog integrates with streamed assembler");
            var after = Snapshot(root);
            Program.Equal(before.Count, after.Count, "source file count unchanged");
            foreach (var file in before) Program.Equal(file.Value, after[file.Key], "source digest and mtime unchanged");
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    private static void SuppliedAuxiliaryWins()
    {
        string root = CreateFolder();
        try
        {
            byte[] keystone = Enumerable.Repeat((byte)0x5a, 96).ToArray();
            byte[] right = new byte[] { 0x54, 0x14, 0xf5, 0xee, 5, 6, 7, 8 };
            Directory.CreateDirectory(Path.Combine(root, "sce_sys", "about"));
            File.WriteAllBytes(Path.Combine(root, "sce_sys", "keystone"), keystone);
            File.WriteAllBytes(Path.Combine(root, "sce_sys", "about", "right.sprx"), right);
            var catalog = ProsperoStreamingFolderSource.Create(root, Passcode);
            Same(keystone, Read(catalog.Files.Single(f => f.Path == "/sce_sys/keystone")), "supplied keystone takes precedence");
            Same(right, Read(catalog.Files.Single(f => f.Path == "/sce_sys/about/right.sprx")), "supplied about module takes precedence");
            Program.Equal(2, catalog.Files.Count, "no duplicate generated auxiliary descriptors");
            Directory.Delete(Path.Combine(root, "sce_sys", "about"), recursive: true);
            File.WriteAllText(Path.Combine(root, "sce_sys", "about"), "conflicting regular file");
            if (ProsperoPlayGo.GetRightSprx() is { Length: > 0 })
                Program.Throws<ArgumentException>(() => ProsperoStreamingFolderSource.Create(root, Passcode));
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    private static void InvalidInputsAndChanges()
    {
        string root = CreateFolder();
        try
        {
            Program.Throws<ArgumentException>(() => ProsperoStreamingFolderSource.Create(root, "short"));
            var inspected = ProsperoStreamingFolderSource.Inspect(root);
            Program.Equal(true, inspected.Files.Any(f => f.Path == "/sce_sys/param.json"), "inspection needs no package options");
            using var cts = new CancellationTokenSource(); cts.Cancel();
            Program.Throws<OperationCanceledException>(() => ProsperoStreamingFolderSource.Create(root, Passcode, cts.Token));
            string asset = Path.Combine(root, "asset.bin");
            File.WriteAllBytes(asset, new byte[] { 1, 2, 3 });
            var catalog = ProsperoStreamingFolderSource.Create(root, Passcode);
            File.AppendAllText(asset, "changed");
            Program.Throws<InvalidDataException>(() => catalog.Files.Single(f => f.Path == "/asset.bin").OpenRead());
            Program.Throws<InvalidDataException>(() => catalog.Catalog.Validate());
            File.WriteAllBytes(asset, new byte[20]);
            var stable = ProsperoStreamingFolderSource.Create(root, Passcode);
            using var reader = stable.Files.Single(f => f.Path == "/asset.bin").OpenRead();
            Program.Equal(false, reader.CanSeek, "prepared reader is forward-only");
            Program.Throws<NotSupportedException>(() => _ = reader.Length);
            byte[] got = new byte[20]; reader.ReadExactly(got);
            Program.Equal(-1, reader.ReadByte(), "header replay has exact source length");
            var generated = stable.Files.Single(f => f.Path == "/sce_sys/keystone");
            File.WriteAllText(Path.Combine(root, "sce_sys", "keystone"), "new source file");
            Program.Throws<InvalidDataException>(() => generated.OpenRead());
            File.Delete(Path.Combine(root, "sce_sys", "keystone"));
            byte[] elf = new byte[20]; elf[0] = 0x7f; elf[1] = (byte)'E'; elf[2] = (byte)'L'; elf[3] = (byte)'F';
            elf[0x10] = 2; elf[0x12] = 0x3e;
            File.WriteAllBytes(Path.Combine(root, "eboot.bin"), elf);
            var rawCatalog = ProsperoStreamingFolderSource.Create(root, Passcode);
            Program.Throws<NotSupportedException>(() => rawCatalog.Files.Single(f => f.Path == "/eboot.bin").OpenRead());
            Same(elf, File.ReadAllBytes(Path.Combine(root, "eboot.bin")), "raw ELF rejection does not modify source");
            Directory.CreateDirectory(Path.Combine(root, "sce_sys", "uds"));
            using (var large = new FileStream(Path.Combine(root, "sce_sys", "uds", "large.ucp"), FileMode.CreateNew))
                large.SetLength(ProsperoStreamingFolderSource.MaximumUcpOverlaySize + 1L);
            Program.Throws<NotSupportedException>(() => ProsperoStreamingFolderSource.Create(root, Passcode));
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    private static void LinksAndNames()
    {
        string root = CreateFolder();
        string outside = Path.Combine(Path.GetTempPath(), "prospero-outside-" + Guid.NewGuid());
        Directory.CreateDirectory(outside);
        try
        {
            File.WriteAllBytes(Path.Combine(outside, "asset"), new byte[] { 9 });
            string link = Path.Combine(root, "link");
            try
            {
                Directory.CreateSymbolicLink(link, outside);
                Program.Throws<NotSupportedException>(() => ProsperoStreamingFolderSource.Create(root, Passcode));
            }
            catch (UnauthorizedAccessException) when (OperatingSystem.IsWindows()) { }
            finally { if (Directory.Exists(link)) Directory.Delete(link); }
            string nonAscii = Path.Combine(root, "gáme.bin");
            File.WriteAllBytes(nonAscii, new byte[] { 1 });
            Program.Throws<NotSupportedException>(() => ProsperoStreamingFolderSource.Create(root, Passcode));
            File.Delete(nonAscii);
            string fileLink = Path.Combine(root, "file-link");
            try
            {
                File.CreateSymbolicLink(fileLink, Path.Combine(outside, "asset"));
                Program.Throws<NotSupportedException>(() => ProsperoStreamingFolderSource.Create(root, Passcode));
            }
            catch (UnauthorizedAccessException) when (OperatingSystem.IsWindows()) { }
            finally { if (File.Exists(fileLink)) File.Delete(fileLink); }
        }
        finally { Directory.Delete(root, recursive: true); Directory.Delete(outside, recursive: true); }
    }
}
