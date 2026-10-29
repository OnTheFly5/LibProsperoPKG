// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
#nullable enable
using System;
using System.IO;
using System.Linq;

namespace LibProsperoPkg.PKG;

internal static class ProsperoStreamingModes
{
    internal static ProsperoSourceCatalog Homebrew(ProsperoSourceCatalog source, string moduleName, string? manifestPath)
    {
        if (string.IsNullOrWhiteSpace(moduleName) || moduleName.StartsWith('/') || moduleName.Contains('\\'))
            throw new ArgumentException("Homebrew module must be a relative catalog path.");
        string selected = "/" + moduleName;
        var module = source.Files.SingleOrDefault(f => f.Path == selected)
            ?? throw new FileNotFoundException("Homebrew main module was not found: " + moduleName);
        using (var reader = module.OpenRead())
        {
            byte[] magic = new byte[4];
            if (module.Length < magic.Length) throw new InvalidDataException("Homebrew main module is truncated: " + moduleName);
            reader.ReadExactly(magic);
            if (!(magic[0] == 0x7f && magic[1] == (byte)'E' && magic[2] == (byte)'L' && magic[3] == (byte)'F') &&
                System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(magic) != LibProsperoPkg.Content.ProsperoFself.Magic)
                throw new InvalidDataException("Homebrew main module must be ELF or SELF: " + moduleName);
        }
        var dirs = source.Directories.Where(d => d.Path == "/sce_sys" || d.Path.StartsWith("/sce_sys/", StringComparison.Ordinal) ||
            d.Path == "/sce_module" || d.Path.StartsWith("/sce_module/", StringComparison.Ordinal) ||
            (manifestPath is not null && manifestPath.StartsWith(d.Path + "/", StringComparison.Ordinal))).ToList();
        if (!dirs.Any(d => d.Path == "/sce_sys")) dirs.Add(new ProsperoSourceDirectory { Path = "/sce_sys", Validate = source.Validate });
        var files = source.Files.Where(f => f.Path.StartsWith("/sce_sys/", StringComparison.Ordinal) ||
            f.Path.StartsWith("/sce_module/", StringComparison.Ordinal) || f.Path == manifestPath).ToList();
        files.Add(new ProsperoSourceFile { Path = "/eboot.bin", Length = module.Length, Validate = module.Validate, OpenRead = module.OpenRead });
        return new ProsperoSourceCatalog(dirs, files, source.Validate);
    }

    internal static void ValidateNoData(ProsperoSourceCatalog source)
    {
        var payload = source.Files.FirstOrDefault(f => !f.Path.StartsWith("/sce_sys/", StringComparison.Ordinal) &&
            !f.Path.EndsWith(".gp4", StringComparison.OrdinalIgnoreCase) && !f.Path.EndsWith(".gp5", StringComparison.OrdinalIgnoreCase));
        if (payload is not null) throw new InvalidDataException("Entitlement-only DLC cannot contain payload files: " + payload.Path);
    }
}
