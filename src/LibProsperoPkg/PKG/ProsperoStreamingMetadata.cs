// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
#nullable enable
using LibProsperoPkg.Metadata;
using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Text;

namespace LibProsperoPkg.PKG;

/// <summary>Optional package metadata changes. Null fields retain their source values.</summary>
public sealed class ProsperoStreamingMetadataEdits
{
    /// <summary>Generate a default param when none exists; requires content ID, title ID and title.</summary>
    public bool GenerateMissingParam { get; init; }
    public string? TitleId { get; init; }
    public string? TitleName { get; init; }
    /// <summary>Package version in NN.NN format.</summary>
    public string? Version { get; init; }
    public ProsperoDrmType? DrmType { get; init; }
    /// <summary>Optional manifest overlay at an explicitly selected source-catalog path.</summary>
    public ProsperoStreamingManifestEdits? Manifest { get; init; }
}

/// <summary>Changes to a framework application manifest; null fields retain existing values.</summary>
public sealed class ProsperoStreamingManifestEdits
{
    public required string Path { get; init; }
    public string? ApplicationName { get; init; }
    public string? ApplicationVersion { get; init; }
    public string? TitleId { get; init; }
    public string? RuntimeVersion { get; init; }
    public string? BranchType { get; init; }
    public bool? TwinTurbo { get; init; }
}

internal static class ProsperoStreamingMetadata
{
    private const int Limit = 4 * 1024 * 1024;
    private static readonly UTF8Encoding Utf8 = new(false, true);

    internal static ProsperoSourceCatalog ApplyManifest(ProsperoSourceCatalog catalog, ProsperoStreamingManifestEdits? edits, CancellationToken token)
    {
        if (edits is null) return catalog;
        token.ThrowIfCancellationRequested();
        string path = edits.Path;
        if (string.IsNullOrEmpty(path) || !path.StartsWith("/", StringComparison.Ordinal) ||
            !path.EndsWith("/manifest.json", StringComparison.Ordinal) ||
            path.StartsWith("/sce_sys/", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Manifest path must select manifest.json outside sce_sys.");
        var original = catalog.Files.FirstOrDefault(f => f.Path == path);
        ProsperoManifest manifest;
        if (original is null)
        {
            if (string.IsNullOrWhiteSpace(edits.ApplicationName) || string.IsNullOrWhiteSpace(edits.ApplicationVersion) ||
                string.IsNullOrWhiteSpace(edits.TitleId) || string.IsNullOrWhiteSpace(edits.RuntimeVersion))
                throw new ArgumentException("Generating a manifest requires application name, version, title ID and runtime version.");
            manifest = ProsperoManifest.Create(edits.ApplicationName, edits.ApplicationVersion, edits.TitleId,
                edits.RuntimeVersion, edits.BranchType ?? "release", edits.TwinTurbo ?? true);
        }
        else
        {
            if (original.Length > Limit) throw new InvalidDataException("manifest.json exceeds the 4 MiB metadata limit.");
            using var reader = original.OpenRead();
            byte[] input = new byte[checked((int)original.Length)];
            reader.ReadExactly(input);
            if (reader.ReadByte() != -1) throw new InvalidDataException("Manifest changed while reading.");
            manifest = ProsperoManifest.Parse(Utf8.GetString(input));
            if (edits.ApplicationName is not null) manifest.ApplicationName = edits.ApplicationName;
            if (edits.ApplicationVersion is not null) manifest.ApplicationVersion = edits.ApplicationVersion;
            if (edits.TitleId is not null) manifest.TitleId = edits.TitleId;
            if (edits.RuntimeVersion is not null) manifest.ReactNativePlaystationVersion = edits.RuntimeVersion;
            if (edits.BranchType is not null) manifest.BranchType = edits.BranchType;
            if (edits.TwinTurbo is not null) manifest.TwinTurbo = edits.TwinTurbo;
        }
        byte[] bytes = Utf8.GetBytes(manifest.ToJson());
        if (bytes.Length > Limit) throw new InvalidDataException("Edited manifest.json exceeds the 4 MiB metadata limit.");
        var replacement = new ProsperoSourceFile { Path = path, Length = bytes.Length,
            Validate = catalog.Validate, OpenRead = () => { catalog.Validate(); return new MemoryStream(bytes, writable: false); } };
        return new ProsperoSourceCatalog(catalog.Directories, catalog.Files.Where(f => f.Path != path).Append(replacement), catalog.Validate);
    }

    internal static byte[] ApplyParam(byte[]? source, string? contentId, ProsperoStreamingMetadataEdits? edits)
    {
        if (source is { Length: > Limit }) throw new InvalidDataException("param.json exceeds the 4 MiB metadata limit.");
        if (source is null && edits?.GenerateMissingParam != true)
            throw new FileNotFoundException("Prepared source requires sce_sys/param.json.");
        if (edits is null || (source is not null && edits.TitleId is null && edits.TitleName is null &&
            edits.Version is null && edits.DrmType is null)) return source!;
        ProsperoParam param;
        if (source is null)
        {
            if (string.IsNullOrWhiteSpace(contentId) || string.IsNullOrWhiteSpace(edits.TitleId) || string.IsNullOrWhiteSpace(edits.TitleName))
                throw new ArgumentException("Generating param.json requires a content ID, title ID and title name.");
            param = ProsperoParam.CreateDefault(contentId, edits.TitleId, edits.TitleName, edits.DrmType ?? ProsperoDrmType.Standard);
        }
        else param = ProsperoParam.Parse(Utf8.GetString(source));
        if (edits.TitleId is not null) { ArgumentException.ThrowIfNullOrWhiteSpace(edits.TitleId); param.TitleId = edits.TitleId; }
        if (edits.TitleName is not null)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(edits.TitleName);
            param.SetTitleName(string.IsNullOrWhiteSpace(param.DefaultLanguage) ? "en-US" : param.DefaultLanguage, edits.TitleName);
            if (string.IsNullOrWhiteSpace(param.DefaultLanguage)) param.DefaultLanguage = "en-US";
        }
        if (edits.Version is { } version)
        {
            if (version.Length != 5 || version[2] != '.' || !char.IsAsciiDigit(version[0]) || !char.IsAsciiDigit(version[1]) || !char.IsAsciiDigit(version[3]) || !char.IsAsciiDigit(version[4]))
                throw new ArgumentException("Version must have the form NN.NN.");
            param.MasterVersion = version;
            param.ContentVersion = version[..2] + ".0" + version[3..] + ".000";
        }
        if (edits.DrmType is { } drm) param.ApplicationDrmType = ProsperoDrmTypes.ToToken(drm);
        byte[] result = Utf8.GetBytes(param.ToJson());
        if (result.Length > Limit) throw new InvalidDataException("Edited param.json exceeds the 4 MiB metadata limit.");
        return result;
    }
}
