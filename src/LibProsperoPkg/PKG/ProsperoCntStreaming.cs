// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
#nullable enable
using LibProsperoPkg.PFS;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace LibProsperoPkg.PKG;

/// <summary>Final embedded CNT metadata; no PFS payload is retained.</summary>
public sealed class ProsperoEmbeddedCntResult
{
    public required byte[] Bytes { get; init; }
    public required ProsperoPfsImageXmlOptions Xml { get; init; }
    public byte[]? PlayGoChunkDat { get; init; }
}

public static partial class ProsperoPkgBuilder
{
    /// <summary>
    /// Builds the finalized embedded CNT from a streamed outer image and its final FIH block.
    /// Only container metadata is buffered. Source metadata is read without modifying the folder;
    /// overrides are paths relative to sce_sys and are snapshotted before construction.
    /// Bytes belong after the PFS in the FIH mount, not before it as in a standalone CNT package.
    /// </summary>
    public static ProsperoEmbeddedCntResult BuildEmbeddedContainer(
        ProsperoPkgBuildProperties props, ProsperoOuterPfsStreamResult outer,
        ReadOnlyMemory<byte> fihHeader, ReadOnlyMemory<byte> imageSeed, uint playgoFileCount,
        IReadOnlyDictionary<string, byte[]>? metadataOverrides = null, bool metadataSnapshotOnly = false)
    {
        ArgumentNullException.ThrowIfNull(props);
        ArgumentNullException.ThrowIfNull(outer);
        if (props.ContentId is not { Length: 36 } || props.Passcode is not { Length: 32 })
            throw new ArgumentException("Content id and passcode must contain 36 and 32 characters respectively.", nameof(props));
        if (string.IsNullOrWhiteSpace(props.SourceFolder) || !Directory.Exists(props.SourceFolder))
            throw new ArgumentException("Prepared source folder does not exist.", nameof(props));
        if (!Enum.IsDefined(props.VolumeType)) throw new ArgumentException("Unsupported volume type.", nameof(props));
        if (imageSeed.Length != 16) throw new ArgumentException("Image seed must contain 16 bytes.", nameof(imageSeed));
        byte[] seed = imageSeed.ToArray();
        byte[] fih = fihHeader.ToArray();
        ValidateStreamingFih(fih, outer);
        var overrides = SnapshotMetadataOverrides(metadataOverrides);
        byte[] ekpfs = ProsperoPfsKeys.DeriveEkpfs(props.ContentId, props.Passcode);
        long total = checked(BlockSize + outer.PfsSize);
        long first = checked((long)outer.FileBlockCount[0] * BlockSize);
        long mchunk0 = first > 0 && first < total ? first : total - BlockSize;
        var pkg = BuildContainer(props, ekpfs, Path.GetFullPath(props.SourceFolder), (ulong)outer.PfsSize,
            checked(outer.BlockCount * ProsperoImageDigests.DigestSize), playgoFileCount,
            (ulong)mchunk0, (ulong)(total - mchunk0), overrides, metadataSnapshotOnly);
        return FinalizeEmbeddedContainer(pkg, props, outer, fih, seed, overrides);
    }

    private static Dictionary<string, byte[]> SnapshotMetadataOverrides(IReadOnlyDictionary<string, byte[]>? values)
    {
        var result = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        if (values is null) return result;
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, bytes) in values)
        {
            if (string.IsNullOrEmpty(name) || name.Contains('\\') || name.Contains('\0') ||
                name.StartsWith('/') || name.Split('/').Any(p => p.Length == 0 || p is "." or "..") ||
                !names.Add(name) || bytes is null ||
                (name != "param.json" && !ProsperoCntEntryNames.NameToId.ContainsKey(name)))
                throw new ArgumentException("Metadata overrides require unique known sce_sys-relative paths.", nameof(values));
            result.Add(name, bytes.ToArray());
        }
        return result;
    }

    private static void ValidateStreamingFih(byte[] fih, ProsperoOuterPfsStreamResult outer)
    {
        if (fih.Length != BlockSize || !fih.AsSpan(0, 4).SequenceEqual(ProsperoPkgLayout.FihMagic) || fih[5] != 0 ||
            BinaryPrimitives.ReadUInt64LittleEndian(fih.AsSpan(0x10)) != BlockSize ||
            BinaryPrimitives.ReadUInt64LittleEndian(fih.AsSpan(0x18)) != (ulong)outer.PfsSize ||
            BinaryPrimitives.ReadUInt64LittleEndian(fih.AsSpan(0x58)) != checked((ulong)(BlockSize + outer.PfsSize)) ||
            BinaryPrimitives.ReadUInt64LittleEndian(fih.AsSpan(0x20)) != checked((ulong)(outer.SuperblockIndex + 1L) * BlockSize))
            throw new ArgumentException("FIH geometry does not match the streamed outer image.", nameof(fih));
        if (outer.FileBlockCount.Count != 2 || outer.FileFirstBlock.Count != 2 ||
            outer.FileFirstBlock[0] != 0 || outer.FileFirstBlock[1] != outer.FileBlockCount[0] ||
            outer.SuperblockIndex != checked(outer.FileBlockCount[0] + outer.FileBlockCount[1]) ||
            BinaryPrimitives.ReadUInt32LittleEndian(fih.AsSpan(0x90)) != (uint)outer.FileBlockCount[0] ||
            BinaryPrimitives.ReadUInt64LittleEndian(fih.AsSpan(0xA8)) != (ulong)outer.FileSize[1] ||
            BinaryPrimitives.ReadUInt64LittleEndian(fih.AsSpan(0xA0)) != (ulong)outer.FileSizeCompressed[0])
            throw new ArgumentException("The two-file nwonly outer layout is required.", nameof(outer));
        ReadOnlySpan<byte> root = outer.GetBlockDigest(outer.SuperblockIndex).Span;
        foreach (int offset in new[] { 0x30, 0x70, 0xD0 })
            if (!fih.AsSpan(offset, 32).SequenceEqual(root))
                throw new ArgumentException("FIH superblock digest does not match the streamed outer image.", nameof(fih));
    }

    // This internal seam allows the managed regression to finalize one shared prepared CNT through
    // both paths. Independently prepared IMAGE_KEY entries intentionally have random RSA padding.
    internal static ProsperoEmbeddedCntResult FinalizeEmbeddedContainer(
        ProsperoCnt pkg, ProsperoPkgBuildProperties props, ProsperoOuterPfsStreamResult outer,
        byte[] fih, byte[] seed, IReadOnlyDictionary<string, byte[]> overrides)
    {
        long containerSize = checked((long)pkg.Header.pfs_image_offset);
        if (containerSize > int.MaxValue) throw new NotSupportedException("CNT metadata exceeds the supported array size.");
        var imageDigests = ((ProsperoCntGenericEntry)pkg.Entries.First(e => (uint)e.Id == ImagedigsEntryId)).FileData;
        for (int i = 0; i < outer.BlockCount; i++)
        {
            var digest = outer.GetBlockDigest(i).Span;
            for (int j = 0; j < 32; j++) imageDigests[i * 32 + j] = digest[31 - j];
        }
        pkg.Header.pfs_image_digest = outer.GetBlockDigest(outer.SuperblockIndex).ToArray();
        pkg.Header.pfs_signed_digest = ProsperoImageDigests.ComputeFixedInfoDigest(fih);
        pkg.Header.image_seed = seed.ToArray();
        foreach (var pair in ComputeGeneralDigests(pkg)) pkg.GeneralDigests.Set(pair.Key, pair.Value);
        using var metadata = new MemoryStream((int)containerSize);
        metadata.SetLength(containerSize);
        var writer = new ProsperoCntWriter(metadata);
        writer.WriteBody(pkg, props.ContentId, props.Passcode);
        CalcBodyDigests(pkg, metadata);
        byte[] buffer = metadata.GetBuffer();
        pkg.Header.desc_digest = new byte[64];
        ProsperoImageDigests.Sha3_256(buffer.AsSpan(checked((int)pkg.Header.desc_image_key_offset),
            checked((int)pkg.Header.desc_image_key_size))).CopyTo(pkg.Header.desc_digest, 0);
        ProsperoImageDigests.Sha3_256(buffer.AsSpan(checked((int)pkg.Header.desc_mandatory_offset),
            checked((int)pkg.Header.desc_mandatory_size))).CopyTo(pkg.Header.desc_digest, 32);
        writer.WriteHeader(pkg.Header);
        metadata.Position = 0;
        var header = new byte[0x1000];
        metadata.ReadExactly(header);
        BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(ProsperoImageDigests.CntPfsImageOffsetField),
            ProsperoImageDigests.FihRelativeImageOffset);
        pkg.HeaderDigest = ProsperoImageDigests.ComputePackageDigest(header);
        pkg.HeaderDigest.CopyTo(header.AsSpan(ProsperoImageDigests.PackageDigestStoredOffset));
        metadata.Position = 0;
        metadata.Write(header);
        pkg.HeaderSignature = ProsperoPkgSigner.EncryptHeaderDigest(ProsperoImageDigests.Sha3_256(header));
        metadata.Position = 0x1000;
        metadata.Write(pkg.HeaderSignature);
        byte[]? param = overrides.TryGetValue("param.json", out var bytes) ? bytes : null;
        var xml = BuildSiXmlOptionsFromSeed(pkg, seed.ToArray(), Path.GetFullPath(props.SourceFolder), param);
        if (metadata.Length != containerSize || buffer.LongLength != containerSize)
            throw new InvalidDataException("CNT serialization exceeded its metadata reservation.");
        return new ProsperoEmbeddedCntResult
        {
            Bytes = buffer, Xml = xml,
            PlayGoChunkDat = (pkg.Entries.FirstOrDefault(e => (uint)e.Id == PlayGoChunkDatEntryId) as ProsperoCntGenericEntry)?.FileData,
        };
    }
}
