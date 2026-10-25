using System;
using System.Buffers;
using System.IO;
using System.Security.Cryptography;

namespace LibProsperoPkg.Util;

/// <summary>Incremental SHA3-256 with a native fast path and a portable managed fallback.</summary>
internal sealed class Sha3Digest : IDisposable
{
    private readonly IncrementalHash? native;
    private readonly ThirdParty.ACryptoHashNet.Sha3_256? managed;

    internal Sha3Digest(bool forceManaged = false)
    {
        if (!forceManaged && SHA3_256.IsSupported)
            native = IncrementalHash.CreateHash(HashAlgorithmName.SHA3_256);
        else
            managed = new ThirdParty.ACryptoHashNet.Sha3_256();
    }

    internal void AppendData(ReadOnlySpan<byte> data)
    {
        if (native is not null)
        {
            native.AppendData(data);
            return;
        }
        if (data.IsEmpty) return;
        byte[] buffer = ArrayPool<byte>.Shared.Rent(Math.Min(data.Length, 65536));
        try
        {
            while (!data.IsEmpty)
            {
                int length = Math.Min(data.Length, buffer.Length);
                data[..length].CopyTo(buffer);
                managed!.TransformBlock(buffer, 0, length, null, 0);
                data = data[length..];
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    internal byte[] GetHashAndReset()
    {
        if (native is not null) return native.GetHashAndReset();
        managed!.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        byte[] result = managed.Hash!;
        managed.Initialize();
        return result;
    }

    internal static byte[] HashData(ReadOnlySpan<byte> data)
    {
        using var hash = new Sha3Digest();
        hash.AppendData(data);
        return hash.GetHashAndReset();
    }

    internal static int HashData(ReadOnlySpan<byte> data, Span<byte> destination)
    {
        if (destination.Length < 32)
            throw new ArgumentException("Destination must contain at least 32 bytes.", nameof(destination));
        HashData(data).CopyTo(destination);
        return 32;
    }

    internal static byte[] HashData(Stream data)
    {
        ArgumentNullException.ThrowIfNull(data);
        using var hash = new Sha3Digest();
        byte[] buffer = ArrayPool<byte>.Shared.Rent(65536);
        try
        {
            int length;
            while ((length = data.Read(buffer, 0, buffer.Length)) != 0)
                hash.AppendData(buffer.AsSpan(0, length));
            return hash.GetHashAndReset();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    public void Dispose()
    {
        native?.Dispose();
        managed?.Dispose();
    }
}
