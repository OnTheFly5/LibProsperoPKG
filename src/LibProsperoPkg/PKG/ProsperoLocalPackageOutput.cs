// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
#nullable enable
using Microsoft.Win32.SafeHandles;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace LibProsperoPkg.PKG;

/// <summary>Owns one selected local output, from exclusive .part creation to non-overwriting publication.</summary>
public static class ProsperoLocalPackageOutput
{
    /// <summary>
    /// Creates finalPath + ".part" in an existing output directory and lends its read/write stream
    /// to generate. The callback may patch and hash that file; it must not retain or close the stream.
    /// Existing final files always fail. Existing partials require explicit deletion consent and are
    /// never resumed. Successful generation is flushed to disk, closed, and renamed without overwrite.
    /// Failure/cancellation deletes only the identified partial owned by this invocation. If cleanup
    /// fails, an AggregateException retains the generation error and the cleanup error(s).
    /// </summary>
    /// <remarks>
    /// Identity checks preserve files replaced during callbacks. Portable filesystem APIs do not
    /// provide an atomic identity-conditional unlink/rename, so the output directory must not be
    /// concurrently renamed or modified by an uncooperative writer during publication/cleanup.
    /// </remarks>
    public static T Write<T>(string finalPath, Func<FileStream, CancellationToken, T> generate,
        Func<string, bool>? confirmDeleteExistingPart = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(finalPath);
        ArgumentNullException.ThrowIfNull(generate);
        if (!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
            throw new PlatformNotSupportedException("Local package ownership checks support Windows, Linux and macOS.");
        if (!OperatingSystem.IsWindows() && RuntimeInformation.ProcessArchitecture is not Architecture.X64 and not Architecture.Arm64)
            throw new PlatformNotSupportedException("Unix file ownership checks require a supported 64-bit runtime.");
        string output = Path.GetFullPath(finalPath);
        string partial = output + ".part";
        string parent = Path.GetDirectoryName(output)!;
        if (!Directory.Exists(parent))
            throw new DirectoryNotFoundException("The output directory must already exist: " + parent);
        cancellationToken.ThrowIfCancellationRequested();
        EnsureFinalMissing(output);

        if (EntryExists(partial))
        {
            using var existing = OpenIdentityGuard(partial);
            var identity = FileIdentity.Read(existing);
            if (confirmDeleteExistingPart is null || !confirmDeleteExistingPart(partial))
                throw new IOException("Existing partial output was not authorized for deletion: " + partial);
            cancellationToken.ThrowIfCancellationRequested();
            EnsureFinalMissing(output);
            if (EntryExists(partial))
            {
                EnsureIdentity(partial, identity);
                File.Delete(partial);
            }
        }
        cancellationToken.ThrowIfCancellationRequested();
        EnsureFinalMissing(output);

        FileStream? stream = null;
        SafeFileHandle? guard = null;
        FileIdentity? ownedIdentity = null;
        bool created = false;
        try
        {
            // Read sharing permits a guard handle; writers are excluded. On Windows this also
            // prevents deletion while the generation stream is open. Unix additionally needs identity checks.
            stream = new FileStream(partial, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read,
                bufferSize: 65536, FileOptions.None);
            created = true;
            ownedIdentity = FileIdentity.Read(stream.SafeFileHandle);
            guard = OpenIdentityGuard(partial);
            if (FileIdentity.Read(guard) != ownedIdentity.Value)
                throw new IOException("The partial output changed during creation: " + partial);
            cancellationToken.ThrowIfCancellationRequested();
            T result = generate(stream, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            stream.Flush(flushToDisk: true);
            cancellationToken.ThrowIfCancellationRequested();
            EnsureIdentity(partial, ownedIdentity.Value);
            stream.Dispose();
            stream = null;
            cancellationToken.ThrowIfCancellationRequested();
            EnsureIdentity(partial, ownedIdentity.Value);
            File.Move(partial, output, overwrite: false);
            return result;
        }
        catch (Exception primary)
        {
            var errors = new List<Exception> { primary };
            try { stream?.Dispose(); }
            catch (Exception closeError) { errors.Add(closeError); }
            stream = null;
            if (created)
            {
                try
                {
                    if (EntryExists(partial))
                    {
                        if (ownedIdentity is not { } identity)
                            throw new IOException("Cannot establish ownership; partial output was preserved: " + partial);
                        EnsureIdentity(partial, identity);
                        File.Delete(partial);
                    }
                }
                catch (Exception cleanupError) { errors.Add(cleanupError); }
            }
            if (errors.Count > 1)
                throw new AggregateException("Package generation failed and output cleanup was incomplete.", errors);
            throw;
        }
        finally
        {
            guard?.Dispose();
        }
    }

    private static void EnsureFinalMissing(string output)
    {
        if (EntryExists(output))
            throw new IOException("Final output already exists; replacement is not allowed: " + output);
    }

    private static bool EntryExists(string path)
    {
        try { _ = File.GetAttributes(path); return true; }
        catch (FileNotFoundException) { return false; }
        catch (DirectoryNotFoundException) { return false; }
    }

    private static SafeFileHandle OpenIdentityGuard(string path)
    {
        var attributes = File.GetAttributes(path);
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            throw new IOException("Output paths must identify regular files: " + path);
        return File.OpenHandle(path, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete, FileOptions.None);
    }

    private static void EnsureIdentity(string path, FileIdentity expected)
    {
        using var handle = OpenIdentityGuard(path);
        if (FileIdentity.Read(handle) != expected)
            throw new IOException("Partial output was replaced; the replacement was preserved: " + path);
    }

    private readonly record struct FileIdentity(ulong Device, ulong Index)
    {
        internal static FileIdentity Read(SafeFileHandle handle)
        {
            if (OperatingSystem.IsWindows())
            {
                // BY_HANDLE_FILE_INFORMATION: DWORD volume serial at 0x1c, file index at 0x2c/0x30.
                var info = new byte[52];
                if (!GetFileInformationByHandle(handle, info)) ThrowIdentityError();
                ulong device = BinaryPrimitives.ReadUInt32LittleEndian(info.AsSpan(28));
                ulong index = (ulong)BinaryPrimitives.ReadUInt32LittleEndian(info.AsSpan(44)) << 32 |
                    BinaryPrimitives.ReadUInt32LittleEndian(info.AsSpan(48));
                return new FileIdentity(device, index);
            }
            // 64-bit Linux and Darwin stat layouts share st_ino at offset 8; Darwin's dev_t is 32-bit.
            // The oversized scratch buffer permits libc to write its complete platform stat structure.
            var stat = new byte[512];
            int fd = handle.DangerousGetHandle().ToInt32();
            int result;
            if (OperatingSystem.IsMacOS())
            {
                if (RuntimeInformation.ProcessArchitecture == Architecture.X64)
                    result = MacFstatInode64(fd, stat);
                else
                    result = MacFstat(fd, stat);
            }
            else result = LinuxFstat(fd, stat);
            GC.KeepAlive(handle);
            if (result != 0) ThrowIdentityError();
            ulong dev = OperatingSystem.IsMacOS()
                ? BinaryPrimitives.ReadUInt32LittleEndian(stat)
                : BinaryPrimitives.ReadUInt64LittleEndian(stat);
            return new FileIdentity(dev, BinaryPrimitives.ReadUInt64LittleEndian(stat.AsSpan(8)));
        }

        private static void ThrowIdentityError()
            => throw new IOException("Could not read output file identity.", new Win32Exception(Marshal.GetLastPInvokeError()));

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle handle, [Out] byte[] information);
        [DllImport("libc", EntryPoint = "fstat", SetLastError = true)]
        private static extern int LinuxFstat(int fd, [Out] byte[] stat);
        [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint = "fstat", SetLastError = true)]
        private static extern int MacFstat(int fd, [Out] byte[] stat);
        [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint = "fstat$INODE64", SetLastError = true)]
        private static extern int MacFstatInode64(int fd, [Out] byte[] stat);
    }
}
