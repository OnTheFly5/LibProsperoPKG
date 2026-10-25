// Adapted from acryptohashnet; see README.md and LICENSE in this directory.
#nullable disable
using System.Runtime.CompilerServices;

namespace LibProsperoPkg.ThirdParty.ACryptoHashNet
{
    internal static class BitOperations
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint RotateLeft(this uint x, int n)
        {
            return x << n | x >> 32 - n;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong RotateLeft(this ulong x, int n)
        {
            return x << n | x >> 64 - n;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint RotateRight(this uint x, int n)
        {
            return x >> n | x << 32 - n;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong RotateRight(this ulong x, int n)
        {
            return x >> n | x << 64 - n;
        }
    }
}
