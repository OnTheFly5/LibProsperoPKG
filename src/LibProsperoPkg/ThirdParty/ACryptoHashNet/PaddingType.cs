// Adapted from acryptohashnet; see README.md and LICENSE in this directory.
#nullable disable
namespace LibProsperoPkg.ThirdParty.ACryptoHashNet
{
    internal enum PaddingType
    {
        Custom,
        OneZeroFillAnd8BytesMessageLengthLittleEndian,
        OneZeroFillAnd8BytesMessageLengthBigEndian,
        OneZeroFillAnd16BytesMessageLengthBigEndian
    }
}
