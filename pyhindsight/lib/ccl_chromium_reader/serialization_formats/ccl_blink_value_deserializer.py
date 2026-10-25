"""
Copyright 2020, CCL Forensics

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import sys
import enum
import typing
from dataclasses import dataclass

from . import ccl_v8_value_deserializer

# See: https://chromium.googlesource.com/chromium/src/third_party/+/master/blink/renderer/bindings/core/v8/serialization
#      https://source.chromium.org/chromium/chromium/src/+/main:third_party/blink/renderer/bindings/modules/v8/serialization/v8_script_value_serializer_for_modules.cc


# WebCoreStrings are read as (length:uint32_t, string:UTF8[length]).
# RawStrings are read as (length:uint32_t, string:UTF8[length]).
# RawUCharStrings are read as
#     (length:uint32_t, string:UChar[length/sizeof(UChar)]).
# RawFiles are read as
#     (path:WebCoreString, url:WebCoreStrng, type:WebCoreString).
# There is a reference table that maps object references (uint32_t) to
# v8::Values.
# Tokens marked with (ref) are inserted into the reference table and given the
# next object reference ID after decoding.
# All tags except InvalidTag, PaddingTag, ReferenceCountTag, VersionTag,
# GenerateFreshObjectTag and GenerateFreshArrayTag push their results to the
# deserialization stack.
# There is also an 'open' stack that is used to resolve circular references.
# Objects or arrays may contain self-references. Before we begin to deserialize
# the contents of these values, they are first given object reference IDs (by
# GenerateFreshObjectTag/GenerateFreshArrayTag); these reference IDs are then
# used with ObjectReferenceTag to tie the recursive knot.

__version__ = "0.3"
__description__ = "Partial reimplementation of the Blink Javascript Object Serialization"
__contact__ = "Alex Caithness"

__DEBUG = False


def log(msg, debug_only=True):
    if __DEBUG or not debug_only:
        caller_name = sys._getframe(1).f_code.co_name
        caller_line = sys._getframe(1).f_code.co_firstlineno
        print(f"{caller_name} ({caller_line}):\t{msg}")


class BlobIndexType(enum.Enum):
    Blob = 0
    File = 1


@dataclass
class BlobIndex:
    index_type: BlobIndexType
    index_id: int


@dataclass(frozen=True)
class NativeFileHandle:
    is_dir: bool
    name: str
    token_index: int


@dataclass(frozen=True)
class CryptoKey:
    sub_type: "V8CryptoKeySubType"
    algorithm_type: typing.Optional["V8CryptoKeyAlgorithm"]
    hash_type: typing.Optional["V8CryptoKeyAlgorithm"]
    asymmetric_key_type: typing.Optional["V8AsymmetricCryptoKeyType"]
    byte_length: typing.Optional[int]
    public_exponent: typing.Optional[bytes]
    named_curve_type: typing.Optional["V8CryptoNamedCurve"]
    key_usage: "V8CryptoKeyUsage"
    key_data: bytes


class Constants:
    tag_kMessagePortTag = b"M"  # index:int -> MessagePort. Fills the result with
                                # transferred MessagePort.
    tag_kMojoHandleTag = b"h"   # index:int -> MojoHandle. Fills the result with
                                # transferred MojoHandle.
    tag_kBlobTag = b"b"         # uuid:WebCoreString, type:WebCoreString, size:uint64_t ->
                                # Blob (ref)
    tag_kBlobIndexTag = b"i"    # index:int32_t -> Blob (ref)
    tag_kFileTag = b"f"         # file:RawFile -> File (ref)
    tag_kFileIndexTag = b"e"    # index:int32_t -> File (ref)
    tag_kDOMFileSystemTag = b"d"  # type : int32_t, name:WebCoreString,
                                  # uuid:WebCoreString -> FileSystem (ref)
    tag_kNativeFileSystemFileHandleTag = b"n"  # name:WebCoreString, index:uint32_t
                                               # -> NativeFileSystemFileHandle (ref)
    tag_kNativeFileSystemDirectoryHandleTag = b"N"  # name:WebCoreString, index:uint32_t ->
                                                   # NativeFileSystemDirectoryHandle (ref)
    tag_kFileListTag = b"l"                     # length:uint32_t, files:RawFile[length] -> FileList (ref)
    tag_kFileListIndexTag = b"L"                # length:uint32_t, files:int32_t[length] -> FileList (ref)
    tag_kImageDataTag = b"#"                   # tags terminated by ImageSerializationTag::kEnd (see
                                               # SerializedColorParams.h), width:uint32_t,
                                               # height:uint32_t, pixelDataLength:uint64_t,
                                               # data:byte[pixelDataLength]
                                               # -> ImageData (ref)
    tag_kImageBitmapTag = b"g"        # tags terminated by ImageSerializationTag::kEnd (see
                                      # SerializedColorParams.h), width:uint32_t,
                                      # height:uint32_t, pixelDataLength:uint32_t,
                                      # data:byte[pixelDataLength]
                                      # -> ImageBitmap (ref)
    tag_kImageBitmapTransferTag = b"G"      # index:uint32_t -> ImageBitmap. For ImageBitmap transfer
    tag_kOffscreenCanvasTransferTag = b"H"  # index, width, height, id,
                                            # filter_quality::uint32_t ->
                                            # OffscreenCanvas. For OffscreenCanvas
                                            # transfer
    tag_kReadableStreamTransferTag = b"r"    # index:uint32_t
    tag_kTransformStreamTransferTag = b"m"   # index:uint32_t
    tag_kWritableStreamTransferTag = b"w"    # index:uint32_t
    tag_kDOMPointTag = b"Q"                  # x:Double, y:Double, z:Double, w:Double
    tag_kDOMPointReadOnlyTag = b"W"          # x:Double, y:Double, z:Double, w:Double
    tag_kDOMRectTag = b"E"                   # x:Double, y:Double, width:Double, height:Double
    tag_kDOMRectReadOnlyTag = b"R"           # x:Double, y:Double, width:Double, height:Double
    tag_kDOMQuadTag = b"T"                   # p1:Double, p2:Double, p3:Double, p4:Double
    tag_kDOMMatrixTag = b"Y"                 # m11..m44: 16 Double
    tag_kDOMMatrixReadOnlyTag = b"U"         # m11..m44: 16 Double
    tag_kDOMMatrix2DTag = b"I"               # a..f: 6 Double
    tag_kDOMMatrix2DReadOnlyTag = b"O"       # a..f: 6 Double
    tag_kCryptoKeyTag = b"K"                 # subtag:byte, props, usages:uint32_t,
    # keyDataLength:uint32_t, keyData:byte[keyDataLength]
    #                 If subtag=AesKeyTag:
    #                     props = keyLengthBytes:uint32_t, algorithmId:uint32_t
    #                 If subtag=HmacKeyTag:
    #                     props = keyLengthBytes:uint32_t, hashId:uint32_t
    #                 If subtag=RsaHashedKeyTag:
    #                     props = algorithmId:uint32_t, type:uint32_t,
    #                     modulusLengthBits:uint32_t,
    #                     publicExponentLength:uint32_t,
    #                     publicExponent:byte[publicExponentLength],
    #                     hashId:uint32_t
    #                 If subtag=EcKeyTag:
    #                     props = algorithmId:uint32_t, type:uint32_t,
    #                     namedCurve:uint32_t
    tag_kRTCCertificateTag = b"k"  # length:uint32_t, pemPrivateKey:WebCoreString,
    # pemCertificate:WebCoreString
    tag_kRTCEncodedAudioFrameTag = b"A"  # uint32_t -> transferred audio frame ID
    tag_kRTCEncodedVideoFrameTag = b"V"  # uint32_t -> transferred video frame ID
    tag_kVideoFrameTag = b"v"            # uint32_t -> transferred video frame ID

    # The following tags were used by the Shape Detection API implementation
    # between M71 and M81. During these milestones, the API was always behind
    # a flag. Usage was removed in https:#crrev.com/c/2040378.
    tag_kDeprecatedDetectedBarcodeTag = b"B"
    tag_kDeprecatedDetectedFaceTag = b"F"
    tag_kDeprecatedDetectedTextTag = b"t"

    tag_kDOMExceptionTag = b"x"  # name:String,message:String,stack:String
    tag_kVersionTag = b"\xff"  # version:uint32_t -> Uses this as the file version.
    tag_kTrailerOffsetTag = b"\xfe" # offset:uint64_t (fixed width, network order) from buffer, start size:uint32_t (fixed width, network order)
    tag_kTrailerRequiresInterfacesTag = b"\xA0"


class V8CryptoKeySubType(enum.IntEnum):
    """
    See: third_party/blink/renderer/bindings/modules/v8/serialization/web_crypto_sub_tags.h
    Used by the kCryptoKeyTag type
    """
    AesKey = 1
    HmacKey = 2
    # ID 3 was used by RsaKeyTag, while still behind experimental flag.
    RsaHashedKey = 4
    EcKey = 5
    NoParamsKey = 6


class V8CryptoKeyAlgorithm(enum.IntEnum):
    """
    See: third_party/blink/renderer/bindings/modules/v8/serialization/web_crypto_sub_tags.h
    Used by the kCryptoKeyTag type
    """
    AesCbcTag = 1
    HmacTag = 2
    RsaSsaPkcs1v1_5Tag = 3
    # ID 4 was used by RsaEs, while still behind experimental flag.
    Sha1Tag = 5
    Sha256Tag = 6
    Sha384Tag = 7
    Sha512Tag = 8
    AesGcmTag = 9
    RsaOaepTag = 10
    AesCtrTag = 11
    AesKwTag = 12
    RsaPssTag = 13
    EcdsaTag = 14
    EcdhTag = 15
    HkdfTag = 16
    Pbkdf2Tag = 17


class V8AsymmetricCryptoKeyType(enum.IntEnum):
    Public = 1
    Private = 2


class V8CryptoNamedCurve(enum.IntEnum):
    """
    See: third_party/blink/renderer/bindings/modules/v8/serialization/web_crypto_sub_tags.h
    Used by the kCryptoKeyTag type
    """
    P256 = 1
    P384 = 2
    P521 = 3


class V8CryptoKeyUsage(enum.IntFlag):
    """
    See: third_party/blink/renderer/bindings/modules/v8/serialization/web_crypto_sub_tags.h
    Used by the kCryptoKeyTag type
    """
    kExtractableUsage = 1 << 0
    kEncryptUsage = 1 << 1
    kDecryptUsage = 1 << 2
    kSignUsage = 1 << 3
    kVerifyUsage = 1 << 4
    kDeriveKeyUsage = 1 << 5
    kWrapKeyUsage = 1 << 6
    kUnwrapKeyUsage = 1 << 7
    kDeriveBitsUsage = 1 << 8


class BlinkV8Deserializer:
    def _read_varint(self, stream) -> int:
        return ccl_v8_value_deserializer.read_le_varint(stream)[0]

    def _read_varint32(self, stream) -> int:
        return ccl_v8_value_deserializer.read_le_varint(stream, is_32bit=True)[0]

    def _read_utf8_string(self, stream: typing.BinaryIO) -> str:
        length = self._read_varint32(stream)
        raw_string = stream.read(length)
        if len(raw_string) != length:
            raise ValueError("Could not read all of the utf-8 data")
        return raw_string.decode("utf-8")

    # def _read_uint32(self, stream: typing.BinaryIO) -> int:
    #     raw = stream.read(4)
    #     if len(raw) < 4:
    #         raise ValueError("Could not read enough data when reading int32")
    #     return struct.unpack("<I", raw)[0]

    def _read_file_index(self, stream: typing.BinaryIO) -> BlobIndex:
        return BlobIndex(BlobIndexType.File, self._read_varint(stream))

    def _read_blob_index(self, stream: typing.BinaryIO) -> BlobIndex:
        return BlobIndex(BlobIndexType.Blob, self._read_varint(stream))

    def _read_file_list_index(self, stream: typing.BinaryIO) -> typing.Iterable[BlobIndex]:
        length = self._read_varint(stream)
        result = [self._read_file_index(stream) for _ in range(length)]
        return result

    def _read_native_file_handle(self, is_dir: bool, stream: typing.BinaryIO) -> NativeFileHandle:
        return NativeFileHandle(is_dir, self._read_utf8_string(stream), self._read_varint(stream))

    def _read_crypto_key(self, stream: typing.BinaryIO):
        sub_type = V8CryptoKeySubType(stream.read(1)[0])

        if sub_type == V8CryptoKeySubType.AesKey:
            algorithm_id = V8CryptoKeyAlgorithm(self._read_varint32(stream))
            byte_length = self._read_varint32(stream)
            params = {
                "algorithm_type": algorithm_id,
                "byte_length": byte_length,
                "hash_type": None,
                "named_curve_type": None,
                "asymmetric_key_type": None,
                "public_exponent": None
            }
        elif sub_type == V8CryptoKeySubType.HmacKey:
            byte_length = self._read_varint32(stream)
            hash_id = V8CryptoKeyAlgorithm(self._read_varint32(stream))
            params = {
                "byte_length": byte_length,
                "hash_type": hash_id,
                "algorithm_type": None,
                "named_curve_type": None,
                "asymmetric_key_type": None,
                "public_exponent": None
            }
        elif sub_type == V8CryptoKeySubType.RsaHashedKey:
            algorithm_id = V8CryptoKeyAlgorithm(self._read_varint32(stream))
            asymmetric_key_type = V8AsymmetricCryptoKeyType(stream.read(1)[0])
            length_bytes = self._read_varint32(stream)
            public_exponent_length = self._read_varint32(stream)
            public_exponent = stream.read(public_exponent_length)
            if len(public_exponent) != public_exponent_length:
                raise ValueError(f"Could not read all of public exponent data")
            hash_id = V8CryptoKeyAlgorithm(self._read_varint32(stream))
            params = {
                "algorithm_type": algorithm_id,
                "asymmetric_key_type": asymmetric_key_type,
                "byte_length": length_bytes,
                "public_exponent": public_exponent,
                "hash_type": hash_id,
                "named_curve_type": None
            }

        elif sub_type == V8CryptoKeySubType.EcKey:
            algorithm_id = V8CryptoKeyAlgorithm(self._read_varint32(stream))
            asymmetric_key_type = V8AsymmetricCryptoKeyType(stream.read(1)[0])
            named_curve = V8CryptoNamedCurve(self._read_varint32(stream))
            params = {
                "algorithm_type": algorithm_id,
                "asymmetric_key_type": asymmetric_key_type,
                "named_curve_type": named_curve,
                "hash_type": None,
                "byte_length": None,
                "public_exponent": None
            }
        elif sub_type == V8CryptoKeySubType.NoParamsKey:
            algorithm_id = V8CryptoKeyAlgorithm(self._read_varint32(stream))
            params = {
                "algorithm_type": algorithm_id,
                "hash_type": None,
                "asymmetric_key_type": None,
                "byte_length": None,
                "named_curve_type": None,
                "public_exponent": None
            }
        else:
            raise ValueError(f"Unknown V8CryptoKeySubType {sub_type}")

        params["key_usage"] = V8CryptoKeyUsage(self._read_varint32(stream))
        key_length = self._read_varint32(stream)
        key_data = stream.read(key_length)
        if len(key_data) < key_length:
            raise ValueError("Could not read all key data")

        params["key_data"] = key_data
        return CryptoKey(sub_type, **params)

    def _not_implemented(self, stream):
        raise NotImplementedError()

    def read(self, stream: typing.BinaryIO) -> typing.Any:
        tag = stream.read(1)

        func = {
            Constants.tag_kMessagePortTag: lambda x: self._not_implemented(x),
            Constants.tag_kMojoHandleTag: lambda x: self._not_implemented(x),
            Constants.tag_kBlobTag: lambda x: self._not_implemented(x),
            Constants.tag_kBlobIndexTag: lambda x: self._read_blob_index(x),
            Constants.tag_kFileTag: lambda x: self._not_implemented(x),
            Constants.tag_kFileIndexTag: lambda x: self._read_file_index(x),
            Constants.tag_kDOMFileSystemTag: lambda x: self._not_implemented(x),
            Constants.tag_kNativeFileSystemFileHandleTag: lambda x: self._read_native_file_handle(False, x),
            Constants.tag_kNativeFileSystemDirectoryHandleTag: lambda x: self._read_native_file_handle(True, x),
            Constants.tag_kFileListTag: lambda x: self._not_implemented(x),
            Constants.tag_kFileListIndexTag: lambda x: self._read_file_list_index(x),
            Constants.tag_kImageDataTag: lambda x: self._not_implemented(x),
            Constants.tag_kImageBitmapTag: lambda x: self._not_implemented(x),
            Constants.tag_kImageBitmapTransferTag: lambda x: self._not_implemented(x),
            Constants.tag_kOffscreenCanvasTransferTag: lambda x: self._not_implemented(x),
            Constants.tag_kReadableStreamTransferTag: lambda x: self._not_implemented(x),
            Constants.tag_kTransformStreamTransferTag: lambda x: self._not_implemented(x),
            Constants.tag_kWritableStreamTransferTag: lambda x: self._not_implemented(x),
            Constants.tag_kDOMPointTag: lambda x: self._not_implemented(x),
            Constants.tag_kDOMPointReadOnlyTag: lambda x: self._not_implemented(x),
            Constants.tag_kDOMRectTag: lambda x: self._not_implemented(x),
            Constants.tag_kDOMRectReadOnlyTag: lambda x: self._not_implemented(x),
            Constants.tag_kDOMQuadTag: lambda x: self._not_implemented(x),
            Constants.tag_kDOMMatrixTag: lambda x: self._not_implemented(x),
            Constants.tag_kDOMMatrixReadOnlyTag: lambda x: self._not_implemented(x),
            Constants.tag_kDOMMatrix2DTag: lambda x: self._not_implemented(x),
            Constants.tag_kDOMMatrix2DReadOnlyTag: lambda x: self._not_implemented(x),
            Constants.tag_kCryptoKeyTag: lambda x: self._read_crypto_key(x),
            Constants.tag_kRTCCertificateTag: lambda x: self._not_implemented(x),
            Constants.tag_kRTCEncodedAudioFrameTag: lambda x: self._not_implemented(x),
            Constants.tag_kRTCEncodedVideoFrameTag: lambda x: self._not_implemented(x),
            Constants.tag_kVideoFrameTag: lambda x: self._not_implemented(x),
            Constants.tag_kDOMExceptionTag: lambda x: self._not_implemented(x)
        }.get(tag)

        if func is None:
            raise ValueError(f"Unknown tag: {tag}")

        return func(stream)
