import dataclasses
import datetime
import struct
import enum

from .structures import ArtifactLocation
from .serialization_formats import ccl_protobuff as pb


class DownloadSource(enum.Enum):
    shared_proto_db = 1
    history_db = 2


@dataclasses.dataclass(frozen=True)
class Download:  # TODO: all of the parameters
    source_file_path: str
    record_source: DownloadSource
    record_id: int
    guid: str
    hash: str
    url_chain: tuple[str, ...]
    tab_url: str
    tab_referrer_url: str
    target_path: str
    mime_type: str
    original_mime_type: str
    total_bytes: str
    start_time: datetime.datetime
    end_time: datetime.datetime

    @property
    def level_db_seq_no(self):
        if self.record_source == DownloadSource.shared_proto_db:
            return self.record_id

    @property
    def record_location(self) -> ArtifactLocation:
        if self.record_source == DownloadSource.shared_proto_db:
            return ArtifactLocation(self.source_file_path, None, f"Leveldb Seq: {self.record_id}")
        elif self.record_source == DownloadSource.history_db:
            return ArtifactLocation(self.source_file_path, None, f"SQLite Rowid: {self.record_id}")
        raise NotImplementedError()

    @property
    def url(self) -> str:
        return self.url_chain[-1]

    @property
    def file_size(self) -> int:
        return int(self.total_bytes)

    @classmethod
    def from_pb(cls, source_file: str, seq: int, proto: pb.ProtoObject, *, target_path_is_utf_16=True):
        if not proto.only("download_info").value:
            raise ValueError("download_info is empty")
        target_path_raw = proto.only("download_info").only("in_progress_info").only("target_path").value
        path_proto_length, path_char_count = struct.unpack("<II", target_path_raw[0:8])
        if path_proto_length != len(target_path_raw) - 4:
            raise ValueError("Invalid pickle for target path")
        if target_path_is_utf_16:
            target_path = target_path_raw[8: 8 + (path_char_count * 2)].decode("utf-16-le")
        else:
            target_path = target_path_raw[8: 8 + path_char_count].decode("utf-8")

        return cls(
            source_file,
            DownloadSource.shared_proto_db,
            seq,
            proto.only("download_info").only("guid").value,
            proto.only("download_info").only("in_progress_info").only("hash").value.hex(),
            tuple(x.value for x in proto.only("download_info").only("in_progress_info")["url_chain"]),
            proto.only("download_info").only("in_progress_info").only("tab_url").value,
            proto.only("download_info").only("in_progress_info").only("tab_url_referrer").value,
            target_path,
            proto.only("download_info").only("in_progress_info").only("mime_type").value,
            proto.only("download_info").only("in_progress_info").only("original_mime_type").value,
            proto.only("download_info").only("in_progress_info").only("total_bytes").value,
            proto.only("download_info").only("in_progress_info").only("start_time").value,
            proto.only("download_info").only("in_progress_info").only("end_time").value,
        )
