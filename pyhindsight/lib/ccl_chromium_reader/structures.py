import typing

from .profile_folder_protocols import ArtifactLocationProtocol


class ArtifactLocation(ArtifactLocationProtocol):
    def __init__(self, source_file: str, offset: typing.Optional[int], friendly_string: str):
        self._source_file = source_file
        self._offset = offset
        self._friendly_string = friendly_string

    @property
    def source_file(self) -> str:
        return self._source_file

    @property
    def offset(self) -> typing.Optional[int]:
        return self._offset

    @property
    def friendly_string(self) -> str:
        return self._friendly_string

    def __str__(self):
        return self._friendly_string
