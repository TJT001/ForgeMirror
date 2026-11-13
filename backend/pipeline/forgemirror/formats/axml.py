"""Minimal binary AndroidManifest.xml (AXML) reader/editor/writer.

Preserves the original chunk order and string indices, appends new strings, and
supports changing/adding application attributes and injecting provider/activity
children. Intended for the S6 manifest rewrite; validate with aapt2 after edits.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

CHUNK_STRING_POOL = 0x0001
CHUNK_RESOURCE_MAP = 0x0180
CHUNK_START_NAMESPACE = 0x0100
CHUNK_END_NAMESPACE = 0x0101
CHUNK_START_ELEMENT = 0x0102
CHUNK_END_ELEMENT = 0x0103
CHUNK_CDATA = 0x0104

TYPE_STRING = 0x03
TYPE_INT_BOOLEAN = 0x12

ANDROID_NS = "http://schemas.android.com/apk/res/android"

RESOURCE_IDS = {
    "name": 0x01010003,
    "exported": 0x01010010,
    "authorities": 0x01010018,
    "usesCleartextTraffic": 0x010104EC,
    "appComponentFactory": 0x0101057A,
}

SORTED_FLAG = 0x00000001
UTF8_FLAG = 0x00000100


class AxmlError(Exception):
    pass


@dataclass
class Attr:
    ns: int
    name: int
    raw: int
    data_type: int
    data: int


@dataclass
class StartNamespace:
    prefix: int
    uri: int


@dataclass
class EndNamespace:
    prefix: int
    uri: int


@dataclass
class StartElement:
    ns: int
    name: int
    attrs: list[Attr] = field(default_factory=list)


@dataclass
class EndElement:
    ns: int
    name: int


@dataclass
class CData:
    data: int
    data_type: int
    typed_data: int


class Document:
    def __init__(self) -> None:
        self.strings: list[str] = []
        self.flags = UTF8_FLAG
        self.resource_ids: list[int] = []
        self.chunks: list[object] = []

    # --- string table helpers -------------------------------------------------

    def index_of(self, value: str) -> int:
        try:
            return self.strings.index(value)
        except ValueError:
            self.strings.append(value)
            return len(self.strings) - 1

    def ensure_android_namespace(self) -> int:
        for index, chunk in enumerate(self.chunks):
            if isinstance(chunk, StartNamespace) and self.strings[chunk.uri] == ANDROID_NS:
                return index
        prefix = self.index_of("android")
        uri = self.index_of(ANDROID_NS)
        self.chunks.insert(0, StartNamespace(prefix, uri))
        self.chunks.append(EndNamespace(prefix, uri))
        return 0

    def android_ns_index(self) -> int:
        return self.index_of(ANDROID_NS)

    # --- element helpers ------------------------------------------------------

    def find_start(self, name: str, start: int = 0) -> int:
        for index in range(start, len(self.chunks)):
            chunk = self.chunks[index]
            if isinstance(chunk, StartElement) and self.strings[chunk.name] == name:
                return index
        raise AxmlError(f"element not found: {name}")

    def element_end(self, start_index: int) -> int:
        depth = 0
        for index in range(start_index, len(self.chunks)):
            chunk = self.chunks[index]
            if isinstance(chunk, StartElement):
                depth += 1
            elif isinstance(chunk, EndElement):
                depth -= 1
                if depth == 0:
                    return index
        raise AxmlError("unbalanced elements")

    def attr_value(self, element: StartElement, name: str) -> str | None:
        ns_index = self.android_ns_index()
        for attr in element.attrs:
            if attr.ns == ns_index and self.strings[attr.name] == name:
                if attr.data_type == TYPE_STRING and attr.data < len(self.strings):
                    return self.strings[attr.data]
                if attr.raw != 0xFFFFFFFF and attr.raw < len(self.strings):
                    return self.strings[attr.raw]
        return None

    def set_string_attr(self, element: StartElement, name: str, value: str) -> None:
        ns_index = self.android_ns_index()
        value_index = self.index_of(value)
        for attr in element.attrs:
            if attr.ns == ns_index and self.strings[attr.name] == name:
                attr.raw = value_index
                attr.data_type = TYPE_STRING
                attr.data = value_index
                return
        element.attrs.append(
            Attr(ns_index, self.index_of(name), value_index, TYPE_STRING, value_index)
        )

    def set_bool_attr(self, element: StartElement, name: str, value: bool) -> None:
        ns_index = self.android_ns_index()
        data = 0xFFFFFFFF if value else 0
        for attr in element.attrs:
            if attr.ns == ns_index and self.strings[attr.name] == name:
                attr.raw = 0xFFFFFFFF
                attr.data_type = TYPE_INT_BOOLEAN
                attr.data = data
                return
        element.attrs.append(
            Attr(ns_index, self.index_of(name), 0xFFFFFFFF, TYPE_INT_BOOLEAN, data)
        )

    def package_name(self) -> str | None:
        index = self.find_start("manifest")
        element = self.chunks[index]
        for attr in element.attrs:
            if attr.ns == 0xFFFFFFFF and self.strings[attr.name] == "package":
                if attr.data_type == TYPE_STRING:
                    return self.strings[attr.data]
        return None

    def application_names(self) -> tuple[str | None, str | None]:
        index = self.find_start("application")
        element = self.chunks[index]
        return self.attr_value(element, "name"), self.attr_value(element, "appComponentFactory")

    def manifest_version_code(self) -> int | None:
        index = self.find_start("manifest")
        element = self.chunks[index]
        ns_index = self.android_ns_index()
        for attr in element.attrs:
            if attr.ns == ns_index and self.strings[attr.name] == "versionCode":
                if attr.data_type in (0x10, 0x11):
                    return attr.data
        return None

    def rewrite_application(self, application: str, factory: str,
                            cleartext: bool = False) -> None:
        index = self.find_start("application")
        element = self.chunks[index]
        self.set_string_attr(element, "name", application)
        self.set_string_attr(element, "appComponentFactory", factory)
        if cleartext:
            self.set_bool_attr(element, "usesCleartextTraffic", True)
        self.chunks[index] = element

    def inject_child(self, parent: str, child_name: str, attrs: list[tuple[str, str | bool]]) -> None:
        parent_index = self.find_start(parent)
        parent_end = self.element_end(parent_index)
        namespace_index = self.android_ns_index()
        name_index = self.index_of(child_name)
        element = StartElement(namespace_index, name_index)
        for attr_name, value in attrs:
            if isinstance(value, bool):
                self.set_bool_attr(element, attr_name, value)
            else:
                self.set_string_attr(element, attr_name, value)
        self.chunks.insert(parent_end, EndElement(namespace_index, name_index))
        self.chunks.insert(parent_end, element)


# --- parsing -----------------------------------------------------------------


def _parse_string_pool(data: bytes, offset: int, header_size: int) -> tuple[list[str], int]:
    string_count, style_count, flags, strings_start, styles_start = struct.unpack_from(
        "<IIIII", data, offset + 8
    )
    if style_count != 0:
        raise AxmlError("styled string pools are not supported")
    offsets = struct.unpack_from("<" + "I" * string_count, data, offset + header_size)
    base = offset + strings_start
    utf8 = bool(flags & UTF8_FLAG)
    strings: list[str] = []
    for value_offset in offsets:
        position = base + value_offset
        if utf8:
            length = data[position]
            position += 1
            if length & 0x80:
                length = ((length & 0x7F) << 8) | data[position]
                position += 1
            strings.append(data[position : position + length].decode("utf-8", "replace"))
        else:
            length = struct.unpack_from("<H", data, position)[0]
            position += 2
            if length & 0x8000:
                length = ((length & 0x7FFF) << 16) | struct.unpack_from(
                    "<H", data, position
                )[0]
                position += 2
            strings.append(
                data[position : position + length * 2].decode("utf-16-le", "replace")
            )
    return strings, flags


def _parse_start_element(data: bytes, offset: int, header_size: int) -> StartElement:
    ns, name = struct.unpack_from("<II", data, offset + 16)
    attribute_start, attribute_size, attribute_count = struct.unpack_from(
        "<HHH", data, offset + 24
    )
    element = StartElement(ns, name)
    base = offset + header_size + attribute_start
    for index in range(attribute_count):
        position = base + index * attribute_size
        attr_ns, attr_name, raw = struct.unpack_from("<III", data, position)
        data_type = data[position + 15]
        typed_data = struct.unpack_from("<I", data, position + 16)[0]
        element.attrs.append(Attr(attr_ns, attr_name, raw, data_type, typed_data))
    return element


def parse(data: bytes) -> Document:
    chunk_type, header_size, total_size = struct.unpack_from("<HHI", data, 0)
    if chunk_type != 0x0003 or header_size != 8:
        raise AxmlError("not an AXML document")
    document = Document()
    position = 8
    while position < total_size:
        chunk_type, chunk_header, chunk_size = struct.unpack_from("<HHI", data, position)
        if chunk_size < 8 or position + chunk_size > len(data):
            raise AxmlError("bad chunk bounds")
        if chunk_type == CHUNK_STRING_POOL:
            document.strings, document.flags = _parse_string_pool(
                data, position, chunk_header
            )
        elif chunk_type == CHUNK_RESOURCE_MAP:
            count = (chunk_size - chunk_header) // 4
            document.resource_ids = list(
                struct.unpack_from("<" + "I" * count, data, position + chunk_header)
            )
        elif chunk_type == CHUNK_START_NAMESPACE:
            prefix, uri = struct.unpack_from("<II", data, position + 16)
            document.chunks.append(StartNamespace(prefix, uri))
        elif chunk_type == CHUNK_END_NAMESPACE:
            prefix, uri = struct.unpack_from("<II", data, position + 16)
            document.chunks.append(EndNamespace(prefix, uri))
        elif chunk_type == CHUNK_START_ELEMENT:
            document.chunks.append(_parse_start_element(data, position, chunk_header))
        elif chunk_type == CHUNK_END_ELEMENT:
            ns, name = struct.unpack_from("<II", data, position + 16)
            document.chunks.append(EndElement(ns, name))
        elif chunk_type == CHUNK_CDATA:
            cdata = struct.unpack_from("<I", data, position + 16)[0]
            data_type = data[position + 23]
            typed_data = struct.unpack_from("<I", data, position + 24)[0]
            document.chunks.append(CData(cdata, data_type, typed_data))
        else:
            document.chunks.append(data[position : position + chunk_size])
        position += chunk_size
    return document


# --- serialization -----------------------------------------------------------


def _encode_string_pool(strings: list[str], flags: int) -> bytes:
    utf8 = bool(flags & UTF8_FLAG)
    encoded: list[bytes] = []
    offsets: list[int] = []
    offset = 0
    for value in strings:
        offsets.append(offset)
        if utf8:
            raw = value.encode("utf-8")
            length = len(raw)
            if length < 0x80:
                prefix = bytes([length])
            else:
                prefix = bytes([(length >> 8) | 0x80, length & 0xFF])
            item = prefix + raw + b"\x00"
        else:
            raw = value.encode("utf-16-le")
            length = len(value)
            if length < 0x8000:
                prefix = struct.pack("<H", length)
            else:
                prefix = struct.pack("<HH", (length >> 16) | 0x8000, length & 0xFFFF)
            item = prefix + raw + b"\x00\x00"
        encoded.append(item)
        offset += len(item)

    header_size = 28
    offsets_size = 4 * len(strings)
    strings_start = header_size + offsets_size
    strings_start += (4 - (strings_start % 4)) % 4
    data = bytearray()
    for item in encoded:
        data.extend(item)
    size = strings_start + len(data)
    header = struct.pack(
        "<HHIIIIII",
        CHUNK_STRING_POOL,
        header_size,
        size,
        len(strings),
        0,
        flags & UTF8_FLAG,
        strings_start,
        0,
    )
    result = bytearray(header)
    result.extend(struct.pack("<" + "I" * len(strings), *offsets))
    result.extend(b"\x00" * (strings_start - len(result)))
    result.extend(data)
    return bytes(result)


def _serialize_start_element(element: StartElement) -> bytes:
    attribute_count = len(element.attrs)
    size = 36 + 20 * attribute_count
    result = bytearray(
        struct.pack("<HHI", CHUNK_START_ELEMENT, 16, size)
    )
    result.extend(struct.pack("<II", 0, 0xFFFFFFFF))
    result.extend(struct.pack("<II", element.ns, element.name))
    result.extend(struct.pack("<HHH", 20, 20, attribute_count))
    result.extend(struct.pack("<HHH", 0, 0, 0))
    for attr in element.attrs:
        result.extend(
            struct.pack(
                "<IIIHBBI",
                attr.ns,
                attr.name,
                attr.raw,
                8,
                0,
                attr.data_type,
                attr.data,
            )
        )
    return bytes(result)


def serialize(document: Document) -> bytes:
    body = bytearray()
    body.extend(_encode_string_pool(document.strings, document.flags))
    resource_ids = list(document.resource_ids)
    while len(resource_ids) < len(document.strings):
        resource_ids.append(0)
    for index, value in enumerate(document.strings):
        if resource_ids[index] == 0 and value in RESOURCE_IDS:
            resource_ids[index] = RESOURCE_IDS[value]
    resource_map_size = 8 + 4 * len(resource_ids)
    body.extend(
        struct.pack("<HHI", CHUNK_RESOURCE_MAP, 8, resource_map_size)
    )
    body.extend(struct.pack("<" + "I" * len(resource_ids), *resource_ids))

    for chunk in document.chunks:
        if isinstance(chunk, StartNamespace):
            body.extend(
                struct.pack(
                    "<HHIIIII", CHUNK_START_NAMESPACE, 16, 24, 0, 0xFFFFFFFF,
                    chunk.prefix, chunk.uri,
                )
            )
        elif isinstance(chunk, EndNamespace):
            body.extend(
                struct.pack(
                    "<HHIIIII", CHUNK_END_NAMESPACE, 16, 24, 0, 0xFFFFFFFF,
                    chunk.prefix, chunk.uri,
                )
            )
        elif isinstance(chunk, StartElement):
            body.extend(_serialize_start_element(chunk))
        elif isinstance(chunk, EndElement):
            body.extend(
                struct.pack(
                    "<HHIIIII", CHUNK_END_ELEMENT, 16, 24, 0, 0xFFFFFFFF,
                    chunk.ns, chunk.name,
                )
            )
        elif isinstance(chunk, CData):
            body.extend(struct.pack("<HHI", CHUNK_CDATA, 16, 28))
            body.extend(struct.pack("<II", 0, 0xFFFFFFFF))
            body.extend(
                struct.pack(
                    "<IHBBI",
                    chunk.data,
                    8,
                    0,
                    chunk.data_type,
                    chunk.typed_data,
                )
            )
        elif isinstance(chunk, bytes):
            body.extend(chunk)
        else:
            raise AxmlError(f"unknown chunk {type(chunk)}")

    total = 8 + len(body)
    return struct.pack("<HHI", 0x0003, 8, total) + bytes(body)
