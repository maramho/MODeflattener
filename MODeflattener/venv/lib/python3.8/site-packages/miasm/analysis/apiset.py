import sys
from pdb import pm
import ctypes

from miasm.analysis.binary import Container
from miasm.core.locationdb import LocationDB
from miasm.loader.pe_init import PE

ULONG = ctypes.c_uint32


def extract_409_resource(res):
    """
    Find the first resource id 0x409
    """
    if res is None:
        return None
    for x in res.resentries:
        if x.data:
            if x.name == 0x409:
                return x.data.s
        if x.offsettosubdir:
            ret = extract_409_resource(x.subdir)
            if ret:
                return ret
    return None


class ApiSetWin10(object):
    def __init__(self, fname_apisetschema):
        self.pe = PE(open(fname_apisetschema, "rb").read())
        self.version = self.get_version()

        loc_db = LocationDB()

        self.api_section = self.pe.getsectionbyname(".apiset").get_data()

    def get_version(self):
        res = self.pe.DirRes.resdesc

        data = extract_409_resource(res)
        token = b"ProductVersion\x00"
        out = []
        for c in token:
            out += [c, 0]
        out = bytes(out)
        index_start = data.find(out)
        assert index_start > 0
        index_start += len(out)
        index_stop = data.find(b"\x00\x00", index_start)
        assert index_start > 0
        data = data[index_start:index_stop]
        data = data[::2].decode()
        print("Version:", data)
        return data

    # Win 10
    """
    typedef struct _API_SET_NAMESPACE
    {
        ULONG Version;
        ULONG Size;
        ULONG Flags;
        ULONG Count;
        ULONG EntryOffset;
        ULONG HashOffset;
        ULONG HashFactor;
    } API_SET_NAMESPACE, *PAPI_SET_NAMESPACE;
    """

    class ApiSetHeader(ctypes.Structure):
        _fields_ = [
            ("Version", ULONG),
            ("Size", ULONG),
            ("Flags", ULONG),
            ("Count", ULONG),
            ("EntryOffset", ULONG),
            ("HashOffset", ULONG),
            ("HashFactor", ULONG),
        ]

    class ApiSetHashEntry(ctypes.Structure):
        _fields_ = [
            ("NumberOfEntries", ULONG),
        ]

    class ApiSetHosts_win10(ctypes.Structure):
        _fields_ = [
            ("Hash", ULONG),
            ("Index", ULONG),
        ]

    """
    typedef struct _API_SET_NAMESPACE_ENTRY
    {
        ULONG Flags;
        ULONG NameOffset;
        ULONG NameLength;
        ULONG HashedLength;
        ULONG ValueOffset;
        ULONG ValueCount;
    } API_SET_NAMESPACE_ENTRY, *PAPI_SET_NAMESPACE_ENTRY;
    """

    class ApiSetNameSpaceEntry(ctypes.Structure):
        _fields_ = [
            ("Flags", ULONG),
            ("NameOffset", ULONG),
            ("NameLength", ULONG),
            ("HashedLength", ULONG),
            ("ValueOffset", ULONG),
            ("ValueCount", ULONG),
        ]

    """
    typedef struct _API_SET_VALUE_ENTRY
    {
        ULONG Flags;
        ULONG NameOffset;
        ULONG NameLength;
        ULONG ValueOffset;
        ULONG ValueLength;
    } API_SET_VALUE_ENTRY, *PAPI_SET_VALUE_ENTRY;
    """

    class ApiSetValueEntry(ctypes.Structure):
        _fields_ = [
            ("Flags", ULONG),
            ("NameOffset", ULONG),
            ("NameLength", ULONG),
            ("ValueOffset", ULONG),
            ("ValueLength", ULONG),
        ]


    def get_redirection_by_name(self):
        hdr = self.ApiSetHeader.from_buffer_copy(
            self.api_section[0 : ctypes.sizeof(self.ApiSetHeader)]
        )
        print(repr(hdr))
        redir = {}
        for i in range(hdr.Count):
            addr = hdr.EntryOffset + i * ctypes.sizeof(self.ApiSetNameSpaceEntry)
            entry = self.ApiSetNameSpaceEntry.from_buffer_copy(
                self.api_section[addr : addr + ctypes.sizeof(self.ApiSetNameSpaceEntry)]
            )
            addr = entry.NameOffset
            redir_name = self.api_section[addr : addr + entry.NameLength]
            redir_name = redir_name[::2]
            # print(repr(redir_name))

            addr_descs = entry.ValueOffset

            host_out = {}
            for i in range(entry.ValueCount):
                addr = addr_descs + i * ctypes.sizeof(self.ApiSetValueEntry)
                host = self.ApiSetValueEntry.from_buffer_copy(
                    self.api_section[addr : addr + ctypes.sizeof(self.ApiSetValueEntry)]
                )
                if host.NameOffset != 0:
                    addr = host.NameOffset
                    importName = self.api_section[addr : addr + host.NameLength]
                    importName = importName[::2]
                else:
                    importName = ""
                # print(importName)

                addr = host.ValueOffset
                hostName = self.api_section[addr : addr + host.ValueLength]
                hostName = hostName[::2]
                if not importName:
                    importName = None
                host_out[importName] = hostName
            redir[redir_name.lower()] = host_out

        self.redir = redir

    # hash func can be found in ntdll!ApiSetpSearchForApiSet
    def compute_hash(self, apiset_lib_name, hashf):
        hashk = 0
        for c in apiset_lib_name:
            hashk = (hashk * hashf + c) & ((1 << 32) - 1)
        return hashk

    def get_entry_by_hash(self, dll_name):
        namespace = self.ApiSetHeader.from_buffer_copy(
            self.api_section[: ctypes.sizeof(self.ApiSetHeader)]
        )
        hash_to_search = self.compute_hash(dll_name, namespace.HashFactor)
        print("[+] Looking for hash 0x{0:08X} ({1})".format(hash_to_search, dll_name))
        for i in range(0, namespace.Count):
            offset = namespace.HashOffset + i * ctypes.sizeof(self.ApiSetHosts_win10)
            hash_entry = self.ApiSetHosts_win10.from_buffer_copy(
                self.api_section[
                    offset : offset + ctypes.sizeof(self.ApiSetHosts_win10)
                ]
            )
            if hash_entry.Hash == hash_to_search:
                ##if True:
                print("Hash %X" % hash_entry.Hash)
                offset = namespace.EntryOffset + hash_entry.Index * ctypes.sizeof(
                    self.ApiSetNameSpaceEntry
                )
                namespace_entry = self.ApiSetNameSpaceEntry.from_buffer_copy(
                    self.api_section[
                        offset : offset + ctypes.sizeof(self.ApiSetNameSpaceEntry)
                    ]
                )
                for c in range(0, namespace_entry.ValueCount):
                    print("value_entry[{0}]".format(c))
                    offset = namespace_entry.ValueOffset + c * ctypes.sizeof(
                        self.ApiSetValueEntry
                    )
                    value_entry = self.ApiSetValueEntry.from_buffer_copy(
                        self.api_section[
                            offset : offset + ctypes.sizeof(self.ApiSetValueEntry)
                        ]
                    )
                    value_name = self.api_section[
                        value_entry.NameOffset : value_entry.NameOffset
                        + value_entry.NameLength
                    ]
                    value_data = self.api_section[
                        value_entry.ValueOffset : value_entry.ValueOffset
                        + value_entry.ValueLength
                    ]
                    print("    -> {0}".format(value_name.replace(b"\x00", b"")))
                    print("    -> {0}".format(value_data.replace(b"\x00", b"")))


apiset = ApiSetWin10(sys.argv[1])
apiset.get_redirection_by_name()
dll_name = b"api-ms-win-core-processthreads-l1-1"
apiset.get_entry_by_hash(dll_name)


# fname = sys.argv[1]
# e = PE(open(fname, "rb").read())
# res = e.DirRes.resdesc


# data = extract_409_resource(res)
# token = b"ProductVersion\x00"
# out = []
# for c in token:
#     out += [c, 0]
# out = bytes(out)
# index_start = data.find(out)
# assert index_start > 0
# index_start += len(out)
# index_stop = data.find(b"\x00\x00", index_start)
# assert index_start > 0
# data = data[index_start:index_stop]
# data = data[::2].decode()
# print("Version:", data)

# loc_db = LocationDB()

# apiset.get_entry_by_hash(dll_name)
