try:
    from socket import inet_pton
except ImportError:
    from typing import TYPE_CHECKING

    if TYPE_CHECKING:  # pragma: no cover
        pass
    else:
        # based on https://gist.github.com/nnemkin/4966028
        # this code only applies on Windows Python 2.7
        import ctypes
        import socket

        class SockAddr(ctypes.Structure):
            _fields_ = [
                ("sa_family", ctypes.c_short),
                ("__pad1", ctypes.c_ushort),
                ("ipv4_addr", ctypes.c_byte * 4),
                ("ipv6_addr", ctypes.c_byte * 16),
                ("__pad2", ctypes.c_ulong),
            ]

        WSAStringToAddressA = ctypes.windll.ws2_32.WSAStringToAddressA
        WSAAddressToStringA = ctypes.windll.ws2_32.WSAAddressToStringA

        def inet_pton(address_family, ip_string):
            # type: (int, str) -> bytes
            addr = SockAddr()
            ip_string_bytes = ip_string.encode("ascii")
            addr.sa_family = address_family
            addr_size = ctypes.c_int(ctypes.sizeof(addr))

            try:
                attribute, size = {
                    socket.AF_INET: ("ipv4_addr", 4),
                    socket.AF_INET6: ("ipv6_addr", 16),
                }[address_family]
            except KeyError:
                raise socket.error("unknown address family")

            if (
                WSAStringToAddressA(
                    ip_string_bytes,
                    address_family,
                    None,
                    ctypes.byref(addr),
                    ctypes.byref(addr_size),
                )
                != 0
            ):
                raise socket.error(ctypes.FormatError())

            return ctypes.string_at(getattr(addr, attribute), size)


try:
    from socket import inet_ntop
except ImportError:
    from typing import TYPE_CHECKING

    if TYPE_CHECKING:  # pragma: no cover
        pass
    else:
        # pure-python fallback for platforms lacking socket.inet_ntop
        # (Windows Python 2.7), mirroring the inet_pton fallback above
        import socket

        def inet_ntop(address_family, packed_ip):
            # type: (int, bytes) -> str
            octets = bytearray(packed_ip)
            if address_family == socket.AF_INET:
                return ".".join(str(b) for b in octets)
            if address_family == socket.AF_INET6:
                groups = [
                    (octets[i] << 8) | octets[i + 1] for i in range(0, 16, 2)
                ]
                # compress the longest run of zero groups
                best_start, best_len = -1, 0
                i = 0
                while i < len(groups):
                    if groups[i] == 0:
                        j = i
                        while j < len(groups) and groups[j] == 0:
                            j += 1
                        if j - i > best_len:
                            best_start, best_len = i, j - i
                        i = j
                    else:
                        i += 1
                if best_len > 1:
                    left = ":".join("%x" % g for g in groups[:best_start])
                    right = ":".join(
                        "%x" % g for g in groups[best_start + best_len :]
                    )
                    return left + "::" + right
                return ":".join("%x" % g for g in groups)
            raise socket.error("unknown address family %r" % address_family)
