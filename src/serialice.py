# Python interface for the SerialICE protocol

BINARY_READ_MEM8   = b"\x00"
BINARY_READ_MEM16  = b"\x01"
BINARY_READ_MEM32  = b"\x02"
BINARY_READ_MEM64  = b"\x03"
BINARY_WRITE_MEM8  = b"\x10"
BINARY_WRITE_MEM16 = b"\x11"
BINARY_WRITE_MEM32 = b"\x12"
BINARY_WRITE_MEM64 = b"\x13"
BINARY_READ_IO8    = b"\x20"
BINARY_READ_IO16   = b"\x21"
BINARY_READ_IO32   = b"\x22"
BINARY_WRITE_IO8   = b"\x30"
BINARY_WRITE_IO16  = b"\x31"
BINARY_WRITE_IO32  = b"\x32"
BINARY_RDMSR       = b"\x40"
BINARY_WRMSR       = b"\x41"
BINARY_CPUID       = b"\x42"
BINARY_RDTSC       = b"\x43"
BINARY_RDTSCP      = b"\x44"
BINARY_NOP         = b"\xaa"
BINARY_ACK         = b"\x55"
BINARY_NAK         = b"\xbb"

class SerialICE:
    def __init__(self, ser):
        self._ser = ser

    def handshake(self):
        """Wait until the device acknowledges a nop command
        """

        while True:
            # Clear any previously buffered bytes
            self._ser.read(self._ser.in_waiting)

            # Trigger prompt (exiting binary mode if needed)
            self._ser.write(b"~")
            resp = self._ser.read(5)
            if resp == b"~\r\n> " or resp == BINARY_ACK + b"\r\n> ":
                break

        # Enter binary mode
        self._ser.write(b"*eb")
        resp = self._ser.read(4)
        if resp != b"*eb" + BINARY_ACK:
            raise Exception(f"Got {resp} instead of binary mode ACK")

    def bin_cmd(self, req, resp_len):
        self._ser.write(req)
        resp = self._ser.read(resp_len)
        if self._ser.read(1) != BINARY_ACK:
            raise Exception(f"Trailing ACK missing from response {resp}")
        return resp

    def read_mem(self, addr: int, size: int) -> int:
        if size == 1:
            resp = self.bin_cmd(BINARY_READ_MEM8 + addr.to_bytes(4, byteorder='little'), 1)
            return resp[0]
        elif size == 2:
            resp = self.bin_cmd(BINARY_READ_MEM16 + addr.to_bytes(4, byteorder='little'), 2)
            return int.from_bytes(resp[:2], byteorder='little')
        elif size == 4:
            resp = self.bin_cmd(BINARY_READ_MEM32 + addr.to_bytes(4, byteorder='little'), 4)
            return int.from_bytes(resp[:4], byteorder='little')
        elif size == 8:
            resp = self.bin_cmd(BINARY_READ_MEM64 + addr.to_bytes(4, byteorder='little'), 8)
            return int.from_bytes(resp[:8], byteorder='little')
        else:
            raise Exception(f"Invalid size {size} for read_mem")

    def write_mem(self, addr: int, size: int, val: int) -> int:
        if size == 1:
            self.bin_cmd(BINARY_WRITE_MEM8 + addr.to_bytes(4, byteorder='little') \
                                           + val.to_bytes(1, byteorder='little'), 0)
        elif size == 2:
            self.bin_cmd(BINARY_WRITE_MEM16 + addr.to_bytes(4, byteorder='little') \
                                            + val.to_bytes(2, byteorder='little'), 0)
        elif size == 4:
            self.bin_cmd(BINARY_WRITE_MEM32 + addr.to_bytes(4, byteorder='little') \
                                            + val.to_bytes(4, byteorder='little'), 0)
        elif size == 8:
            self.bin_cmd(BINARY_WRITE_MEM64 + addr.to_bytes(4, byteorder='little') \
                                            + val.to_bytes(8, byteorder='little'), 0)
        else:
            raise Exception(f"Invalid size {size} for write_mem")

    def read_io(self, addr: int, size: int) -> int:
        if size == 1:
            resp = self.bin_cmd(BINARY_READ_IO8 + addr.to_bytes(2, byteorder='little'), 1)
            return resp[0]
        elif size == 2:
            resp = self.bin_cmd(BINARY_READ_IO16 + addr.to_bytes(2, byteorder='little'), 2)
            return int.from_bytes(resp[:2], byteorder='little')
        elif size == 4:
            resp = self.bin_cmd(BINARY_READ_IO32 + addr.to_bytes(2, byteorder='little'), 4)
            return int.from_bytes(resp[:4], byteorder='little')
        else:
            raise Exception(f"Invalid size {size} for read_io")

    def write_io(self, addr: int, size: int, val: int) -> int:
        if size == 1:
            self.bin_cmd(BINARY_WRITE_IO8 + addr.to_bytes(2, byteorder='little') \
                                          + val.to_bytes(1, byteorder='little'), 0)
        elif size == 2:
            self.bin_cmd(BINARY_WRITE_IO16 + addr.to_bytes(2, byteorder='little') \
                                           + val.to_bytes(2, byteorder='little'), 0)
        elif size == 4:
            self.bin_cmd(BINARY_WRITE_IO32 + addr.to_bytes(2, byteorder='little') \
                                           + val.to_bytes(4, byteorder='little'), 0)
        else:
            raise Exception(f"Invalid size {size} for write_io")

    def rdmsr(self, ecx: int) -> (int, int):
        resp = self.bin_cmd(BINARY_RDMSR + ecx.to_bytes(4, byteorder='little'), 8)
        return int.from_bytes(resp[:4], byteorder='little'), \
               int.from_bytes(resp[4:], byteorder='little')

    def wrmsr(self, ecx: int, eax: int, edx: int):
        self.bin_cmd(BINARY_WRMSR + ecx.to_bytes(4, byteorder='little') \
                                  + eax.to_bytes(4, byteorder='little') \
                                  + edx.to_bytes(4, byteorder='little'), 0)

    def cpuid(self, eax: int, ecx: int) -> (int, int, int, int):
        resp = self.bin_cmd(BINARY_CPUID + eax.to_bytes(4, byteorder='little') \
                                         + ecx.to_bytes(4, byteorder='little'), 16)
        return int.from_bytes(resp[:4], byteorder='little'), \
               int.from_bytes(resp[4:8], byteorder='little'), \
               int.from_bytes(resp[8:12], byteorder='little'), \
               int.from_bytes(resp[12:], byteorder='little')

    def rdtsc(self) -> (int, int):
        resp = self.bin_cmd(BINARY_RDTSC, 8)
        return int.from_bytes(resp[:4], byteorder='little'), \
               int.from_bytes(resp[4:], byteorder='little')

    def rdtscp(self) -> (int, int, int):
        resp = self.bin_cmd(BINARY_RDTSCP, 12)
        return int.from_bytes(resp[:4], byteorder='little'), \
               int.from_bytes(resp[4:8], byteorder='little'), \
               int.from_bytes(resp[8:], byteorder='little')
