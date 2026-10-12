"""Registry of every cipher the benchmark knows how to run.

To add a new cipher:
  1. Put the implementation under LW_Block_Cipher/ or LW_Stream_Cipher/ with a
     Python wrapper module exposing
         <enc>(plaintext: bytes, key: bytes[, block_size: int]) -> (output, time, throughput, ram)
         <dec>(ciphertext: bytes, key: bytes[, block_size: int]) -> (output, time, throughput, ram)
  2. If it is C, add its .so target to the Makefile so `make build` compiles it.
  3. Add a Cipher(...) entry to CIPHERS below.
  4. Add its name to the `ciphers[]` array in Arduino_code/receive_data_from_RP
     if you want energy measurements for it.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

STREAM = "-"  # block size placeholder used for stream ciphers


@dataclass(frozen=True)
class Cipher:
    name: str                      # CLI name, also sent to the Arduino
    label: str                     # name written to the result CSVs
    path: str                      # directory holding the wrapper module
    module: str                    # wrapper module name
    enc: str                       # encrypt function name
    dec: str                       # decrypt function name
    sizes: Dict[str, List[str]]    # block size -> supported key sizes
    pass_block_size: bool = False  # wrapper takes block_size as 3rd argument
    # Optional per-key-size overrides: key size -> (enc function, dec function)
    per_key: Dict[str, tuple] = field(default_factory=dict)
    kind: str = "block"            # "block" or "stream"
    key_format: str = "bytes"      # "bytes", or "bits" for wrappers expecting a '0101...' string
    impl: str = "C"                # "C" or "Python"

    def functions_for(self, key_size: str):
        return self.per_key.get(key_size, (self.enc, self.dec))

    def configs(self):
        """All (block_size, key_size) pairs this cipher supports."""
        return [(b, k) for b, keys in self.sizes.items() for k in keys]


def _stream(name, label, path, module, enc, dec, keys, impl="C"):
    return Cipher(name, label, path, module, enc, dec, {STREAM: keys}, kind="stream", impl=impl)


_SIMON_SPECK_C = {"32": ["64"], "48": ["96"], "64": ["128"], "96": ["144"], "128": ["256"]}
_SIMON_SPECK_PY = {"32": ["64"], "48": ["96"], "64": ["96", "128"], "96": ["96"], "128": ["128", "192", "256"]}

_CIPHER_LIST = [
    # ---- Conventional baseline ----
    Cipher("aes", "c-AES", "Conv_cipher/AES/c_imp", "cAES_main",
           "c_aes_encrypt_file", "c_aes_decrypt_file", {"128": ["128", "192", "256"]}),
    Cipher("py-aes", "py-AES", "Conv_cipher/AES/python_imp", "pyaes_main",
           "pyaes_encrypt_file", "pyaes_decrypt_file", {"128": ["128", "192", "256"]},
           pass_block_size=True, impl="Python"),

    # ---- Lightweight block ciphers ----
    Cipher("present", "c-PRESENT", "LW_Block_Cipher/SPN/PRESENT/c_imp", "cpresent_main",
           "", "", {"64": ["80", "128"]}, key_format="bits",
           per_key={"80": ("c_present_encrypt_file_key_80", "c_present_decrypt_file_key_80"),
                    "128": ("c_present_encrypt_file_key_128", "c_present_decrypt_file_key_128")}),
    Cipher("py-present", "py-PRESENT", "LW_Block_Cipher/SPN/PRESENT/python_imp", "pypresent_main",
           "pypresent_encrypt_file", "pypresent_decrypt_file", {"64": ["80", "128"]}, impl="Python"),
    Cipher("xtea", "XTEA", "LW_Block_Cipher/FN/XTEA/c_imp", "cXTEA_main",
           "c_xtea_encrypt_file", "c_xtea_decrypt_file", {"64": ["128"]}),
    Cipher("py-xtea", "py-XTEA", "LW_Block_Cipher/FN/XTEA/python_imp", "pyxtea_main",
           "pyxtea_encrypt_file", "pyxtea_decrypt_file", {"64": ["128"]}, impl="Python"),
    Cipher("clefia", "c-CLEFIA", "LW_Block_Cipher/GFN/CLEFIA/c_imp", "cClefia_main",
           "cClefia_encrypt_file", "cClefia_decrypt_file", {"128": ["128", "192", "256"]}),
    Cipher("simon", "SIMON", "LW_Block_Cipher/FN/SIMON/c_imp", "cSIMON_main",
           "c_simon_encrypt_file", "c_simon_decrypt_file", _SIMON_SPECK_C, pass_block_size=True),
    Cipher("py-simon", "py-SIMON", "LW_Block_Cipher/FN/SIMON/python_imp", "pysimon_main",
           "pysimon_encrypt_file", "pysimon_decrypt_file", _SIMON_SPECK_PY,
           pass_block_size=True, impl="Python"),
    Cipher("speck", "SPECK", "LW_Block_Cipher/ARX/SPECK/c_imp", "cSPECK_main",
           "c_speck_encrypt_file", "c_speck_decrypt_file", _SIMON_SPECK_C, pass_block_size=True),
    Cipher("py-speck", "py-SPECK", "LW_Block_Cipher/ARX/SPECK/python_imp", "pyspeck_main",
           "pyspeck_encrypt_file", "pyspeck_decrypt_file", _SIMON_SPECK_PY,
           pass_block_size=True, impl="Python"),

    # ---- Stream ciphers / lightweight AE ----
    _stream("ascon", "c-ASCON", "LW_Stream_Cipher/LWAE/ASCON/c_imp", "cAscon_main",
            "c_ascon_encrypt_file", "c_ascon_decrypt_file", ["128"]),
    _stream("grain-128a", "c-Grain-128a", "LW_Stream_Cipher/LWAE/Grain128a/c_imp", "cGrain128a_main",
            "c_grain128_encrypt_file", "c_grain128_decrypt_file", ["128"]),
    _stream("grain-v1", "c-Grain-v1-80", "LW_Stream_Cipher/eSTREAM/HW_oriented/Grain/c_imp", "cGrain_main",
            "c_grain_v1_encrypt_file", "c_grain_v1_decrypt_file", ["80"]),
    _stream("mickey", "c-MICKEY-80", "LW_Stream_Cipher/eSTREAM/HW_oriented/Mickey/c_imp", "cMickey_main",
            "c_mickey_encrypt_file", "c_mickey_decrypt_file", ["80"]),
    _stream("trivium", "c-Trivium-80", "LW_Stream_Cipher/eSTREAM/HW_oriented/Trivium/c_imp", "cTRivium_main",
            "c_trivium_encrypt_file", "c_trivium_decrypt_file", ["80"]),
    _stream("salsa", "c-Salsa-128", "LW_Stream_Cipher/eSTREAM/SW_oriented/Salsa/c_imp", "cSalsa_main",
            "c_salsa_encrypt_file", "c_salsa_decrypt_file", ["128"]),
    _stream("sosemanuk", "c-Sosemanuk-128", "LW_Stream_Cipher/eSTREAM/SW_oriented/Sosemanuk/c_imp", "cSosemanuk_main",
            "c_sosemanuk_encrypt_file", "c_sosemanuk_decrypt_file", ["128"]),
    # py-rabbit is not registered: its wrapper (Rabbit/python_imp/pyrabbit_main.py) does not round-trip yet.
]

CIPHERS: Dict[str, Cipher] = {c.name: c for c in _CIPHER_LIST}


def get(name: str) -> Optional[Cipher]:
    return CIPHERS.get(name)
