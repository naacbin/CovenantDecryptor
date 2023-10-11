from Crypto.Util.number import bytes_to_long
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad
from base64 import b64encode, b64decode
from re import match, search
from enum import Enum
from pathlib import Path
from typing_extensions import Annotated
from typing import Optional
from rich import print
import logging
import typer
import json

app = typer.Typer(add_completion=False)

aes_key = b""

# https://github.com/tiangolo/typer/issues/290
class KeyType(str, Enum):
    STRING = "string"
    BASE64 = "base64"
    HEX = "hex"


class PacketType(str, Enum):
    REQUEST = "Request"
    RESPONSE = "Response"


def is_hex(s: str) -> bool:
    """Check if a string represents a valid hexadecimal value.

    Args:
        s (str): The input string to be checked.

    Returns:
        bool: True if it's a valid hexadecimal, False otherwise.
    """
    hex_pattern = r"^[0-9A-Fa-f]+$"
    return bool(match(hex_pattern, s)) and len(s) % 2 == 0


def is_base64(s: str) -> bool:
    """Check if a string represents a valid base64 value.

    Args:
        s (str): The input string to be checked.

    Returns:
        bool: True if it's a valid base64, False otherwise.
    """
    try:
        return b64encode(b64decode(s.encode())) == s.encode()
    except Exception:
        return False


def aes_decrypt(cipher_text: bytes, key: bytes, iv: bytes) -> Optional[bytes]:
    """Decrypt a ciphertext using AES encryption in CBC mode.

    Args:
        cipher_text (bytes): The ciphertext to be decrypted.
        key (bytes): The encryption key.
        iv (bytes): The initialization vector.

    Returns:
        bytes | None: The decrypted plaintext if successful, or None if an error occurs.
    """
    try:
        aes = AES.new(key, AES.MODE_CBC, iv)
        plaintext = aes.decrypt(cipher_text)
        return unpad(plaintext, AES.block_size)
    except Exception as e:
        print(f"[red][-] Error : {str(e)}[/red]")
        logging.debug(f"[-] Cipher text : {cipher_text}")
        logging.debug(f"[-] Key : {key}")
        logging.debug(f"[-] IV : {iv}")
        return None


def rsa_decrypt(cipher_text: bytes, private_key: RSA.RsaKey) -> Optional[bytes]:
    """Decrypt a ciphertext using RSA encryption with OAEP as padding.

    Args:
        cipher_text (bytes): The ciphertext to be decrypted.
        private_key (RSA.RsaKey): The RSA private key.

    Returns:
        bytes | None: The decrypted plaintext if successful, or None if an error occurs.
    """
    try:
        cipher = PKCS1_OAEP.new(private_key)
        return cipher.decrypt(cipher_text)
    except Exception as e:
        print(f"[red][-] Error : {str(e)}[/red]")
        logging.debug(f"[-] Cipher text : {cipher_text}")
        logging.debug(f"[-] Private key : {private_key}")
        return None


def decrypt_packet(packet: bytes) -> Optional[bytes]:
    """Decrypt a packet containing an encrypted message.

    Args:
        packet (bytes): The packet to be decrypted.

    Returns:
        bytes | None: The decrypted message if aes_decrypt is successful, or None if an error occurs.
    """
    data = json.loads(packet)
    encrypted_message = b64decode(data["EncryptedMessage"].encode())
    iv = b64decode(data["IV"].encode())
    return aes_decrypt(encrypted_message, aes_key, iv)


def process_communication(
    packet: str, line_count: int, packet_type: PacketType
) -> bool:
    """Print decrypted message of a packet.

    Args:
        packet (str): The packet in base64 to be decrypted.
        line_count (int): The number of lines processed.
        packet_type (PacketType): The type of packet "request" or "response".

    Returns:
        bool: True if the packet is not empty, False otherwise.
    """
    bclear_packet = decrypt_packet(b64decode(packet.encode()))
    if bclear_packet is None:
        return False
    try:
        clear_packet = bclear_packet.decode()
    except UnicodeDecodeError:
        clear_packet = b64encode(bclear_packet).decode()
    print(f"[*] {packet_type.value} message {line_count} : " + clear_packet)
    return True


def extract_base64(data: str) -> Optional[str]:
    """Extract a base64 string of a data string.

    Args:
        data (str): The input string from which to extract base64 data.

    Returns:
        str | None: The base64 string if one is found, None otherwise.
    """
    for string in data.replace("\\n", "").split():
        string = string.strip()
        if is_base64(string):
            logging.debug(f"[*] Data field : {string}")
            return string
    print("[red][-] base64 packet not found.[/red]")
    return None


def convert_key(key: str, key_type: KeyType = KeyType.STRING) -> Optional[bytes]:
    """Convert a key that could be of differents format to a bytes string.

    Args:
        key (str): The key to transform to bytes string.
        key_type (KeyType, optional): The type of the key from which to convert. Defaults to KeyType.STRING.

    Returns:
        bytes | None: The raw key if the decoding is successful, None otherwise.
    """
    if key_type == KeyType.STRING:
        bkey = key.encode()
    elif key_type == KeyType.HEX:
        if is_hex(key):
            bkey = bytes.fromhex(key)
        else:
            print("[red][-] The key is not in an hexadecimal format.[/red]")
            return None
    elif key_type == KeyType.BASE64:
        if is_base64(key):
            bkey = b64decode(key.encode())
        else:
            print("[red][-] The key is not in an base64 format.[/red]")
            return None
    return bkey


@app.command("decrypt")
def decrypt_communication(
    file_path: Annotated[
        Path,
        typer.Option(
            "-i",
            "--input",
            help="Path to the file containing Covenant data traffic.",
            exists=True,
            file_okay=True,
            dir_okay=False,
            writable=False,
            readable=True,
            resolve_path=True,
        ),
    ],
    key: Annotated[
        str,
        typer.Option(
            "-k",
            "--key",
            help="The AES key used to decrypt Covennant traffic (post Stage 0). "
            "Can be string, hexadecimal or base64.",
        ),
    ],
    key_type: Annotated[
        KeyType, typer.Option("-t", "--type-key", help="The type of key.")
    ] = KeyType.STRING.value,
    skip: Annotated[
        int,
        typer.Option("-s", "--skip", help="First n packet to skip."),
    ] = 0,
):
    """Decrypt the Covenant communication using the AES key of stage 1."""
    global aes_key
    bkey = convert_key(key, key_type)
    if bkey is None:
        raise typer.Exit(code=1)
    aes_key = bkey

    with open(file_path, "r") as file:
        for line_count, line in enumerate(file, start=1):
            if line_count - 1 < skip:
                continue
            if line.startswith("i="):
                match = search(r"data=([^&]+)", line)
                if match:
                    if not process_communication(
                        match.group(1), line_count, PacketType.RESPONSE
                    ):
                        print(f"[red][-] Packet {line_count} decryption failed.[/red]")

            elif line.startswith("<html>"):
                for word in line.replace("\\n", "").split():
                    if is_base64(word.strip()):
                        if not process_communication(
                            word, line_count, PacketType.REQUEST
                        ):
                            print(
                                f"[red][-] Packet {line_count} decryption failed.[/red]"
                            )


@app.command("key")
def get_aes_key(
    file_path: Annotated[
        Path,
        typer.Option(
            "-i",
            "--input",
            help="Path to a file containing the data packet transmitting AES key of Covenant communication.",
            exists=True,
            file_okay=True,
            dir_okay=False,
            writable=False,
            readable=True,
            resolve_path=True,
        ),
    ],
    key: Annotated[
        str,
        typer.Option(
            "-k",
            "--key",
            help="The AES key used to decrypt the Covenant data packet. "
            "Can be string, hexadecimal or base64.",
        ),
    ],
    private_key_file: Annotated[
        Path,
        typer.Option(
            "-r",
            "--rsa",
            help="The RSA key file used to decrypt the new AES key.",
            exists=True,
            file_okay=True,
            dir_okay=False,
            writable=False,
            readable=True,
            resolve_path=True,
        ),
    ],
    key_type: Annotated[
        KeyType, typer.Option("-t", "--type-key", help="The type of key.")
    ] = KeyType.STRING.value,
    skip: Annotated[
        int,
        typer.Option("-s", "--skip", help="First n packet to skip."),
    ] = 0,
):
    """Recover AES key of stage 1 using the RSA private key and the AES key from stage 0."""
    global aes_key
    bkey = convert_key(key, key_type)
    if bkey is None:
        raise typer.Exit(code=1)
    aes_key = bkey

    with open(private_key_file, "r") as f:
        try:
            rsa_private_key = RSA.import_key(f.read())
        except ValueError as e:
            print(f"[red][-] Error : {str(e)}[/red]")
            raise typer.Exit(code=1)
        logging.debug(f"[*] RSA key N : {rsa_private_key.n}")
        logging.debug(f"[*] RSA key P : {rsa_private_key.p}")
        logging.debug(f"[*] RSA key Q : {rsa_private_key.q}")
        logging.debug(f"[*] RSA key D : {rsa_private_key.d}")
        logging.debug(f"[*] RSA key E : {rsa_private_key.e}")

    with open(file_path, "r") as f:
        for _ in range(skip):
            next(f)
        first_line = f.readline().strip()

    data = extract_base64(first_line)
    if data is None:
        raise typer.Exit(code=1)

    encrypt_aes_key = decrypt_packet(b64decode(data.encode()))
    if encrypt_aes_key is None:
        print("[red][-] Failed to decrypt the packet.[/red]")
        raise typer.Exit(code=1)
    logging.debug(f"[*] Encrypted AES key : {encrypt_aes_key}")

    new_aes_key = rsa_decrypt(encrypt_aes_key, rsa_private_key)
    if new_aes_key is None:
        print(
            "[red][-] Failed to decrypt the new AES key with the RSA private key.[/red]"
        )
        raise typer.Exit(code=1)
    print("[+] New AES key : " + bytes.hex(new_aes_key))


@app.command("modulus")
def get_public_key_info_from_xml(
    file_path: Annotated[
        Path,
        typer.Option(
            "-i",
            "--input",
            help="Path to a file containing the first data packet of Covenant communication.",
            exists=True,
            file_okay=True,
            dir_okay=False,
            writable=False,
            readable=True,
            resolve_path=True,
        ),
    ],
    key: Annotated[
        str,
        typer.Option(
            "-k",
            "--key",
            help="The AES key used to decrypt the Covenant data packet. "
            "Can be string, hexadecimal or base64.",
        ),
    ],
    key_type: Annotated[
        KeyType, typer.Option("-t", "--type-key", help="The type of key.")
    ] = KeyType.STRING.value,
    skip: Annotated[
        int,
        typer.Option("-s", "--skip", help="First n packet to skip."),
    ] = 0,
):
    """Extract the modulus and the exponent of the public key us and exponent from Covenant stage 0 communication."""
    global aes_key
    bkey = convert_key(key, key_type)
    if bkey is None:
        raise typer.Exit(code=1)
    aes_key = bkey

    with open(file_path, "r") as f:
        for _ in range(skip):
            next(f)
        first_line = f.readline().strip()

    data_pattern = r"data=([^&]+)"
    match = search(data_pattern, first_line)
    if match:
        data = match.group(1)
        logging.debug(f"[*] Data field : {data}")
    else:
        print("[red][-] Data parameter not found.[/red]")
        raise typer.Exit(code=1)
    bpublic_key_xml = decrypt_packet(b64decode(data.encode()))
    if bpublic_key_xml is None:
        raise typer.Exit(code=1)
    public_key_xml = bpublic_key_xml.decode()
    logging.debug(f"[*] Public key XML : {public_key_xml}")

    pattern_m = r"<Modulus>(.*?)<\/Modulus>"
    pattern_e = r"<Exponent>(.*?)<\/Exponent>"
    match_m = search(pattern_m, public_key_xml)
    match_e = search(pattern_e, public_key_xml)

    if match_m:
        modulus = match_m.group(1)
        print("[+] Modulus:", bytes_to_long(b64decode(modulus.encode())))
    else:
        print(f"[yellow][-] No modulus found in[/yellow] {public_key_xml}")

    if match_e:
        exponent = match_e.group(1)
        print("[+] Exponent:", bytes_to_long(b64decode(exponent.encode())))
    else:
        print(f"[yellow][-] No exponent found in[/yellow] {public_key_xml}")


# https://github.com/tiangolo/typer/issues/203
@app.callback()
def callback(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Active debug output.")
):
    lvl = logging.INFO
    if verbose:
        lvl = logging.DEBUG
    logging.basicConfig(level=lvl, format="%(message)s")


if __name__ == "__main__":
    app()
