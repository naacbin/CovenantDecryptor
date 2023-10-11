from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.PublicKey import RSA
from minidump.minidumpfile import MinidumpFile
from pathlib import Path
from typing_extensions import Annotated
from typing import Optional, List
from rich import print
import typer
import logging


app = typer.Typer()


# https://github.com/tiangolo/typer/issues/203
def callback(verbose: bool):
    lvl = logging.INFO
    if verbose:
        lvl = logging.DEBUG
    logging.basicConfig(level=lvl, format="%(message)s")


def build_private_key(p: int, q: int, e: int = 65537) -> RSA.RsaKey:
    """Build an RSA private key.

    Args:
        p (int): The first prime number.
        q (int): The second prime number.
        e (int): The public exponent. Defaults to 65537.

    Returns:
        RSA.RsaKey: The RSA private key.
    """
    # Calculate phi(n), where n is the modulus
    phi_n = (p - 1) * (q - 1)
    # Calculate the modular multiplicative inverse of e mod phi(n) to get d
    d = pow(e, -1, phi_n)
    # Construct the RSA private key using the components
    return RSA.construct((p * q, e, d))


def create_private_key(private_key_file: Path, p: int, q: int, e: int = 65537):
    """Create an RSA private key on disk.

    Args:
        private_key_file (Path): Path to the private key file to save.
        p (int): The first prime number.
        q (int): The second prime number.
        e (int): The public exponent. Defaults to 65537.
    """
    rsa_private_key = build_private_key(p, q, e)
    logging.debug(f"[*] RSA key D : {rsa_private_key.d}")
    with open(private_key_file, "wb") as f:
        f.write(rsa_private_key.export_key())
    print(f"[green][+] Saved private key {private_key_file}[/green]")


def extract_prime_numbers(data: bytes, modulus: int) -> set:
    """Find prime numbers (p and q) inside binary data using modulus (n).
    The prime factors immediately follow the modulus in Microsoft RSA private key blob.
    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/5cf2e6b9-3195-4f85-bc18-05b50e6d4e11

    Args:
        data (bytes): The binary data to search for prime numbers in.
        modulus (bytes): The modulus value used to find prime factors.

    Returns:
        set: A set containing the prime numbers (p and q) found in the data.
    """
    cursor = 0
    bmodulus = long_to_bytes(modulus)
    size_modulus = len(bmodulus)
    size_of_prime = round(size_modulus / 2)
    p_q_pairs = set()
    while cursor < len(data):
        # Search for the next occurrence
        index = data.find(bmodulus, cursor)
        # If no more occurrences are found, break out of the loop
        if index == -1:
            break
        # Move the starting position to after the found occurrence
        cursor = index + size_modulus
        cursor_with_prime = cursor + size_of_prime

        prime_p = bytes_to_long(data[cursor:cursor_with_prime])
        prime_q = bytes_to_long(
            data[cursor_with_prime : cursor_with_prime + size_of_prime]
        )
        if prime_p * prime_q == modulus:
            p_q_pairs.add((prime_p, prime_q))
            logging.debug(f"[*] Found P : {prime_p}")
            logging.debug(f"[*] Found Q : {prime_q}")
        else:
            print(
                "[yellow][-] A pair of P and Q were located, but they do not match the modulus.[/yellow]"
            )
            logging.debug(f"[*] Found P : {prime_p}")
            logging.debug(f"[*] Found Q : {prime_q}")
    return p_q_pairs


def read_minidump(minidump: MinidumpFile, modulus: int) -> Optional[List]:
    """Retrieve a list of P and Q from a minidump file data.

    Args:
        minidump (MinidumpFile): Minidump file data to analyse.
        modulus (int): The modulus value used to find prime factors.

    Returns:
        List | None: A list of P and Q values. None if the memory segments could not be determined.
    """
    reader = minidump.get_reader().get_buffered_reader()
    if minidump.memory_segments_64:
        logging.debug(str(minidump.memory_segments_64))
        all_ms = minidump.memory_segments_64.memory_segments
    elif minidump.memory_segments:
        logging.debug(str(minidump.memory_segments))
        all_ms = minidump.memory_segments.memory_segments
    else:
        return None

    p_q_pairs = set()
    for ms in all_ms:
        reader.move(ms.start_virtual_address)
        data = reader.read(ms.size)
        if data:
            p_q_pairs.update(extract_prime_numbers(data, modulus))
    return list(p_q_pairs)


def main(
    memory_file: Annotated[
        Path,
        typer.Option(
            "-i",
            "--input",
            help="The path to the memory file.",
            exists=True,
            file_okay=True,
            dir_okay=False,
            writable=False,
            readable=True,
            resolve_path=True,
        ),
    ],
    private_key_dir: Annotated[
        Path,
        typer.Option(
            "-o",
            "--output",
            help="The directory to save the private RSA keys.",
            exists=True,
            file_okay=False,
            dir_okay=True,
            writable=True,
            readable=False,
            resolve_path=True,
        ),
    ],
    public_modulus: Annotated[
        Optional[int],
        typer.Option("-m", "--modulus", help="The modulus of the public key"),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Active debug output.", callback=callback),
    ] = False,
):
    """Extract Microsoft RSA private keys from a file."""
    try:
        minidump = MinidumpFile.parse(memory_file)
    except Exception as e:
        print(f"Minidump parsing error : {e}")
        raise typer.Exit(code=1)

    if not public_modulus:
        return 0

    p_q_pairs = read_minidump(minidump, public_modulus)
    if p_q_pairs is None:
        print("[red]Failed to parse memory_segments from minidump file.[/red]")
        raise typer.Exit(code=1)
    elif not p_q_pairs:
        print("[red]No private keys found.[/red]")
        raise typer.Exit(code=1)
    else:
        for i, (p, q) in enumerate(p_q_pairs, start=1):
            logging.debug(f"[+] Pair {i}")
            logging.debug(f"[+] P : {p}")
            logging.debug(f"[+] Q : {q}")
            private_key_file = Path(
                str(private_key_dir) + "/" + "privkey" + str(i) + ".pem"
            )
            create_private_key(private_key_file, p, q)


if __name__ == "__main__":
    typer.run(main)
