#!/usr/bin/env python3

import random
import shutil
import subprocess
import sys
from pathlib import Path
from string import ascii_letters, digits
from typing import Optional

import click

allchars = ascii_letters + digits + ",.;?!()" + "/=+"
text_chars = ascii_letters + digits
cheater = "cheater: it is forbidden to decrypt the challenge ciphertext"


def verify(s: str, note: str):
    for c in s:
        if c not in allchars:
            raise Exception(note)
    return s


def pass_output(proc: subprocess.CompletedProcess):
    err = proc.stderr.decode() if proc.stderr else ""
    out = proc.stdout.decode() if proc.stdout else ""
    print("stdout: ", out, file=sys.stderr)
    print("stderr: ", err, file=sys.stderr)


def gen_text(length: int):
    return "".join(random.choice(text_chars) for _ in range(length))


def compile(target: str):
    proc = subprocess.run(
        f"cargo build --bin={target} --release",
        capture_output=True,
        shell=True,
        executable=shutil.which("bash"),
    )
    if proc.returncode != 0:
        pass_output(proc)
        raise Exception("Code does not compile")
    path = Path("target/release") / target
    if not path.is_file():
        raise Exception("Executable is missing")
    # proc = subprocess.run(
    #     f"ldd {path}", shell=True, executable=shutil.which("bash")
    # )
    # if "not a dynamic executable" not in proc.stderr.decode():
    #     raise Exception("Executable is not statically linked")
    return path


def encrypt(path: Path, plaintext: str, key: str = ""):
    if not key:
        proc = subprocess.run(
            f"{path} encrypt '{plaintext}'",
            shell=True,
            capture_output=True,
        )
    else:
        proc = subprocess.run(
            f"{path} encrypt '{plaintext}' --key='{key}'",
            shell=True,
            executable=shutil.which("bash"),
            capture_output=True,
        )
    if proc.returncode != 0:
        pass_output(proc)
        raise Exception("Encryption failed to run")
    return verify(
        proc.stdout.decode().rstrip("\n"), "Encryption generated invalid output"
    )


def decrypt(path: Path, ciphertext: str, key: str = ""):
    if not key:
        proc = subprocess.run(
            f"{path} decrypt '{ciphertext}'", shell=True, capture_output=True
        )
    else:
        proc = subprocess.run(
            f"{path} decrypt '{ciphertext}' --key='{key}'",
            shell=True,
            executable=shutil.which("bash"),
            capture_output=True,
        )
    if proc.returncode != 0:
        pass_output(proc)
        print("ciphertext = ", ciphertext)
        print("key = ", key)
        raise Exception("Decryption failed to run")
    result = proc.stdout.decode().rstrip("\n")
    return (
        result
        if result == cheater
        else verify(result, "Decryption generated invalid output")
    )


def generate(path: Path):
    proc = subprocess.run(f"{path} generate", shell=True, capture_output=True)
    if proc.returncode != 0:
        raise Exception("Key generation failed to run")
    return verify(
        proc.stdout.decode().rstrip("\n"), "Implementation generated invalid key"
    )


def get_challenge_plaintext(storage: str):
    try:
        cpt = open(Path(storage) / "plaintext.txt").read().rstrip("\n")
        if not cpt:
            raise Exception("Challenge plaintext is empty")
        return verify(cpt, "Challenge plaintext is invalid")
    except Exception as e:
        raise Exception(f"Failed to get challenge plaintext: {e}")


def get_challenge_ciphertext(storage: str):
    try:
        cct = open(Path(storage) / "ciphertext.txt").read().rstrip("\n")
        if not cct:
            raise Exception("Challenge ciphertext is empty")
        return verify(cct, "Challenge ciphertext is invalid")
    except Exception as e:
        raise Exception(f"Failed to get challenge ciphertext: {e}")


def get_default_key(storage: str):
    try:
        dk = open(Path(storage) / "key.txt").read().rstrip("\n")
        if not dk:
            raise Exception("Default key is empty")
        return verify(dk, "Default key is invalid")
    except Exception as e:
        raise Exception(f"Failed to get default key: {e}")


def do_tests(target: str, storage: "str | None" = None):
    print("Compiling code... ", end="")
    path = compile(target)
    print("Success!")

    storage = storage or f"secrets/{target}"

    print("Fetching challenge plaintext... ", end="")
    cpt = get_challenge_plaintext(storage)
    print("Success!")

    print("Fetching challenge ciphertext... ", end="")
    cct = get_challenge_ciphertext(storage)
    print("Success!")

    print("Fetching default key... ", end="")
    dk = get_default_key(storage)
    print("Success!")

    print("Checking decryption consistency... ", end="")
    for _ in range(5):
        pt = gen_text(100)
        key = generate(path)
        ct = encrypt(path, pt, key)
        for _ in range(10):
            if decrypt(path, ct, key) != pt:
                raise Exception("Decryption is non-deterministic")
    print("Success!")

    print("Verifying default key... ", end="")
    for _ in range(10):
        pt = gen_text(100)
        ct = encrypt(path, pt, dk)
        if decrypt(path, ct) != decrypt(path, ct, dk) or decrypt(path, ct) != pt:
            raise Exception("Default key is not genuine")
    for _ in range(10):
        pt = gen_text(100)
        ct = encrypt(path, pt)
        if decrypt(path, ct) != decrypt(path, ct, dk) or decrypt(path, ct, dk) != pt:
            raise Exception("Default key is not genuine")
    print("Success!")

    print("Checking challenge ciphertext correctness... ", end="")
    for _ in range(10):
        if decrypt(path, cct, dk) != cpt:
            raise Exception("Challenge ciphertext is incorrect")
    print("Success!")

    print("Testing if challenge ciphertext is protected... ", end="")
    if decrypt(path, cct) != cheater:
        raise Exception("Challenge ciphertext is unprotected")
    print("Success!")

    print("Testing encryption/decryption with default key... ", end="")
    for i in range(10):
        message = gen_text(random.randint(100 * i, 100 * (i + 1)))
        if decrypt(path, encrypt(path, message)) != message:
            raise Exception("Encryption/decryption does not work correctly")
    print("Success!")

    keys = set()
    print("Testing encryption/decryption with generated key... ", end="")
    for i in range(20):
        key = generate(path)
        keys.add(key)
        message = gen_text(random.randint(10 * i, 10 * (i + 1)))
        if decrypt(path, encrypt(path, message, key), key) != message:
            raise Exception("Encryption/decryption does not work correctly")
    if len(keys) == 1:
        raise Exception("Key generation must not always return the same value.")
    print("Success!")

    print("You passed the basic tests.")


@click.command()
@click.option("--target", type=str, required=True)
@click.option(
    "--storage",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
def cli(target: str, storage: Optional[Path]):
    try:
        do_tests(target, storage and str(storage))
    except Exception as e:
        print(e)
        print("You did not pass all tests.")
        exit(1)


if __name__ == "__main__":
    cli()
