"""Tiny password-auth SSH helper (paramiko) used for the build host and the ONT.

Usage:
    python tools/remote.py <host> [port] <command...>        # run a command
    python tools/remote.py <host> [port] --put <local> <remote> [mode]

Credentials default to the shared build-host account (root / e3eb773F),
which the ONT container also uses.

**Remote paths must be passed WITHOUT a leading slash** ("tmp/olz/x", not
"/tmp/olz/x"). This file runs under Git Bash on Windows, and MSYS rewrites
any argv that looks like a POSIX path ("/tmp/olz/x" ->
"C:/Users/.../Temp/1/olz/x") *before* Python sees it — the sftp-server then
gets a Windows path and answers ENOENT. A bare "tmp/olz/x" is left alone and
`abs_remote()` restores the slash locally. Do NOT set MSYS_NO_PATHCONV=1:
it also disables conversion of the local script path.

SFTP works fine on the ONT: dropbear spawns /usr/libexec/sftp-server (its
compile-time default path) and 5/5 trial puts of 64KB completed in ~0.3s
with matching md5. The base64 fallback below is only for hosts that truly
lack an sftp-server. One quirk worth knowing: on this device an SFTP OPEN
with a *nonexistent parent directory* kills the whole SSH session
(EOFError) instead of returning a clean SFTP error, so never probe paths.
"""
import re
import sys

import paramiko

USER = "root"
PWD = "e3eb773F"
DEFAULT_PORT = 22


def connect(host, port):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, port=port, username=USER, password=PWD, timeout=20,
              look_for_keys=False, allow_agent=False)
    return c


def sh(c, cmd):
    _, out, err = c.exec_command(cmd)
    o = out.read().decode(errors="replace")
    e = err.read().decode(errors="replace")
    return o, e, out.channel.recv_exit_status()


def abs_remote(p):
    """Restore the leading slash stripped to survive MSYS argv mangling.

    Windows-style paths (starting with a drive letter) are returned as-is;
    "tmp/olz/x" becomes "/tmp/olz/x". See the module docstring.
    """
    if p and not p.startswith("/") and not re.match(r"^[A-Za-z]:", p):
        return "/" + p
    return p


def put(c, local, remote, mode=0o755, chunk=32 * 1024):
    """Upload without handing the remote path to a shell (MSYS would mangle it).

    Uses SFTP (present on the ONT — see module docstring); falls back to
    chunked `base64 -d >>` only when the server has no sftp subsystem. The
    fallback chunk is 32KB: a 64KB chunk base64-encodes to an ~87KB command
    line, which the ONT's dropbear answers by killing the transport.
    """
    remote = abs_remote(remote)
    try:
        sftp = c.open_sftp()
        sftp.put(local, remote)
        sftp.chmod(remote, mode)
        sftp.close()
        return "sftp"
    except Exception:
        sh(c, f"rm -f {remote}")
        with open(local, "rb") as f:
            n = 0
            while True:
                buf = f.read(chunk)
                if not buf:
                    break
                import base64
                b = base64.b64encode(buf).decode()
                # `printf %s | base64 -d >>` : busybox base64 supports -d
                sh(c, f"printf %s '{b}' | base64 -d >> {remote}")
                n += 1
        sh(c, f"chmod {oct(mode)[2:]} {remote}")
        return f"chunked x{n}"


def main():
    argv = sys.argv[1:]
    if not argv:
        print(__doc__)
        return 1
    host = argv[0]
    rest = argv[1:]
    port = DEFAULT_PORT
    if rest and rest[0].isdigit():
        port = int(rest[0])
        rest = rest[1:]
    c = connect(host, port)
    try:
        if rest and rest[0] == "--put":
            local, remote = rest[1], rest[2]
            mode = int(rest[3], 8) if len(rest) > 3 else 0o755
            print("upload via", put(c, local, remote, mode), flush=True)
        else:
            cmd = " ".join(rest)
            o, e, rc = sh(c, cmd)
            if o.strip():
                print(o.rstrip())
            if e.strip():
                print(e.rstrip(), file=sys.stderr)
            return rc
    finally:
        c.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
