from __future__ import annotations

import getpass

from phantom_net.auth import hash_password


if __name__ == "__main__":
    password = getpass.getpass("Admin password: ")
    print(hash_password(password))
