# ─── Constants from lib.rs ─────────────────────────────────────────────────────
#: Message length in bytes, for messages that we want to sign.
MESSAGE_LENGTH: int = 32

#: Tweak separators (just single‐byte markers) used throughout the tree/chain hashes.
TWEAK_SEPARATOR_FOR_MESSAGE_HASH: int = 0x02
TWEAK_SEPARATOR_FOR_TREE_HASH:    int = 0x01
TWEAK_SEPARATOR_FOR_CHAIN_HASH:   int = 0x00