# Message length in bytes, for messages that we want to sign.
MESSAGE_LENGTH = 32

# Tweak separators for different hash domains
TWEAK_SEPARATOR_FOR_MESSAGE_HASH = 0x02
TWEAK_SEPARATOR_FOR_TREE_HASH    = 0x01
TWEAK_SEPARATOR_FOR_CHAIN_HASH   = 0x00