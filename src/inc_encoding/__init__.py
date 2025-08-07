# translated from src/inc_encoding.rs
# expose the two encoding variants
from .basic_winternitz import BasicWinternitzEncoding, EncodingError
from .target_sum      import TargetSumWinternitzEncoding