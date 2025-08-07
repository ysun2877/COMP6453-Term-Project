# translated from src/symmetric/prf/shake_to_field.rs
# TODO: implement XOF-to-field mapping
class ShakeToFieldPRF():#(PRF):
    def eval(self, key: bytes, data: bytes) -> bytes:
        raise NotImplementedError("SHAKE-to-field PRF not implemented")