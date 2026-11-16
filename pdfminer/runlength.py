#
# RunLength decoder (Adobe version) implementation based on PDF Reference
# version 1.4 section 3.3.4.
#
#  * public domain *
#

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pdfminer.decodebudget import DecodeBudget


def rldecode(
    data: bytes,
    budget: "DecodeBudget | None" = None,
    layer: str = "RunLengthDecode",
) -> bytes:
    """RunLength decoder (Adobe version) implementation based on PDF Reference
    version 1.4 section 3.3.4:
        The RunLengthDecode filter decodes data that has been encoded in a
        simple byte-oriented format based on run length. The encoded data
        is a sequence of runs, where each run consists of a length byte
        followed by 1 to 128 bytes of data. If the length byte is in the
        range 0 to 127, the following length + 1 (1 to 128) bytes are
        copied literally during decompression. If length is in the range
        129 to 255, the following single byte is to be copied 257 - length
        (2 to 128) times during decompression. A length value of 128
        denotes EOD.
    """
    decoded_array: list[int] = []
    data_iter = iter(data)

    while True:
        length = next(data_iter, 128)
        if length == 128:
            break

        if 0 <= length < 128:
            run_length = length + 1
            if budget is not None:
                budget.charge(layer, run_length)
            decoded_array.extend(next(data_iter) for _ in range(run_length))

        if length > 128:
            run_length = 257 - length
            if budget is not None:
                budget.charge(layer, run_length)
            run = [next(data_iter)] * run_length
            decoded_array.extend(run)
    return bytes(decoded_array)
