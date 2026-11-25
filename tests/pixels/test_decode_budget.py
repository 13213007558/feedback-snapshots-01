# Copyright 2008-2024 pydicom authors. See LICENSE file for details.
"""Tests for the optional pixel data decode budget."""

import numpy as np
import pytest

from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.encaps import encapsulate
from pydicom.pixels import (
    DecodeBudget,
    DecodeBudgetExceeded,
    get_decoder,
    iter_pixels,
    pixel_array,
)
from pydicom.pixels.decoders.base import DecodeRunner, Decoder
from pydicom.uid import ExplicitVRLittleEndian, RLELossless


def make_native(
    nframes: int = 5, rows: int = 4, columns: int = 4
) -> tuple[Dataset, np.ndarray]:
    """Return a small synthetic native dataset and the expected frames."""
    ds = Dataset()
    ds.file_meta = FileMetaDataset()
    ds.file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
    ds.Rows = rows
    ds.Columns = columns
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.BitsAllocated = 8
    ds.BitsStored = 8
    ds.PixelRepresentation = 0
    ds.NumberOfFrames = nframes
    arr = np.arange(nframes * rows * columns, dtype="u1").reshape(
        nframes, rows, columns
    )
    ds.PixelData = arr.tobytes()

    return ds, arr


def make_encapsulated(nframes: int = 5, rows: int = 4, columns: int = 4) -> Dataset:
    """Return a small synthetic encapsulated dataset."""
    ds = Dataset()
    ds.file_meta = FileMetaDataset()
    ds.file_meta.TransferSyntaxUID = RLELossless
    ds.Rows = rows
    ds.Columns = columns
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.BitsAllocated = 8
    ds.BitsStored = 8
    ds.PixelRepresentation = 0
    ds.NumberOfFrames = nframes
    ds.PixelData = encapsulate([b"\x00\x01\x02\x03"] * nframes)

    return ds


class RecordingDecoder:
    """A local decoder that records each decoded frame and can fail on demand."""

    def __init__(self, fail_on: int | None = None) -> None:
        self.calls: list[int | None] = []
        self.fail_on = fail_on

    def __call__(self, src: bytes, runner: DecodeRunner) -> bytearray:
        self.calls.append(runner.index)
        if self.fail_on is not None and runner.index == self.fail_on:
            raise ValueError("Controlled decode failure")

        return bytearray(np.arange(16, dtype="u1").tobytes())


class TestDecodeBudgetValidation:
    """Tests for the DecodeBudget object itself."""

    def test_defaults(self):
        budget = DecodeBudget()
        assert budget.max_frames is None
        assert budget.max_bytes is None
        assert budget.frames_used == 0
        assert budget.bytes_used == 0
        assert budget.frames_remaining is None
        assert budget.bytes_remaining is None
        assert budget.exhausted is False
        assert bool(budget) is False

    @pytest.mark.parametrize("name", ["max_frames", "max_bytes"])
    def test_negative_raises(self, name):
        msg = f"'{name}' must be greater than or equal to 0"
        with pytest.raises(ValueError, match=msg):
            DecodeBudget(**{name: -1})

    def test_counters(self):
        budget = DecodeBudget(max_frames=2, max_bytes=32)
        budget.commit(frames=2, nbytes=32)
        assert budget.frames_remaining == 0
        assert budget.bytes_remaining == 0
        assert budget.exhausted is True

        budget.reset()
        assert budget.frames_used == 0
        assert budget.bytes_used == 0
        assert budget.exhausted is False

    def test_check_reports_both_limits(self):
        budget = DecodeBudget(max_frames=1, max_bytes=8)
        msg = (
            "Unable to continue decoding pixel data as the decode budget would be "
            r"exceeded for frames \(used 0, requested 2, maximum 1\) and bytes "
            r"\(used 0, requested 16, maximum 8\)"
        )
        with pytest.raises(DecodeBudgetExceeded, match=msg) as exc:
            budget.check(frames=2, nbytes=16, result_usable=True)

        assert exc.value.result_usable is True
        assert exc.value.frames_decoded == 0
        assert exc.value.bytes_allocated == 0


class TestNativeBudget:
    """Tests for budgets with natively encoded, synthetic frames."""

    def test_dataset_pixel_array_options(self):
        """A budget can also be set through Dataset.pixel_array_options()."""
        ds, arr = make_native()
        ds.pixel_array_options(budget=DecodeBudget(max_frames=4))
        with pytest.raises(DecodeBudgetExceeded) as exc:
            ds.pixel_array

        assert exc.value.result_usable is False
        # Clearing the option allows a normal decode
        ds.pixel_array_options()
        assert np.array_equal(ds.pixel_array, arr)

    def test_no_budget_small_sample(self):
        ds, arr = make_native()
        out = pixel_array(ds)
        assert np.array_equal(out, arr)

    def test_pixel_array_frame_budget(self):
        ds, arr = make_native()
        budget = DecodeBudget(max_frames=4)
        with pytest.raises(DecodeBudgetExceeded) as exc:
            pixel_array(ds, budget=budget)

        # A whole array is unusable if it's incomplete
        assert exc.value.result_usable is False
        # No work was committed, and nothing was delivered
        assert budget.frames_used == 0
        assert budget.bytes_used == 0

    def test_pixel_array_byte_budget(self):
        ds, arr = make_native()
        budget = DecodeBudget(max_bytes=arr.nbytes - 1)
        with pytest.raises(DecodeBudgetExceeded) as exc:
            pixel_array(ds, budget=budget)

        assert exc.value.result_usable is False
        assert exc.value.bytes_allocated == 0

        budget = DecodeBudget(max_bytes=arr.nbytes)
        out = pixel_array(ds, budget=budget)
        assert np.array_equal(out, arr)
        assert budget.frames_used == 5
        assert budget.bytes_used == arr.nbytes

    def test_zero_frame_budget(self):
        ds, arr = make_native()
        with pytest.raises(DecodeBudgetExceeded) as exc:
            list(iter_pixels(ds, budget=DecodeBudget(max_frames=0)))

        assert exc.value.result_usable is True
        assert exc.value.frames_decoded == 0
        assert exc.value.requested_frames == 1
        # Nothing is delivered but the call itself is valid
        assert exc.value.budget.frames_used == 0

    def test_iter_pixels_frame_budget(self):
        ds, arr = make_native()
        budget = DecodeBudget(max_frames=2)
        delivered = []
        frames = iter_pixels(ds, budget=budget)
        with pytest.raises(DecodeBudgetExceeded) as exc:
            for frame in frames:
                delivered += [frame]

        assert exc.value.result_usable is True
        assert len(delivered) == 2
        assert np.array_equal(delivered[0], arr[0])
        assert np.array_equal(delivered[1], arr[1])
        assert budget.frames_used == 2

    def test_iter_pixels_byte_budget(self):
        ds, arr = make_native()
        budget = DecodeBudget(max_bytes=arr[0].nbytes * 2)
        frames = iter_pixels(ds, budget=budget)
        delivered = [next(frames), next(frames)]
        with pytest.raises(DecodeBudgetExceeded) as exc:
            next(frames)

        assert exc.value.result_usable is True
        assert len(delivered) == 2
        assert budget.bytes_used == arr[0].nbytes * 2

    def test_index_budget(self):
        ds, arr = make_native()
        budget = DecodeBudget(max_frames=1)
        out = pixel_array(ds, index=2, budget=budget)
        assert np.array_equal(out, arr[2])
        assert budget.frames_used == 1

    def test_index_budget_zero_frames_raises(self):
        ds, arr = make_native()
        budget = DecodeBudget(max_frames=0)
        with pytest.raises(DecodeBudgetExceeded) as exc:
            pixel_array(ds, index=2, budget=budget)

        assert exc.value.result_usable is False


class TestEncapsulatedBudget:
    """Tests for budgets with synthetic encapsulated data."""

    def test_as_buffer_index_budget(self, monkeypatch):
        ds = make_encapsulated()
        decoder = get_decoder(RLELossless)
        recorder = RecordingDecoder()
        monkeypatch.setattr(decoder, "_available", {"rec": recorder})

        budget = DecodeBudget(max_frames=1, max_bytes=16)
        buffer, _ = decoder.as_buffer(ds, index=2, budget=budget, decoding_plugin="rec")
        assert recorder.calls == [2]
        assert budget.frames_used == 1
        assert budget.bytes_used == 16

    def test_second_attempt_after_stop_is_clean(self, monkeypatch):
        ds = make_encapsulated(nframes=3)
        decoder = get_decoder(RLELossless)
        recorder = RecordingDecoder()
        monkeypatch.setattr(decoder, "_available", {"rec": recorder})

        # Stop part-way through the whole-array decode
        with pytest.raises(DecodeBudgetExceeded) as exc:
            pixel_array(ds, budget=DecodeBudget(max_frames=2), decoding_plugin="rec")

        assert recorder.calls == [0, 1]
        assert exc.value.frames_decoded == 2
        # No output array was allocated, only two frames were expanded
        assert exc.value.bytes_allocated == 32

        # A later legal decode with a fresh budget starts from the beginning
        recorder.calls.clear()
        budget = DecodeBudget(max_frames=3, max_bytes=48)
        arr = pixel_array(ds, budget=budget, decoding_plugin="rec")
        assert recorder.calls == [0, 1, 2]
        assert arr.shape == (3, 4, 4)
        assert budget.frames_used == 3

    def test_pixel_array_records_expanded_frames(self, monkeypatch):
        ds = make_encapsulated()
        decoder = get_decoder(RLELossless)
        recorder = RecordingDecoder()
        monkeypatch.setattr(decoder, "_available", {"rec": recorder})

        budget = DecodeBudget(max_frames=2)
        with pytest.raises(DecodeBudgetExceeded) as exc:
            pixel_array(ds, budget=budget, decoding_plugin="rec")

        assert exc.value.result_usable is False
        # Only the frames that could fit were expanded
        assert recorder.calls == [0, 1]
        assert budget.frames_used == 2
        assert exc.value.frames_decoded == 2

    def test_iter_pixels_records_expanded_frames(self, monkeypatch):
        ds = make_encapsulated()
        decoder = get_decoder(RLELossless)
        recorder = RecordingDecoder()
        monkeypatch.setattr(decoder, "_available", {"rec": recorder})

        budget = DecodeBudget(max_frames=2)
        frames = iter_pixels(ds, budget=budget, decoding_plugin="rec")
        delivered = [next(frames), next(frames)]
        with pytest.raises(DecodeBudgetExceeded) as exc:
            next(frames)

        assert exc.value.result_usable is True
        assert recorder.calls == [0, 1]
        assert len(delivered) == 2

    def test_fallback_decoder_used(self, monkeypatch):
        """A failing first decoder is followed by the fallback decoder."""
        ds = make_encapsulated(nframes=3)
        decoder = get_decoder(RLELossless)
        primary = RecordingDecoder(fail_on=1)
        fallback = RecordingDecoder()
        monkeypatch.setattr(
            decoder, "_available", {"primary": primary, "fallback": fallback}
        )

        budget = DecodeBudget(max_frames=3, max_bytes=3 * 16)
        arr = pixel_array(ds, budget=budget, decoding_plugin="")
        assert arr.shape == (3, 4, 4)
        # The first frame used the primary decoder, frame 1 failed there and
        #   was decoded by the fallback, frame 2 continued with the fallback
        assert primary.calls == [0, 1, 1]
        assert fallback.calls == [1, 2]
        assert budget.frames_used == 3
        assert budget.bytes_used == 48

    def test_stop_uses_no_further_resources_then_legal_decode(self, monkeypatch):
        ds = make_encapsulated()
        decoder = get_decoder(RLELossless)
        recorder = RecordingDecoder()
        monkeypatch.setattr(decoder, "_available", {"rec": recorder})

        budget = DecodeBudget(max_frames=2)
        with pytest.raises(DecodeBudgetExceeded):
            pixel_array(ds, budget=budget, decoding_plugin="rec")

        # No further frames were expanded after the stop
        assert recorder.calls == [0, 1]

        # A fresh legal decode can follow using the same decoder
        recorder.calls.clear()
        budget = DecodeBudget(max_frames=5, max_bytes=5 * 16)
        arr = pixel_array(ds, budget=budget, decoding_plugin="rec")
        assert arr.shape == (5, 4, 4)
        assert recorder.calls == [0, 1, 2, 3, 4]
        assert budget.frames_used == 5

    def test_byte_budget_stops_without_allocating_array(self, monkeypatch):
        ds = make_encapsulated()
        decoder = get_decoder(RLELossless)
        recorder = RecordingDecoder()
        monkeypatch.setattr(decoder, "_available", {"rec": recorder})

        budget = DecodeBudget(max_bytes=16 * 2)
        with pytest.raises(DecodeBudgetExceeded) as exc:
            pixel_array(ds, budget=budget, decoding_plugin="rec")

        # The budget stops before the second frame can be expanded
        assert exc.value.result_usable is False
        assert recorder.calls == [0, 1]
        assert exc.value.frames_decoded == 2
        assert budget.bytes_used == 32

    def test_budget_does_not_mask_decode_error(self, monkeypatch):
        ds = make_encapsulated()
        decoder = get_decoder(RLELossless)

        def fail(src, runner):
            raise ValueError("Known bad data")

        monkeypatch.setattr(decoder, "_available", {"bad": fail})
        budget = DecodeBudget(max_frames=5, max_bytes=5 * 16)
        msg = "Unable to decode as exceptions were raised by all available plugins"
        with pytest.raises(RuntimeError, match=msg):
            pixel_array(ds, budget=budget, decoding_plugin="bad")

        # The failed attempt didn't consume budget
        assert budget.frames_used == 0
        assert budget.bytes_used == 0

    def test_buffer_budget(self, monkeypatch):
        ds = make_encapsulated(nframes=3)
        decoder = get_decoder(RLELossless)
        recorder = RecordingDecoder()
        monkeypatch.setattr(decoder, "_available", {"rec": recorder})

        budget = DecodeBudget(max_bytes=16)
        with pytest.raises(DecodeBudgetExceeded) as exc:
            decoder.as_buffer(ds, budget=budget, decoding_plugin="rec")

        # Only the first frame could be expanded, and because the returned
        #   buffer would be incomplete it isn't usable
        assert exc.value.result_usable is False
        assert recorder.calls == [0]
        assert budget.frames_used == 1
        assert budget.bytes_used == 16


class TestDecoderArrayBudget:
    """Tests for budgets with Decoder.as_array()/iter_array()."""

    def test_as_array_uses_decoder_budget(self):
        decoder = Decoder(RLELossless)
        ds = make_encapsulated()
        recorder = RecordingDecoder()
        decoder._available = {"rec": recorder}

        budget = DecodeBudget(max_frames=2)
        with pytest.raises(DecodeBudgetExceeded) as exc:
            decoder.as_array(ds, budget=budget, decoding_plugin="rec")

        assert exc.value.result_usable is False
        assert recorder.calls == [0, 1]

    def test_iter_array_uses_decoder_budget(self):
        decoder = Decoder(RLELossless)
        ds = make_encapsulated()
        recorder = RecordingDecoder()
        decoder._available = {"rec": recorder}

        budget = DecodeBudget(max_frames=2)
        out = []
        with pytest.raises(DecodeBudgetExceeded) as exc:
            for arr, _ in decoder.iter_array(ds, budget=budget, decoding_plugin="rec"):
                out.append(arr)

        assert exc.value.result_usable is True
        assert len(out) == 2
