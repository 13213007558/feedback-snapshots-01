import datetime
import decimal
import glob
import numbers
import os
import shutil
import string
from functools import partial
from stat import ST_DEV, ST_INO

from . import _string_parsers as string_parsers
from ._ctime_functions import get_ctime, set_ctime
from ._datetime import aware_now

# Suffix of the sidecar file marking a log as retained for an incident
# investigation. Its body holds an ISO 8601 UTC expiry timestamp.
HOLD_SUFFIX = ".hold"
# Suffix of a compression output that was not finalized, so a later rotation
# can tell half-finished archives apart from handed-off ones.
PARTIAL_SUFFIX = ".part"


def generate_rename_path(root, ext, creation_time):
    creation_datetime = datetime.datetime.fromtimestamp(creation_time)
    date = FileDateFormatter(creation_datetime)

    renamed_path = "{}.{}{}".format(root, date, ext)
    counter = 1

    while os.path.exists(renamed_path):
        counter += 1
        renamed_path = "{}.{}.{}{}".format(root, date, counter, ext)

    return renamed_path


def rename_file(path_in, path_out):
    try:
        os.rename(path_in, path_out)
    except OSError as error:
        raise OSError(
            "Could not rename log file {!r} to {!r}.\n"
            "Another handler or process may be using the same file and caused a "
            "conflict.\n"
            "Make sure no two active handlers were added with the same filename pattern (the "
            "'{{time}}' field is not an effective differentiator): rotation, retention and "
            "compression procedures may otherwise rename or delete each other's files.\n"
            "A common cause is logger configuration being inadvertently repeated in spawned child "
            "processes or Gunicorn workers.\n".format(path_in, path_out)
        ) from error


def remove_file(path):
    try:
        os.remove(path)
    except OSError as error:
        raise OSError(
            "Could not delete log file {!r}.\n"
            "Another handler or process may be using the same file and caused a "
            "conflict.\n"
            "Make sure no two active handlers were added with the same filename pattern (the "
            "'{{time}}' field is not an effective differentiator): rotation, retention and "
            "compression procedures may otherwise rename or delete each other's files.\n"
            "A common cause is logger configuration being inadvertently repeated in spawned child "
            "processes or Gunicorn workers.\n".format(path)
        ) from error


def hold_path(path):
    return path + HOLD_SUFFIX


def write_hold(path, until):
    marker = hold_path(path)
    with open(marker, "w", encoding="ascii") as file:
        file.write(until.astimezone(datetime.timezone.utc).isoformat())


def hold_is_active(path, now=None):
    marker = hold_path(path)
    if not os.path.exists(marker):
        return False
    try:
        with open(marker, "r", encoding="ascii") as file:
            until = datetime.datetime.fromisoformat(file.read().strip())
    except (OSError, ValueError):
        # A malformed marker is treated as an active hold rather than dropping
        # evidence that an investigation may still depend on.
        return True
    if now is None:
        now = aware_now()
    if until.tzinfo is None:
        until = until.replace(tzinfo=datetime.timezone.utc)
    if now < until:
        return True
    remove_file(marker)
    return False


class FileDateFormatter:
    def __init__(self, datetime=None):
        self.datetime = datetime or aware_now()

    def __format__(self, spec):
        if not spec:
            spec = "%Y-%m-%d_%H-%M-%S_%f"
        return self.datetime.__format__(spec)


class Compression:
    @staticmethod
    def add_compress(path_in, path_out, opener, **kwargs):
        with opener(path_out, **kwargs) as f_comp:
            f_comp.add(path_in, os.path.basename(path_in))

    @staticmethod
    def write_compress(path_in, path_out, opener, **kwargs):
        with opener(path_out, **kwargs) as f_comp:
            f_comp.write(path_in, os.path.basename(path_in))

    @staticmethod
    def copy_compress(path_in, path_out, opener, **kwargs):
        with open(path_in, "rb") as f_in:
            with opener(path_out, **kwargs) as f_out:
                shutil.copyfileobj(f_in, f_out)

    @staticmethod
    def compression(path_in, ext, compress_function):
        path_out = "{}{}".format(path_in, ext)

        if os.path.exists(path_out):
            creation_time = get_ctime(path_out)
            root, ext_before = os.path.splitext(path_in)
            renamed_path = generate_rename_path(root, ext_before + ext, creation_time)
            rename_file(path_out, renamed_path)

        path_tmp = path_out + PARTIAL_SUFFIX
        try:
            compress_function(path_in, path_tmp)
            # Carry the creation time over the final rename so downstream code
            # (and ctime-aware tests) still finds the archive by its final name.
            try:
                creation_time = get_ctime(path_tmp)
            except OSError:
                creation_time = None
            os.replace(path_tmp, path_out)
            if creation_time is not None:
                set_ctime(path_out, creation_time)
        except Exception:
            # The source file is intentionally left untouched so it stays
            # recoverable; any half-finished output is removed because it can be
            # mistaken for a handed-off archive at the next rotation.
            if os.path.exists(path_tmp):
                remove_file(path_tmp)
            raise

        # The retention declaration follows the evidence into the archive.
        marker_in = hold_path(path_in)
        if os.path.exists(marker_in):
            rename_file(marker_in, hold_path(path_out))

        remove_file(path_in)


class Retention:
    @staticmethod
    def retention_count(logs, number):
        def key_log(log):
            return (-os.stat(log).st_mtime, log)

        for log in sorted(logs, key=key_log)[number:]:
            remove_file(log)

    @staticmethod
    def retention_age(logs, seconds):
        t = datetime.datetime.now().timestamp()
        for log in logs:
            if os.stat(log).st_mtime <= t - seconds:
                remove_file(log)


class Rotation:
    @staticmethod
    def forward_day(t):
        return t + datetime.timedelta(days=1)

    @staticmethod
    def forward_weekday(t, weekday):
        days = (weekday - t.weekday()) % 7 or 7
        return t + datetime.timedelta(days=days)

    @staticmethod
    def forward_interval(t, interval):
        return t + interval

    @staticmethod
    def rotation_size(message, file, size_limit):
        file.seek(0, 2)
        return file.tell() + len(message) > size_limit

    class RotationTime:
        def __init__(self, step_forward, time_target=None, day_target=None):
            self._step_forward = step_forward
            self._time_target = time_target
            self._day_target = day_target
            self._limit = None

        def __call__(self, message, file):
            record_time = message.record["time"]

            if self._limit is None:
                filepath = os.path.realpath(file.name)
                creation_time = get_ctime(filepath)
                set_ctime(filepath, creation_time)
                start_time = datetime.datetime.fromtimestamp(
                    creation_time, tz=datetime.timezone.utc
                )

                if self._time_target is None:
                    limit = start_time.astimezone(record_time.tzinfo).replace(tzinfo=None)
                    limit = self._step_forward(limit)
                else:
                    tzinfo = (
                        record_time.tzinfo
                        if self._time_target.tzinfo is None
                        else self._time_target.tzinfo
                    )
                    limit = start_time.astimezone(tzinfo).replace(
                        hour=self._time_target.hour,
                        minute=self._time_target.minute,
                        second=self._time_target.second,
                        microsecond=self._time_target.microsecond,
                    )

                    if self._day_target is not None and limit.weekday() != self._day_target:
                        limit = Rotation.forward_weekday(limit, self._day_target)

                    if limit <= start_time:
                        limit = self._step_forward(limit)

                    if self._time_target.tzinfo is None:
                        limit = limit.replace(tzinfo=None)

                self._limit = limit

            if self._limit.tzinfo is None:
                record_time = record_time.replace(tzinfo=None)

            if record_time >= self._limit:
                while self._limit <= record_time:
                    self._limit = self._step_forward(self._limit)
                return True
            return False

    class RotationGroup:
        def __init__(self, rotations) -> None:
            self._rotations = rotations

        def __call__(self, message, file) -> bool:
            # Don't early exit: all conditions must be evaluated as they have desired side-effects.
            should_rotate = False
            for rotation in self._rotations:
                if rotation(message, file):
                    should_rotate = True
            return should_rotate


class FileSink:
    def __init__(
        self,
        path,
        *,
        rotation=None,
        retention=None,
        compression=None,
        delay=False,
        watch=False,
        mode="a",
        buffering=1,
        encoding="utf8",
        **kwargs
    ):
        self.encoding = encoding

        self._kwargs = {**kwargs, "mode": mode, "buffering": buffering, "encoding": self.encoding}
        self._path = str(path)

        self._glob_patterns = self._make_glob_patterns(self._path)
        self._rotation_function = self._make_rotation_function(rotation)
        self._retention_function = self._make_retention_function(retention)
        self._compression_function = self._make_compression_function(compression)
        self._compression_ext = self._compression_extension(compression)

        self._file = None
        self._file_path = None

        self._watch = watch
        self._file_dev = -1
        self._file_ino = -1

        if not delay:
            path = self._create_path()
            self._create_dirs(path)
            self._create_file(path)

    def write(self, message):
        if self._file is None:
            path = self._create_path()
            self._create_dirs(path)
            self._create_file(path)

        if self._watch:
            self._reopen_if_needed()

        if self._rotation_function is not None and self._rotation_function(message, self._file):
            self._terminate_file(is_rotating=True)

        self._file.write(message)

    def stop(self):
        if self._watch:
            self._reopen_if_needed()

        self._terminate_file(is_rotating=False)

    def tasks_to_complete(self):
        return []

    def _create_path(self):
        path = self._path.format_map({"time": FileDateFormatter()})
        return os.path.abspath(path)

    def _create_dirs(self, path):
        dirname = os.path.dirname(path)
        os.makedirs(dirname, exist_ok=True)

    def _create_file(self, path):
        self._file = open(path, **self._kwargs)
        self._file_path = path

        if self._watch:
            fileno = self._file.fileno()
            result = os.fstat(fileno)
            self._file_dev = result[ST_DEV]
            self._file_ino = result[ST_INO]

    def _close_file(self):
        self._file.flush()
        self._file.close()

        self._file = None
        self._file_path = None
        self._file_dev = -1
        self._file_ino = -1

    def _reopen_if_needed(self):
        # Implemented based on standard library:
        # https://github.com/python/cpython/blob/cb589d1b/Lib/logging/handlers.py#L486
        if not self._file:
            return

        filepath = self._file_path

        try:
            result = os.stat(filepath)
        except FileNotFoundError:
            result = None

        if not result or result[ST_DEV] != self._file_dev or result[ST_INO] != self._file_ino:
            self._close_file()
            self._create_dirs(filepath)
            self._create_file(filepath)

    def _terminate_file(self, *, is_rotating=False):
        old_path = self._file_path

        if self._file is not None:
            self._close_file()

        if is_rotating:
            new_path = self._create_path()
            self._create_dirs(new_path)

            if new_path == old_path:
                creation_time = get_ctime(old_path)
                root, ext = os.path.splitext(old_path)
                renamed_path = generate_rename_path(root, ext, creation_time)
                rename_file(old_path, renamed_path)
                old_path = renamed_path
        else:
            new_path = None

        if is_rotating or self._rotation_function is None:
            # Finish archives interrupted by an earlier failure before handling
            # the file just rotated, so pending raw logs and finalized archives
            # are never mixed inside the retention candidates. Recovery only
            # runs at rotation: on stop the current raw log is compressed once
            # and left untouched otherwise.
            if is_rotating:
                self._recover_pending_archives(skip=old_path)

            if self._compression_function is not None and old_path is not None:
                self._compression_function(old_path)

            if self._retention_function is not None:
                self._apply_retention(active_path=new_path)

        if is_rotating:
            self._create_file(new_path)
            set_ctime(new_path, datetime.datetime.now().timestamp())

    def _managed_files(self):
        return {
            file
            for pattern in self._glob_patterns
            for file in glob.glob(pattern)
            if os.path.isfile(file)
        }

    def _is_pending_raw(self, path, active_path):
        if self._compression_ext is None:
            return False
        if path == active_path:
            return False
        return not path.endswith(self._compression_ext)

    def _recover_pending_archives(self, *, skip):
        if self._compression_function is None:
            return

        for path in self._managed_files():
            if path.endswith(PARTIAL_SUFFIX):
                remove_file(path)

        now = aware_now()
        for path in sorted(self._managed_files()):
            if path.endswith(HOLD_SUFFIX) or path.endswith(PARTIAL_SUFFIX):
                continue
            if path == skip or not self._is_pending_raw(path, skip):
                continue
            # Evidence under an active retention declaration is not reworked:
            # its raw form stays untouched until the hold expires. Files handed
            # off by the current rotation are compressed afterwards regardless.
            if hold_is_active(path, now):
                continue
            self._compression_function(path)

    def _apply_retention(self, *, active_path):
        now = aware_now()
        managed = self._managed_files()

        # Expired markers whose target disappeared are pruned; active markers
        # without a target are kept until they expire.
        for path in managed:
            if path.endswith(HOLD_SUFFIX):
                target = path[: -len(HOLD_SUFFIX)]
                if not os.path.exists(target):
                    hold_is_active(target, now)

        candidates = []
        held = []
        pending = []

        for path in sorted(managed):
            if path.endswith(HOLD_SUFFIX) or path.endswith(PARTIAL_SUFFIX):
                continue
            if hold_is_active(path, now):
                held.append(path)
            elif self._is_pending_raw(path, active_path):
                pending.append(path)
            else:
                candidates.append(path)

        self._retention_function(candidates)

        return {"candidates": candidates, "held": held, "pending": pending}

    @staticmethod
    def _make_glob_patterns(path):
        formatter = string.Formatter()
        tokens = formatter.parse(path)
        escaped = "".join(glob.escape(text) + "*" * (name is not None) for text, name, *_ in tokens)

        root, ext = os.path.splitext(escaped)

        if not ext:
            return [escaped, escaped + ".*"]

        return [escaped, escaped + ".*", root + ".*" + ext, root + ".*" + ext + ".*"]

    @staticmethod
    def _compression_extension(compression):
        if compression is None or callable(compression):
            return None
        if isinstance(compression, str):
            return "." + compression.strip().lstrip(".")
        return None

    @staticmethod
    def _make_rotation_function(rotation):
        if rotation is None:
            return None
        if isinstance(rotation, (list, tuple, set)):
            if len(rotation) == 0:
                raise ValueError("Must provide at least one rotation condition")
            return Rotation.RotationGroup(
                [FileSink._make_rotation_function(rot) for rot in rotation]
            )
        if isinstance(rotation, str):
            size = string_parsers.parse_size(rotation)
            if size is not None:
                return FileSink._make_rotation_function(size)
            interval = string_parsers.parse_duration(rotation)
            if interval is not None:
                return FileSink._make_rotation_function(interval)
            frequency = string_parsers.parse_frequency(rotation)
            if frequency is not None:
                return Rotation.RotationTime(frequency)
            daytime = string_parsers.parse_daytime(rotation)
            if daytime is not None:
                day, time = daytime
                if day is None:
                    return FileSink._make_rotation_function(time)
                if time is None:
                    time = datetime.time(0, 0, 0)
                step_forward = partial(Rotation.forward_weekday, weekday=day)
                return Rotation.RotationTime(step_forward, time, day)
            raise ValueError("Cannot parse rotation from: '%s'" % rotation)
        if isinstance(rotation, bool):
            raise TypeError(
                "Invalid rotation, it should be a size, a time, a timedelta, or a callable, "
                "not a bool (True would rotate at 1 byte)"
            )
        if isinstance(rotation, (numbers.Real, decimal.Decimal)):
            return partial(Rotation.rotation_size, size_limit=rotation)
        if isinstance(rotation, datetime.time):
            return Rotation.RotationTime(Rotation.forward_day, rotation)
        if isinstance(rotation, datetime.timedelta):
            step_forward = partial(Rotation.forward_interval, interval=rotation)
            return Rotation.RotationTime(step_forward)
        if callable(rotation):
            return rotation
        raise TypeError("Cannot infer rotation for objects of type: '%s'" % type(rotation).__name__)

    @staticmethod
    def _make_retention_function(retention):
        if retention is None:
            return None
        if isinstance(retention, str):
            interval = string_parsers.parse_duration(retention)
            if interval is None:
                raise ValueError("Cannot parse retention from: '%s'" % retention)
            return FileSink._make_retention_function(interval)
        if isinstance(retention, bool):
            raise TypeError(
                "Invalid retention, it should be a count, a timedelta, or a callable, "
                "not a bool (True would keep 1 file)"
            )
        if isinstance(retention, int):
            return partial(Retention.retention_count, number=retention)
        if isinstance(retention, datetime.timedelta):
            return partial(Retention.retention_age, seconds=retention.total_seconds())
        if callable(retention):
            return retention
        raise TypeError(
            "Cannot infer retention for objects of type: '%s'" % type(retention).__name__
        )

    @staticmethod
    def _make_compression_function(compression):
        if compression is None:
            return None
        if isinstance(compression, str):
            ext = compression.strip().lstrip(".")

            if ext == "gz":
                import gzip

                compress = partial(Compression.copy_compress, opener=gzip.open, mode="wb")
            elif ext == "bz2":
                import bz2

                compress = partial(Compression.copy_compress, opener=bz2.open, mode="wb")

            elif ext == "xz":
                import lzma

                compress = partial(
                    Compression.copy_compress, opener=lzma.open, mode="wb", format=lzma.FORMAT_XZ
                )

            elif ext == "lzma":
                import lzma

                compress = partial(
                    Compression.copy_compress, opener=lzma.open, mode="wb", format=lzma.FORMAT_ALONE
                )
            elif ext == "tar":
                import tarfile

                compress = partial(Compression.add_compress, opener=tarfile.open, mode="w:")
            elif ext == "tar.gz":
                import gzip
                import tarfile

                compress = partial(Compression.add_compress, opener=tarfile.open, mode="w:gz")
            elif ext == "tar.bz2":
                import bz2
                import tarfile

                compress = partial(Compression.add_compress, opener=tarfile.open, mode="w:bz2")

            elif ext == "tar.xz":
                import lzma
                import tarfile

                compress = partial(Compression.add_compress, opener=tarfile.open, mode="w:xz")
            elif ext == "zip":
                import zipfile

                compress = partial(
                    Compression.write_compress,
                    opener=zipfile.ZipFile,
                    mode="w",
                    compression=zipfile.ZIP_DEFLATED,
                )
            else:
                raise ValueError("Invalid compression format: '%s'" % ext)

            return partial(Compression.compression, ext="." + ext, compress_function=compress)
        if callable(compression):
            return compression
        raise TypeError(
            "Cannot infer compression for objects of type: '%s'" % type(compression).__name__
        )
