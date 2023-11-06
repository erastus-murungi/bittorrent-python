import asyncio
import signal
import sys
import time
from bisect import insort
from itertools import cycle
from time import monotonic
from typing import Optional, TextIO

import resource
from humanfriendly import format_size, format_timespan
from math import ceil
from more_itertools import quantify
from termcolor import colored

from app.content import Piece
from app.torrent import Info

ANSI_ERASE_CURRENT_LINE = "\u001b[2K"
ANSI_MOVE_CURSOR_UP_ONE_LINE = "\x1b[1A"
ANSI_HIDE_CURSOR = "\x1b[?25l"
ANSI_SHOW_CURSOR = "\x1b[?25h"

PROGRESS_SPINNER_SEQUENCE = cycle("◐ ◓ ◑ ◒".split())

COMPLETED_JOBS_REFRESH_TIME = 3
FRAMES_PER_CYCLE = 1.0 / 10.0

MAX_NUMBER_CHARACTERS_HEADER_PROGRESS_BAR = 30

INDENT = "    "


def get_green_bold_colored(text: str) -> str:
    return colored(f"{text}", "green", attrs=["bold"])


class File:
    def __init__(self, file_path: str, file_size: int):
        self.file_path = file_path
        self.file_size = file_size
        self.start_time: float | None = None
        self.finish_time: float | None = None
        self.downloaded: list[Piece] = []
        self.downloaded_size: int = 0
        self.queue = asyncio.Queue[Piece]()
        self.future = asyncio.ensure_future(self.start())

    @property
    def is_completed(self) -> bool:
        return self.downloaded_size == self.file_size

    def start_progress(self):
        self.start_time = time.monotonic()

    @property
    def is_not_completed(self):
        return not self.is_completed

    async def start(self):
        while self.is_not_completed:
            piece = await self.queue.get()
            insort(self.downloaded, piece, key=lambda p: p.index)
            self.downloaded_size += piece.length

    def cleanup(self):
        if self.future:
            self.future.cancel()

    def get_progress_item_title(self) -> str:
        """
        Return a title to display

        """
        return f"{self.file_path}"

    def get_normalized_progress(self) -> float:
        """
        Returns the progress of this time with 1 being complete

        :return: The progress from 0 to 1
        """
        if self.file_size is None:
            return 0.0
        normalized_progress = len(self.downloaded) / self.file_size
        if normalized_progress >= 1.0:
            if self.finish_time is None:
                self.finish_time = monotonic()
        return min(normalized_progress, 1.0)

    def get_percentage_progress(self) -> float:
        return self.get_normalized_progress() * 100

    def pretty_print_progress(self, text_io: TextIO = sys.stdout) -> None:
        progress_item_title = colored(self.get_progress_item_title(), "white")
        progress_spinner_code_point = next(PROGRESS_SPINNER_SEQUENCE)
        if self.is_completed:
            # we define done_str because f-strings do not allow `\`
            done_str = "\u2714"
            text_io.write(
                f"{INDENT}{get_green_bold_colored(done_str)} {progress_item_title} ... finished in "
                f"{format_timespan(self.finish_time - self.start_time)}\n"
            )
        else:
            text_io.write(
                f"{INDENT}{progress_spinner_code_point} {progress_item_title} ... "
                f"{format_timespan(monotonic() - self.start_time)}    ({self.get_percentage_progress():04.2f} %)\n"
            )


def get_files_from_info(info: Info) -> tuple[File, ...]:
    return (File(info.name, info.length),)


class ProgressManager:
    def __init__(
        self,
        info: Info,
        progress_bar_header_title: str = "Downloading",
    ):
        self.start_time: Optional[float] = None
        self.files: tuple[File, ...] = get_files_from_info(info)
        self.header_print_state: tuple[int, int, int] = (
            0,
            MAX_NUMBER_CHARACTERS_HEADER_PROGRESS_BAR,
            0,
        )
        self.progress_bar_header_title = progress_bar_header_title
        self.downloading_files = self.files
        self.download_speed = 0
        self.abort = False
        self.prev_size_and_timestamp: tuple[float, float] = (0, 0)
        self.received_pieces: asyncio.Queue[Piece] = asyncio.Queue()
        self.future = asyncio.ensure_future(self.start())

    @staticmethod
    def delete_ascii_terminal_line(text_io: TextIO = sys.stdout):
        text_io.write(ANSI_ERASE_CURRENT_LINE + "\r" + ANSI_MOVE_CURSOR_UP_ONE_LINE)

    def update_header_print_state(self):
        n_jobs_completed = quantify(self.files, lambda p: p.is_completed)
        n_filled = ceil(
            n_jobs_completed
            / len(self.files)
            * MAX_NUMBER_CHARACTERS_HEADER_PROGRESS_BAR
        )
        n_left = MAX_NUMBER_CHARACTERS_HEADER_PROGRESS_BAR - n_filled
        self.header_print_state = (n_filled, n_left, n_jobs_completed)

    def update_download_speed(self):
        size, timestamp = self.prev_size_and_timestamp
        current_size, current_timestamp = (
            sum(progress_item.downloaded_size for progress_item in self.files),
            monotonic(),
        )
        self.download_speed = (current_size - size) / (current_timestamp - timestamp)
        self.prev_size_and_timestamp = (current_size, current_timestamp)

    def downloaded_size(self):
        return sum(downloading_file.downloaded_size for downloading_file in self.files)

    def total_size(self):
        return sum(downloading_file.file_size for downloading_file in self.files)

    def pretty_print_progress_bar_header(self, text_io: TextIO):
        n_filled, n_left, n_jobs_completed = self.header_print_state
        text_io.write(
            f"\r{INDENT}{get_green_bold_colored(self.progress_bar_header_title)}  "
            f'[{"=" * (n_filled - 1) + ">"}{" " * n_left}] '
            f"[{self.downloaded_size()} / {self.total_size()} downloaded] ... "
            f"{format_timespan(monotonic() - self.start_time, detailed=False)}    "
            f"({format_size(self.download_speed)} / sec)\n"
        )

    def initialize_all_progress_items(self):
        for progress_item in self.files:
            progress_item.start_progress()

    def cleanup_all_progress_items(self):
        for progress_item in self.files:
            if not progress_item.is_completed:
                raise RuntimeError(f"{progress_item} is not completed")
        for progress_item in self.files:
            progress_item.cleanup()

    def cleanup(self):
        self.abort = True
        if self.future:
            self.future.cancel()

    async def pretty_print_all_progress_items(
        self,
        text_io: TextIO = sys.stdout,
    ):
        progress_items = tuple(
            sorted(
                self.downloading_files,
                key=lambda p: p.get_normalized_progress(),
                reverse=True,
            )
        )
        for progress_item in progress_items:
            progress_item.pretty_print_progress()
        await asyncio.sleep(FRAMES_PER_CYCLE)
        for _ in range(len(progress_items)):
            self.delete_ascii_terminal_line()
        text_io.write("\r")
        text_io.write(ANSI_ERASE_CURRENT_LINE)

    def get_incomplete_progress_items_state(
        self,
    ) -> tuple[tuple[File, ...], float]:
        return (
            tuple(filter(lambda p: p.is_not_completed, self.downloading_files)),
            monotonic(),
        )

    def update_correct_file(self, piece: Piece):
        self.files[0].queue.put(piece)

    async def start(self, text_io: TextIO = sys.stdout):
        self.start_time = monotonic()
        self.prev_size_and_timestamp = (0, self.start_time)
        self.initialize_all_progress_items()

        (
            self.downloading_files,
            incomplete_progress_items_update_time,
        ) = self.get_incomplete_progress_items_state()
        while self.downloading_files:
            text_io.write(ANSI_HIDE_CURSOR)

            while (
                monotonic() - incomplete_progress_items_update_time
                < COMPLETED_JOBS_REFRESH_TIME
            ):
                self.pretty_print_progress_bar_header(text_io)
                await self.pretty_print_all_progress_items(text_io)
                self.delete_ascii_terminal_line()
                self.update_header_print_state()

            piece = await self.received_pieces.get()
            self.update_correct_file(piece)
            (
                self.downloading_files,
                incomplete_progress_items_update_time,
            ) = self.get_incomplete_progress_items_state()
            self.update_download_speed()
        text_io.write(ANSI_ERASE_CURRENT_LINE)
        text_io.write("\r")
        self.cleanup_all_progress_items()
        rusage = resource.getrusage(resource.RUSAGE_SELF)
        text_io.write(
            f"Finished successfully\n"
            f"     Time ─────────────────────── {format_timespan(monotonic() - self.start_time)}\n"
            f"     Peak RAM use ─────────────── {format_size(rusage.ru_maxrss)}\n"
        )
        sys.stdout.write(ANSI_SHOW_CURSOR)


def signal_handler(signum, frame):
    sys.stdout.write(ANSI_SHOW_CURSOR)
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


if __name__ == "__main__":
    import doctest

    doctest.testmod()
