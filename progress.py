import sys
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from itertools import cycle
from random import randint
from threading import Thread
from time import monotonic, sleep
from typing import Iterable, Optional, TextIO

import click
import requests
import resource
from humanfriendly import format_size, format_timespan
from math import ceil
from more_itertools import quantify
from termcolor import colored

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


@dataclass
class ProgressItem(ABC):
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    is_finished: bool = False
    start_time: float = float("inf")

    @abstractmethod
    def is_completed(self) -> bool:
        pass

    @abstractmethod
    def start_progress(self) -> bool:
        pass

    def is_not_completed(self):
        return not self.is_completed()

    def cleanup(self):
        pass

    def get_progress_item_title(self) -> str:
        """
        Return a title to display

        """
        return str(self.id)

    def pretty_print_progress(self, text_io: TextIO = sys.stdout) -> None:
        progress_item_title = colored(self.get_progress_item_title(), "white")
        progress_spinner_code_point = next(PROGRESS_SPINNER_SEQUENCE)
        if self.is_completed():
            # we define done_str because f-strings do not allow `\`
            done_str = "\u2714"
            text_io.write(
                f"{INDENT}{get_green_bold_colored(done_str)} [{progress_item_title}]\n"
            )
        else:
            text_io.write(
                f"{INDENT}{progress_spinner_code_point} {progress_item_title} %\n"
            )


class DeterminateProgressItem(ProgressItem):
    finish_time: Optional[float] = None

    @abstractmethod
    def get_normalized_progress(self) -> float:
        """
        Returns the progress of this time with 1 being complete

        :return: The progress from 0 to 1
        """

    def get_percentage_progress(self) -> float:
        return self.get_normalized_progress() * 100

    def pretty_print_progress(self, text_io: TextIO = sys.stdout) -> None:
        progress_item_title = colored(self.get_progress_item_title(), "white")
        progress_spinner_code_point = next(PROGRESS_SPINNER_SEQUENCE)
        if self.is_completed():
            # we define done_str because f-strings do not allow `\`
            done_str = "\u2714"
            text_io.write(
                f"{INDENT}{get_green_bold_colored(done_str)} {progress_item_title} ... finished in {format_timespan(self.finish_time - self.start_time)}\n"
            )
        else:
            text_io.write(
                f"{INDENT}{progress_spinner_code_point} {progress_item_title} ... {format_timespan(monotonic() - self.start_time)}    ({self.get_percentage_progress():04.2f} %)\n"
            )


class DownloadingMixIn(ABC):
    @abstractmethod
    def get_total_size(self):
        pass

    @abstractmethod
    def get_current_downloaded_size(self):
        pass


class MockDownload(DeterminateProgressItem, DownloadingMixIn):
    def __init__(self, download_size: float, bandwidth: float):
        super().__init__()
        self.size = download_size
        self.bandwidth = bandwidth
        self.expected_download_duration: float = download_size / bandwidth

    def start_progress(self) -> None:
        self.start_time = monotonic()

    def get_normalized_progress(self):
        if self.is_finished:
            return 1.0
        normalized_progress = (
            monotonic() - self.start_time
        ) / self.expected_download_duration
        if normalized_progress >= 1.0:
            self.is_finished = True
            if self.finish_time is None:
                self.finish_time = monotonic()
        return min(normalized_progress, 1.0)

    def is_completed(self):
        return (
            self.is_finished
            or (monotonic() - self.start_time) > self.expected_download_duration
        )

    def get_total_size(self):
        return self.size

    def get_current_downloaded_size(self):
        return min(self.size, (monotonic() - self.start_time) * self.bandwidth)

    def __repr__(self):
        return f"{self.__class__.__qualname__}(size={self.size}MB, bandwidth={self.bandwidth}MBps)"


@dataclass(slots=True)
class DownloadState:
    total_size: Optional[int] = None
    downloaded: int = 0.0
    is_finished: bool = False
    finish_time: float = None


class FileDownloadAsync(DeterminateProgressItem, DownloadingMixIn):
    url: str
    filename: str
    download_thread: Thread
    latest_size_and_timestamp = tuple[float, float]

    def get_normalized_progress(self) -> float:
        pass

    def is_completed(self) -> bool:
        pass

    def start_progress(self) -> bool:
        pass

    def get_total_size(self):
        pass

    def get_current_downloaded_size(self):
        pass


class FileDownloadThreaded(DeterminateProgressItem, DownloadingMixIn):
    url: str
    filename: str
    download_thread: Thread
    latest_size_and_timestamp = tuple[float, float]

    def __init__(self, url: str, filename: str = ""):
        super().__init__()
        self.url = url
        self.filename = filename
        self.download_state: DownloadState = DownloadState()

    def get_normalized_progress(self) -> float:
        if self.download_state.total_size is None:
            return 0.0
        normalized_progress = (
            self.download_state.downloaded / self.download_state.total_size
        )
        if normalized_progress >= 1.0:
            self.is_finished = True
            if self.finish_time is None:
                self.finish_time = monotonic()
        return min(normalized_progress, 1.0)

    def is_completed(self) -> bool:
        return self.download_state.is_finished

    def start_progress(self) -> bool:
        self.start_time = monotonic()

        def download_file(download_state: DownloadState):
            response = requests.get(self.url, stream=True)
            if response.status_code != 200:
                raise RuntimeError(
                    f"downloading {self.url} failed with status code {response.status_code}"
                )
            download_state.total_size = (
                int(response.headers.get("Content-Length", "0")) or None
            )
            block_size = 1024
            with open(self.filename, "wb") as file:
                for data in response.iter_content(block_size):
                    download_state.downloaded += len(data)
                    file.write(data)
            download_state.is_finished = True
            download_state.finish_time = monotonic()

        self.download_thread = Thread(
            name=str(self.id),
            target=download_file,
            args=(self.download_state,),
        )
        self.download_thread.start()
        return True

    def cleanup(self):
        self.download_thread.join()

    def get_progress_item_title(self) -> str:
        return f"{self.filename} <- {self.url}"

    def get_total_size(self):
        return self.download_state.total_size

    def get_current_downloaded_size(self):
        return self.download_state.downloaded


class ProgressBarManager:
    def __init__(
        self,
        progress_items: Iterable[DeterminateProgressItem],
        progress_bar_header_title: str = "Downloading",
        downloading: bool = False,
    ):
        self.start_time: Optional[float] = None
        self.progress_items: tuple[DeterminateProgressItem, ...] = tuple(progress_items)
        self.header_print_state: tuple[int, int, int] = (
            0,
            MAX_NUMBER_CHARACTERS_HEADER_PROGRESS_BAR,
            0,
        )
        self.progress_bar_header_title = progress_bar_header_title
        self.incomplete_progress_items = self.progress_items
        self.downloading = downloading
        if downloading:
            self.download_speed = 0
            self.prev_size_and_timestamp: tuple[float, float] = (0, 0)

    @staticmethod
    def delete_ascii_terminal_line(text_io: TextIO = sys.stdout):
        text_io.write(ANSI_ERASE_CURRENT_LINE + "\r" + ANSI_MOVE_CURSOR_UP_ONE_LINE)

    def update_header_print_state(self):
        n_jobs_completed = quantify(self.progress_items, lambda p: p.is_completed())
        n_filled = ceil(
            n_jobs_completed
            / len(self.progress_items)
            * MAX_NUMBER_CHARACTERS_HEADER_PROGRESS_BAR
        )
        n_left = MAX_NUMBER_CHARACTERS_HEADER_PROGRESS_BAR - n_filled
        self.header_print_state = (n_filled, n_left, n_jobs_completed)

    def update_download_speed(self):
        size, timestamp = self.prev_size_and_timestamp
        current_size, current_timestamp = (
            sum(
                progress_item.get_current_downloaded_size()
                for progress_item in self.progress_items
            ),
            monotonic(),
        )
        self.download_speed = (current_size - size) / (current_timestamp - timestamp)
        self.prev_size_and_timestamp = (current_size, current_timestamp)

    def pretty_print_progress_bar_header(self, text_io: TextIO):
        n_filled, n_left, n_jobs_completed = self.header_print_state
        if self.downloading:
            text_io.write(
                f"\r{INDENT}{get_green_bold_colored(self.progress_bar_header_title)}  "
                f'[{"=" * (n_filled - 1) + ">"}{" " * n_left}] '
                f"[{n_jobs_completed} / {len(self.progress_items)} downloaded] ... "
                f"{format_timespan(monotonic() - self.start_time, detailed=False)}    ({format_size(self.download_speed)} / sec)\n"
            )
        else:
            text_io.write(
                f"\r{INDENT}{get_green_bold_colored(self.progress_bar_header_title)}  "
                f'[{"=" * (n_filled - 1) + ">"}{" " * n_left}] '
                f"[{n_jobs_completed} / {len(self.progress_items)} downloaded]... "
                f"{format_timespan(monotonic() - self.start_time, detailed=False)}\n"
            )

    def initialize_all_progress_items(self):
        for progress_item in self.progress_items:
            progress_item.start_progress()

    def cleanup_all_progress_items(self):
        for progress_item in self.progress_items:
            if not progress_item.is_completed():
                raise RuntimeError(f"{progress_item} is not completed")
        for progress_item in self.progress_items:
            progress_item.cleanup()

    def pretty_print_all_progress_items(
        self,
        text_io: TextIO = sys.stdout,
    ):
        progress_items = tuple(
            sorted(
                self.incomplete_progress_items,
                key=lambda p: p.get_normalized_progress(),
                reverse=True,
            )
        )
        for progress_item in progress_items:
            progress_item.pretty_print_progress()
        sleep(FRAMES_PER_CYCLE)
        for _ in range(len(progress_items)):
            self.delete_ascii_terminal_line()
        text_io.write("\r")
        text_io.write(ANSI_ERASE_CURRENT_LINE)

    def get_incomplete_progress_items_state(
        self,
    ) -> tuple[tuple[DeterminateProgressItem, ...], float]:
        return (
            tuple(
                filter(lambda p: p.is_not_completed(), self.incomplete_progress_items)
            ),
            monotonic(),
        )

    def run(self, text_io: TextIO = sys.stdout):
        self.start_time = monotonic()
        self.prev_size_and_timestamp = (0, self.start_time)
        self.initialize_all_progress_items()

        (
            self.incomplete_progress_items,
            incomplete_progress_items_update_time,
        ) = self.get_incomplete_progress_items_state()
        while self.incomplete_progress_items:
            text_io.write(ANSI_HIDE_CURSOR)

            while (
                monotonic() - incomplete_progress_items_update_time
                < COMPLETED_JOBS_REFRESH_TIME
            ):
                self.pretty_print_progress_bar_header(text_io)
                self.pretty_print_all_progress_items(text_io)
                self.delete_ascii_terminal_line()
                self.update_header_print_state()

            (
                self.incomplete_progress_items,
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


@click.command(
    name="Progress",
    help="This is a program to illustrate how to build helpful progress reports for CLIs",
)
@click.option(
    "--real-downloads",
    "-r",
    is_flag=True,
    default=False,
    help="Use real downloads from https://testfiledownload.com/ to do test the program",
)
@click.option(
    "--num-items", "-n", default=8, help="Number of items to run download concurrently"
)
@click.option("--download-speed", "-d", default=20, help="A mock download speed")
@click.option(
    "--max-mock-file-size",
    "-m",
    default=500,
    help="Mock download files are generated from a uniform distribution [1, max_mock_file_size)",
)
def test(
    real_downloads: bool, num_items: int, download_speed: int, max_mock_file_size: int
):
    if real_downloads:
        small_file_url = "https://speed.hetzner.de/100MB.bin"
        downloads = [
            FileDownloadThreaded(small_file_url, f"large_file_{i}.bin")
            for i in range(num_items)
        ]
    else:
        downloads = [
            MockDownload(randint(1, max_mock_file_size), download_speed / num_items)
            for _ in range(num_items)
        ]
    progress_bar_manager = ProgressBarManager(downloads, downloading=True)
    progress_bar_manager.run()


if __name__ == "__main__":
    try:
        test()
    except KeyboardInterrupt:
        sys.stdout.write(ANSI_SHOW_CURSOR)
        sys.exit(0)
