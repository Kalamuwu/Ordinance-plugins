import asyncio
import datetime
import os
import hashlib

from typing import List, Dict, Set, Any

import ordinance

# NOTE
# see https://docs.python.org/3/library/difflib.html#difflib.HtmlDiff.make_file
# NOTE

def _hash_file(path: str) -> str:
    try:
        with open(path, 'rb') as file:
            data = file.read()
        hash = hashlib.sha512()
        hash.update(data)
        return hash.hexdigest()
    except: return ""


class FileMonitorPlugin(ordinance.ext.plugin.OrdinancePlugin):
    """ Monitors files and folders for changes. """

    def __init__(self, config: Dict[str, Any]):
        # read configs
        self.check: Set[str] = set(config.get('paths'))
        self.exclude: Set[str] = set(config.get('exclude'))
        self.freq: int = config.get('frequency_min')
        self.dbpath = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            'integrity.database')
        self.has_scanned_before: bool = None
        ordinance.writer.info("FileMonitor: Initialized.")

    @ordinance.ext.schedule.run_at_startup()
    def set_freq(self):
        sched = ordinance.ext.schedule.get_coro(self.scan)
        sched.set_time_between( datetime.timedelta(minutes=self.freq) )
    
    @ordinance.ext.schedule.run_at_startup()
    def check_integrity_db(self):
        if not os.path.exists(self.dbpath):
            with open(self.dbpath, 'w') as file: file.write('')
        with open(self.dbpath, 'r') as file:
            dat = file.read()
        self.has_scanned_before = len(dat) > 1
        if not self.has_scanned_before:
            ordinance.writer.info(f"FileMonitor: Integrity database missing or empty. Skipping first scan hash checks.")
    
    @ordinance.ext.schedule.run_at_startup()
    def check_given_paths(self):
        def __inner(folder: Set[str]) -> Set[str]:
            out = set()
            for file_or_dir in folder:
                if not os.path.exists(file_or_dir):
                    ordinance.writer.warn(f"FileMonitor: File or dir {file_or_dir} does not exist")
                else: out.add(file_or_dir)
            return out
        self.check = __inner(self.check)
        self.exclude = __inner(self.exclude)
        ordinance.writer.info(f"FileMonitor: Updated file lists.")

    def hash_all(self):
        hashes = {}
        for checkfile in self.check:
            if checkfile in self.exclude: continue
            # checkfile is file. add to hashes
            if os.path.isfile(checkfile):
                hashes[checkfile] = _hash_file(checkfile)
                continue
            # checkfile is dir. walk
            for (path,subdirs,files) in os.walk(checkfile):
                # we walk from last to first so that if we remove an element,
                # the only elements whose position will change are those that
                # we've already checked, so that we don't accidentally skip
                # subdirs.
                for i in range(len(subdirs)-1, -1, -1):
                    if subdirs[i-1] in self.exclude: subdirs.pop(i-1)
                for file in files:
                    fullpath = os.path.join(path, file)
                    if fullpath in self.exclude: continue
                    hashes[fullpath] = _hash_file(fullpath)
        return hashes
    
    def save_hashes(self, hashes: Dict[str, str]) -> None:
        with open(self.dbpath, 'w') as file:
            for path,hash in hashes.items():
                file.write(f"{path}\0{hash}\n")
    
    def read_hashes(self) -> Dict[str, str]:
        hashes = {}
        with open(self.dbpath, 'r') as file:
            for line in file.readlines():
                file,hash = line.split('\0')
                hashes[file] = hash.strip()
        return hashes

    @ordinance.ext.schedule.run_periodically(seconds=15)
    def scan(self):
        ordinance.writer.info("FileMonitor: Starting filsystem scan...")
        new_hashes = self.hash_all()
        ordinance.writer.info("FileMonitor: Calculated new file hashes.")
        old_hashes = self.read_hashes()
        ordinance.writer.info("FileMonitor: Loaded local integrity database.")
        if self.has_scanned_before:
            out = ""
            new_hashes_keys = set(new_hashes.keys())
            old_hashes_keys = set(old_hashes.keys())
            # set operations to get added and deleted files
            new_files = new_hashes_keys - old_hashes_keys
            del_files = old_hashes_keys - new_hashes_keys
            for key in new_files:  out += f"  File added:   {key}\n"
            for key in del_files:  out += f"  File deleted:   {key}\n"
            # alert num add/del
            n_new = len(new_files)
            n_del = len(del_files)
            if n_new and n_del:  ordinance.writer.alert(f"{n_new} new files and {n_del} files deleted since last scan")
            elif n_new:          ordinance.writer.alert(f"{n_new} new files since last scan")
            elif n_del:          ordinance.writer.alert(f"{n_del} files deleted since last scan")
            # diff files that aren't new or deleted
            union = new_hashes_keys & old_hashes_keys
            for file in union:
                new_hash = new_hashes[file]
                old_hash = old_hashes[file]
                if new_hash == old_hash: continue
                out += f"  File changed:   {file}\n"
            if out: ordinance.writer.warn(f"FileMonitor: Aggregated changes:\n{out}")
            else:   ordinance.writer.info(f"FileMonitor: No changes detected.")
        else:
            ordinance.writer.info(f"FileMonitor: This is first scan. Skipping hash checks.")
            self.has_scanned_before = True
        self.save_hashes(new_hashes)
        ordinance.writer.success(f"FileMonitor: Finished scan.")


def setup(config):
    return FileMonitorPlugin(config)

