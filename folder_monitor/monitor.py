import datetime
import os
import hashlib

from typing import List, Dict, Set, Any

import ordinance

# NOTE
# see https://docs.python.org/3/library/difflib.html#difflib.HtmlDiff.make_file
# NOTE

def hash_file(path: str) -> str:
    try:
        with open(path, 'rb') as file:
            data = file.read()
        hash = hashlib.sha512()
        hash.update(data)
        return hash.hexdigest()
    except: return ""


class FileMonitorPlugin(ordinance.plugin.OrdinancePlugin):
    """ Monitors files and folders for changes. """

    def __init__(self, config: Dict[str, Any]):
        # read configs
        self.check: Set[str] = set(config.get('paths'))
        self.exclude: Set[str] = set(config.get('exclude'))
        self.freq: int = config.get('frequency_min')
        db_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            'integrity.database')
        self.db = ordinance.database.StringDatabase(db_path)
        ordinance.writer.info("FileMonitor: Initialized.")

    @ordinance.schedule.run_at_plugin_start()
    def set_freq(self):
        self.scan.add_periodic_trigger( datetime.timedelta(minutes=self.freq) )
        ordinance.writer.debug(f"FileMonitor: Set scan frequency to {self.freq} minutes.")
    
    @ordinance.schedule.run_at_plugin_start()
    def check_given_paths(self):
        def __inner(folder: Set[str]) -> Set[str]:
            out = set()
            for file_or_dir in folder:
                if not os.path.exists(file_or_dir):
                    ordinance.writer.warn(f"FileMonitor: File or dir in database {file_or_dir} does not exist")
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
                hashes[checkfile] = hash_file(checkfile)
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
                    hashes[fullpath] = hash_file(fullpath)
        return hashes

    @ordinance.schedule.blank_schedule()
    def scan(self):
        ordinance.writer.info("FileMonitor: Starting filsystem scan...")
        new_hashes = self.hash_all()
        ordinance.writer.info("FileMonitor: Calculated new file hashes.")
        self.db.read()
        ordinance.writer.info("FileMonitor: Loaded local integrity database.")
        if len(self.db):
            out = ""
            new_hashes_keys = set(new_hashes.keys())
            old_hashes_keys = set(self.db.keys())
            # set operations to get added and deleted files
            new_files = new_hashes_keys - old_hashes_keys
            del_files = old_hashes_keys - new_hashes_keys
            # alert add/del
            n_new = len(new_files)
            n_del = len(del_files)
            if n_new:
                out += f"ADDITIONS: {n_new}\n"
                for key in new_files:
                    out += f"  {key}\n"
            if n_del:
                out += f"DELETIONS: {n_del}\n"
                for key in del_files:
                    out += f"  {key}\n"
            # diff files that aren't new or deleted
            union = new_hashes_keys & old_hashes_keys
            out_changes = ""
            for file in union:
                new_hash = new_hashes.get(file)
                old_hash = self.db.get(file)
                if new_hash == old_hash: continue
                ordinance.writer.warn(f"File '{file}' changed since last scan")
                out += f"  {file}\n"
            if out_changes:
              out += "CHANGES: \n" + out_changes
            if out: ordinance.writer.alert(f"FileMonitor: Aggregated changes:\n{out}")
            else:   ordinance.writer.info(f"FileMonitor: No changes detected.")
        else: ordinance.writer.warn(f"FileMonitor: Integrity database was empty! Skipped hash checking.")
        # update with new hashes
        ordinance.writer.debug(f"FileMonitor: {len(new_hashes)} hashes.")
        self.db.clear()
        for k,v in new_hashes.items(): self.db.set(k, v)
        self.db.flush()
        ordinance.writer.success(f"FileMonitor: Finished scan.")


def setup():
    return FileMonitorPlugin

