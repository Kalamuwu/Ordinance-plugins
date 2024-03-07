import os
import json
import datetime

from typing import List, Dict, Set, Any

import ordinance

class SysHardenerPlugin(ordinance.plugin.OrdinancePlugin):
    """ Scans the system for weak configs. """

    def __init__(self, config: Dict[str, Any]):
        # read configs
        self.scan_days: int = config.get('scan_every_days')
        self.configscans = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            'configscans.json')
        self.scans = None
        ordinance.writer.info("SysHardener: Initialized.")
    
    @ordinance.schedule.run_at_plugin_start()
    def set_scan_rate(self):
        sched = ordinance.schedule.get_coro(self.scan_configs)
        sched.set_time_between( datetime.timedelta(days=self.scan_days) )
    
    @ordinance.schedule.run_at_plugin_start()
    def read_scans(self):
        if not os.path.isfile(self.configscans):
            with open(self.configscans, 'w') as file:
                file.write("{}")
        try:
            with open(self.configscans, 'r') as file:
                self.scans = json.loads(file.read())
        except:
            ordinance.writer.error("SysHardener: Could not load scans db")
            with open(self.configscans, 'w') as file:
                file.write("{}")
            self.scans = {}
        sched = ordinance.schedule.get_coro(self.scan_configs)
        sched.run()
    
    @ordinance.schedule.run_periodically(days=7)
    def scan_configs(self):
        ordinance.writer.info("SysHardener: Starting system config scan...")
        num_issues = 0
        if self.scans is None: return  # too early, this isn't initialized yet
        for (file,patterns) in self.scans.items():
            if not os.path.isfile(file): continue
            ordinance.writer.debug(f"SysHardener: Scanning file {file}")
            with open(file, 'r') as file:
                data = file.read()
            for (pattern, recc) in patterns.items():
                if pattern in data:
                    ordinance.writer.warn(f"SysHardener: Issue identified in file {file}: ", recc)
                    num_issues += 1
        if num_issues:
            ordinance.writer.info(f"SysHardener: Scan complete. {num_issues} issue(s) identified.")
        else:
            ordinance.writer.success("SysHardener: Scan complete. No issues identified.")


def setup():
    return SysHardenerPlugin
