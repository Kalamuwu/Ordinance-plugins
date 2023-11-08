import asyncio
import aiohttp
import json

from typing import List, Dict, Set, Any

import ordinance

class BanlistPlugin(ordinance.ext.plugin.OrdinancePlugin):
    """ Manages a remote white/blacklist database as set by config. """

    headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/118.0'}

    def __init__(self, config: Dict[str, Any]):
        # read configs
        self.remote_fetch: bool = config.get('fetch_on_startup')
        self.remote_refetch: bool = config.get('auto_update_every_24hrs')
        self.remote_srcs: List[str] = config.get('sources')
        self.remote_cache: Dict[str, Set[str]] = { src:set() for src in self.remote_srcs }
        ordinance.writer.info("Banlist: Initialized.")
    
    async def __fetch(self, session: aiohttp.ClientSession, url: str):
        async with session.get(url) as response:
            if response.content_type == "text/plain" \
            or response.content_type == "application/octet-stream":
                msg = await response.text()
                return msg
            elif response.content_type == "text/json":
                msg = await response.json()
                return msg
            raise ordinance.exceptions.NetworkException(f"Unknown content type {response.content_type}")

    @ordinance.ext.schedule.run_at_startup()
    @ordinance.ext.schedule.run_periodically(days=1)
    def refresh_remotes(self):
        ordinance.writer.info("Banlist: Starting remote ban list refresh...")
        # fetch new sources
        async def fetch_all():
            async with aiohttp.ClientSession(loop=loop, headers=self.headers) as session:
                return await asyncio.gather(*[
                    self.__fetch(session, url) for url in self.remote_srcs
                ], return_exceptions=True)
        try:
            loop = asyncio.get_event_loop()
        except:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        results = loop.run_until_complete(fetch_all())
        # compare with old
        for i,remote in enumerate(self.remote_srcs):
            old = self.remote_cache[remote]
            new_list = results[i]
            if isinstance(new_list, Exception):
                ordinance.writer.error(f"Source '{remote}' could not be fetched, with error:", new_list)
                continue
            # clean up `new`
            new = set()
            for line in new_list.split('\n'):
                line = line.strip()
                if line == '': continue
                if line.startswith('#'): continue
                if line.startswith('ALL:'): # probably hosts.deny format
                    line = line.split()[1]
                if ordinance.ext.network.is_valid_ipv4(line):
                    new.add(line)
            # compare sets: what isn't in both?
            to_remove = old - new  # left-over old
            to_add = new - old     # left-over new
            # commit
            ordinance.ext.network.blacklist(to_add)
            ordinance.ext.network.un_blacklist(to_remove)
            # update cache and report
            self.remote_cache[remote] = new
            ordinance.writer.success(f"Banlist: Updated remote banlist '{remote}': " +
                                     f"{len(to_add)} added, {len(to_remove)} removed")
        # save updated blacklist
        ordinance.ext.network.flush_blacklist_to_iptables()


def setup(config):
    return BanlistPlugin(config)
