import asyncio
import aiohttp
import json
import os

from typing import List, Dict, Set, Any

import ordinance

class BanlistPlugin(ordinance.plugin.OrdinancePlugin):
    """ Manages a remote white/blacklist database as set by config. """

    headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/118.0'}

    def parse_url_to_db_name(self, url: str) -> str:
        # pre formatting
        url = url.lower()
        if   url.startswith('http://'):  url = url[7:]
        elif url.startswith('https://'): url = url[8:]
        # keep only good chars
        valid_chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_'
        last_was_dot = False
        name = ""
        for c in url:
            if c in valid_chars:   name += c
            elif not last_was_dot: name += '.'; last_was_dot = True
        # ensure last char isn't .
        while name.endswith('.'): name = name[:-1]
        # all good, return
        #return self.get_local_path('storage/') + name + '.database'
        return os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            f'storage/{name}.database')

    def __init__(self, config: Dict[str, Any]):
        # read configs
        self.remote_fetch: bool = config.get('fetch_on_startup')
        self.remote_refetch: bool = config.get('auto_update_every_24hrs')
        self.remote_srcs: List[str] = config.get('sources')
        self.remote_cache: Dict[str, ordinance.network.IPv4Dataset] = \
            { src : ordinance.network.IPv4Dataset(
                self.parse_url_to_db_name(src)
            ) for src in self.remote_srcs }
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

    @ordinance.schedule.run_at_plugin_start()
    @ordinance.schedule.run_periodically(days=1)
    def refresh_remotes(self):
        ordinance.writer.info("Banlist: Starting remote ban list refresh...")
        # fetch new sources
        try:
            loop = asyncio.get_event_loop()
        except:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        async def fetch_all():
            async with aiohttp.ClientSession(loop=loop, headers=self.headers) as session:
                return await asyncio.gather(*[
                    self.__fetch(session, url) for url in self.remote_srcs
                ], return_exceptions=True)
        results = loop.run_until_complete(fetch_all())
        loop.stop(); loop.close()
        # fetch old sources
        for src,db in self.remote_cache.items():
            db.read()
        # compare with old
        did_something_change = False
        for i,remote in enumerate(self.remote_srcs):
            old_db = self.remote_cache[remote]
            new_list = results[i]
            # make sure it was fetched correctly
            if isinstance(new_list, Exception):
                ordinance.writer.error(f"Source '{remote}' could not be fetched, with error:", new_list)
                continue
            # clean up `new`
            new = set()
            for line in new_list.split('\n'):
                if '#' in line: line,_ = line.split('#', maxsplit=1)
                line = line.strip()
                if not line: continue
                if line.startswith('ALL:'): # probably hosts.deny format
                    line = line.split()[1]
                if ordinance.network.is_valid_ipv4(line):
                    new.add(line)
            # compare sets: what isn't in both?
            to_add, to_remove = old_db.diff(new)
            ordinance.writer.debug(f"Banlist: calculated db diff: {len(to_add)} to add, {len(to_remove)} to remove")
            if len(to_add):
                did_something_change = True
                for ip in to_add:
                    ordinance.network.blacklist.add(ip)
            if len(to_remove):
                did_something_change = True
                for ip in to_remove:
                    try: ordinance.network.blacklist.delete(ip)
                    except KeyError: pass
            # update cache and report
            old_db.update_to(new)
            old_db.flush()
            ordinance.writer.info(f"Banlist: Updated remote banlist '{remote}': " +
                                     f"{len(to_add)} added, {len(to_remove)} removed")
        # save updated blacklist
        if did_something_change:
            ordinance.network.flush_blacklist_to_iptables()
            ordinance.writer.success(f"Banlist: Updated blacklist.")
        else:
            ordinance.writer.info(f"Banlist: Nothing to change.")


def setup():
    return BanlistPlugin
