import asyncio
import time
import socketserver
import threading
import random
import os
import re

from typing import List, Dict, Any

import ordinance

class SocketListener(socketserver.BaseRequestHandler):
    def __init__(self, request: Any, client_address: Any, server: socketserver.BaseServer):
        super().__init__(request, client_address, server)

    def handle(self):
        # try grabbing connection info (shouldnt fail?)
        try:
            ip = str(self.client_address[0])
            port = str(self.server.server_address[1])
            ordinance.writer.debug(f"Honeypot: Detected incoming connection from {ip} to port {port}")
        except Exception as e:
            ordinance.writer.error(f"Honeypot: Error occurred while handling foreign connection: ", e)
            return

        try:
            # kindly generate random length garbage for attacker
            length = random.randint(500, 30000)
            fake_string = os.urandom(length)
            # send garbage data
            try:
                self.request.send(fake_string)
            except Exception as e:
                ordinance.writer.warn(f"Honeypot: Unable to send data to {ip} from port {port}, with e:", e)
            
            # close socket
            try:    self.request.close()
            except: pass

            if ordinance.ext.network.is_valid_ipv4(ip):
                if ordinance.ext.network.is_whitelisted(ip):
                    ordinance.writer.info(f"Honeypot: Ignoring connection from {ip} to port {port}, whitelisted")
                else:
                    # alert of and ban foreign connection
                    self.__class__.plugininstance.async_alert(ip, port)
                    self.__class__.plugininstance.async_ban(ip)
        
        except Exception as e:
            ordinance.writer.error(f"Honeypot: Error occurred while handling foreign connection from {ip} on port {port}:", e)


class ServerThread(threading.Thread):
    def __init__(self, autoaccept: bool, con_type: str, port: int, interface: str):
        self.__autoaccept = autoaccept
        self.__con_type = con_type
        self.__port = port
        self.__interface = interface
        self.server = None
        super().__init__(
            target=self.bind,
            name=f"Honeypot-{con_type}{port}"
        )
    
    def bind(self):
        # open table
        if self.__autoaccept:
            ordinance.ext.network.create_iptables_input_accept(self.__con_type, self.__port)
        # bind server
        self.server = None
        num_attempts = 0
        while num_attempts < 5 and self.server is None:
            try:
                num_attempts += 1
                if self.__con_type == "tcp":
                    self.server = socketserver.ThreadingTCPServer(
                        (self.__interface, self.__port), SocketListener)
                else: # __con_type == "udp"
                    self.server = socketserver.ThreadingUDPServer(
                        (self.__interface, self.__port), SocketListener)
            except Exception as e:
                self.server = None
                i = f" interface {self.__interface}" if self.__interface else ""
                ordinance.writer.debug(f"Honeypot: Bind attempt {num_attempts}/5 to {self.__con_type} port {self.__port}{i} failed with error:", e)
                time.sleep(1)
        if self.server is None:
            i = f" with interface {self.__interface}" if self.__interface else ""
            ordinance.writer.error(f"Honeypot: Could not bind to {self.__con_type} port {self.__port}{i}")
        else:
            self.server.serve_forever(2)


class HoneypotPlugin(ordinance.ext.plugin.OrdinancePlugin):
    """
    Spawns a honeypot on given ports. Can ban on connect automatically, or just
    send an alert.
    """
    def __init__(self, config: Dict[str, Any]):
        # read configs
        self.ban_immediately: bool = config['ban_on_connect']
        self.autoaccept: bool = config['add_iptables_accept_rules']
        self.ban_message: str = config['message']
        self.interface: str = config['server']['interface']
        self.tcp_ports: List[int] = config['server']['tcp_ports']
        self.udp_ports: List[int] = config['server']['udp_ports']
        ordinance.writer.debug(f"Honeypot: Listening on tcp ports: ", self.tcp_ports)
        ordinance.writer.debug(f"Honeypot: Listening on udp ports: ", self.udp_ports)
        # thread refs, for join()ing at the end
        self.tcp_threads: Dict[int, ServerThread] = {}
        self.udp_threads: Dict[int, ServerThread] = {}
        # for communicating with and instancing socketserver
        SocketListener.plugininstance = self
        self.ban_lock = threading.Lock()
        ordinance.writer.info("Honeypot: Initialized.")
    
    @ordinance.ext.schedule.run_at_startup()
    def setup(self):
        # start socket threads
        for tport in self.tcp_ports:
            self.tcp_threads[tport] = ServerThread(self.autoaccept, "tcp", tport, self.interface)
            self.tcp_threads[tport].start()
        for uport in self.udp_ports:
            self.udp_threads[uport] = ServerThread(self.autoaccept, "udp", uport, self.interface)
            self.udp_threads[uport].start()
        ordinance.writer.info("Honeypot: Set up.")
    
    @ordinance.ext.schedule.run_at_shutdown()
    def close(self):
        ordinance.writer.info("Honeypot: Stopping server threads...")
        for th in self.tcp_threads.values():
                # this is evil and illegal but hey idc. im not
                # waiting for every server to synchronously
                # shut down, that will take >2sec per server.
                th.server._BaseServer__shutdown_request = True
        for th in self.udp_threads.values():
                th.server._BaseServer__shutdown_request = True
        time.sleep(2)  # wait for shutdowns to register (takes at most 2 seconds)
        # join threads
        for port,thread in self.tcp_threads.items():
            thread.server.shutdown()  # wait for server to join
            thread.join()
        for port,thread in self.udp_threads.items():
            thread.server.shutdown()  # wait for server to join
            thread.join()
        ordinance.writer.info("Honeypot: Stopped.")
    
    def async_ban(self, ip: str):
        """ Called from ThreadingServer; must be threadsafe. """
        with self.ban_lock:
            ordinance.writer.success(f"Banning ip {ip}...")
            ordinance.ext.network.blacklist(ip, comment="HONEYPOT")
    
    def async_alert(self, ip: str, port: str):
        """ Called from ThreadingServer; must be threadsafe. """
        # writers are threadsafe by virtue of their implementation, so theres
        # nothing special to worry about  :)
        ordinance.writer.alert(self.ban_message \
            .replace("%ip%", ip) \
            .replace("%port%", port))


def setup(config):
    return HoneypotPlugin(config)
