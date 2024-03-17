import time
import socket
import socketserver
import threading
import collections
import random
import os

from typing import List, Dict, Any

import ordinance

plugin_whitelist = collections.deque()

class SocketListener(socketserver.BaseRequestHandler):
    def __init__(self, request: Any, client_address: Any, server: socketserver.BaseServer):
        super().__init__(request, client_address, server)

    def handle(self):
        # try grabbing connection info (shouldnt fail?)
        try:
            ip = str(self.client_address[0])
            port = str(self.server.server_address[1])
            ordinance.writer.alert(f"Honeypot: Detected incoming connection from {ip} to port {port}")
        except Exception as e:
            ordinance.writer.warn(f"Honeypot: Error occurred while handling foreign connection: ", e)
            return

        try:
            if ip in ordinance.network.whitelist:
                ordinance.writer.info(f"Ignoring connection from Ordinance-whitelisted ip {ip}, port {port}")
                return
            elif ip in plugin_whitelist:
                ordinance.writer.info(f"Ignoring connection from plugin-whitelisted ip {ip}, port {port}")
                return
        except: pass  # couldn't be type-casted to valid ip. oh well
        
        try:
            if self.send_garbage:
                ordinance.writer.info(f"Honeypot: Sending garbage bytes to {ip} on port {port}")
                # kindly generate random garbage for attacker
                length = random.randint(500, 30000)
                fake_string = os.urandom(length)
                # send garbage data
                try:
                    if isinstance(self.request, socket.socket):
                        self.request.send(fake_string)
                    else:
                        print(self.request)
                        ordinance.writer.error(f"Honeypot: Incoming connection from {ip} port {port} isn't a socket")
                except Exception as e:
                    ordinance.writer.warn(f"Honeypot: Unable to send data to {ip} from port {port}, with e:", e)
            
            # close socket
            try:
                self.request.close()
            except Exception as e:
                ordinance.writer.warn(f"Honeypot: Unable to properly close connection from {ip} on port {port}, with e:", e)

            if ordinance.network.is_valid_ipv4(ip):
                # alert of and ban foreign connection
                ordinance.writer.alert("Honeypot: " + self.ban_message \
                    .replace("%ip%", ip) \
                    .replace("%port%", port))
                ordinance.writer.success(f"Honeypot: Banning ip {ip}.")
                ordinance.network.blacklist.add(ip)
            else:
                ordinance.writer.error(f"Honeypot: Incoming connection IP '{ip}' not a valid IPv4, doing nothing...")
        
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
            ordinance.network.create_iptables_rule(
                rule_type='ACCEPT',
                port_type=self.__con_type,
                port=self.__port)
        # bind server
        self.server = None
        num_attempts = 0
        while num_attempts < 5 and self.server is None:
            try:
                num_attempts += 1
                if self.__con_type == 'tcp':
                    self.server = socketserver.ThreadingTCPServer(
                        (self.__interface, self.__port), SocketListener)
                else: # __con_type == 'udp'
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
            # shutdown() called, since serve_forever() returned. close ports
            if self.__autoaccept:
                ordinance.network.delete_iptables_rule(
                    rule_type='ACCEPT',
                    port_type=self.__con_type,
                    port=self.__port)


class HoneypotPlugin(ordinance.plugin.OrdinancePlugin):
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
        self.send_garbage: bool = config['send_garbage_data']
        ordinance.writer.debug(f"Honeypot: Listening on tcp ports: ", self.tcp_ports)
        ordinance.writer.debug(f"Honeypot: Listening on udp ports: ", self.udp_ports)
        # thread refs, for join()ing at the end
        self.tcp_threads: Dict[int, ServerThread] = {}
        self.udp_threads: Dict[int, ServerThread] = {}
        # set plugin whitelist from config
        plugin_whitelist.extend(config['whitelist'])
        ordinance.writer.debug(f"Honeypot: Plugin whitelist: ", plugin_whitelist)
        # done!
        ordinance.writer.info("Honeypot: Initialized.")
    
    @ordinance.schedule.run_at_plugin_start()
    def setup(self):
        # start socket threads
        for tport in self.tcp_ports:
            self.tcp_threads[tport] = ServerThread(self.autoaccept, "tcp", tport, self.interface)
            self.tcp_threads[tport].start()
        for uport in self.udp_ports:
            self.udp_threads[uport] = ServerThread(self.autoaccept, "udp", uport, self.interface)
            self.udp_threads[uport].start()
        ordinance.writer.info("Honeypot: Set up.")
    
    @ordinance.schedule.run_at_plugin_stop()
    def close(self):
        ordinance.writer.info("Honeypot: Stopping server threads...")
        for th in self.tcp_threads.values():
            # this is evil and illegal but hey idc. im not
            # waiting for every server to synchronously
            # shut down, that will take >2sec per server.
            th.server._BaseServer__shutdown_request = True
        for th in self.udp_threads.values():
            th.server._BaseServer__shutdown_request = True
        time.sleep(2)  # wait for shutdowns to register (takes at most 2 seconds (poll interval is 2 seconds))
        # send shutdown requests (starts cleanup process)
        for thread in self.tcp_threads.values():
            thread.server.shutdown()
        for thread in self.udp_threads.values():
            thread.server.shutdown()
        # join threads
        for thread in self.tcp_threads.values():
            thread.join()
        for thread in self.udp_threads.values():
            thread.join()
        # done!
        ordinance.writer.info("Honeypot: Stopped.")


def setup():
    return HoneypotPlugin
