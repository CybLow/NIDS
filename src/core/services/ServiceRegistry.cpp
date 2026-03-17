#include "core/services/ServiceRegistry.h"

namespace nids::core {

ServiceRegistry::ServiceRegistry()
    : portToService_{
          {uint16_t{7}, "Echo"},
          {uint16_t{20}, "FTP-data"},
          {uint16_t{21}, "FTP"},
          {uint16_t{22}, "SSH/SCP/SFTP"},
          {uint16_t{23}, "Telnet"},
          {uint16_t{25}, "SMTP"},
          {uint16_t{53}, "DNS"},
          {uint16_t{67}, "DHCP/BOOTP Server"},
          {uint16_t{68}, "DHCP/BOOTP Client"},
          {uint16_t{69}, "TFTP"},
          {uint16_t{80}, "HTTP"},
          {uint16_t{88}, "Kerberos"},
          {uint16_t{110}, "POP3"},
          {uint16_t{123}, "NTP"},
          {uint16_t{137}, "NetBIOS Name Service"},
          {uint16_t{138}, "NetBIOS Datagram Service"},
          {uint16_t{139}, "NetBIOS Session Service"},
          {uint16_t{143}, "IMAP"},
          {uint16_t{161}, "SNMP"},
          {uint16_t{194}, "IRC"},
          {uint16_t{389}, "LDAP"},
          {uint16_t{443}, "HTTPS"},
          {uint16_t{445}, "Microsoft DS SMB"},
          {uint16_t{464}, "Kerberos"},
          {uint16_t{547}, "DHCPv6"},
          {uint16_t{596}, "SMSD"},
          {uint16_t{636}, "LDAP over SSL"},
          {uint16_t{1025}, "Microsoft RPC"},
          {uint16_t{1080}, "SOCKS Proxy"},
          {uint16_t{1194}, "OpenVPN"},
          {uint16_t{1241}, "Nessus"},
          {uint16_t{1311}, "Dell OpenManage"},
          {uint16_t{1337}, "WASTE"},
          {uint16_t{1589}, "Cisco VQP"},
          {uint16_t{1701}, "L2TP VPN"},
          {uint16_t{1720}, "H.323"},
          {uint16_t{1723}, "Microsoft PPTP"},
          {uint16_t{1725}, "Steam"},
          {uint16_t{1755}, "MMS"},
          {uint16_t{1812}, "RADIUS Authentication"},
          {uint16_t{1813}, "RADIUS Accounting"},
          {uint16_t{1863}, "MSN Messenger"},
          {uint16_t{1900}, "UPnP"},
          {uint16_t{1985}, "Cisco HSRP"},
          {uint16_t{2000}, "Cisco SCCP"},
          {uint16_t{2049}, "NFS"},
          {uint16_t{2082}, "cPanel"},
          {uint16_t{2083}, "cPanel SSL"},
          {uint16_t{2100}, "amiganetfs"},
          {uint16_t{2222}, "DirectAdmin"},
          {uint16_t{2302}, "HALO"},
          {uint16_t{2483}, "Oracle DB"},
          {uint16_t{2484}, "Oracle DB SSL"},
          {uint16_t{2745}, "Bagle.H"},
          {uint16_t{2967}, "Symantec AV"},
          {uint16_t{3050}, "Interbase DB"},
          {uint16_t{3074}, "XBOX Live"},
          {uint16_t{3127}, "MyDoom"},
          {uint16_t{3128}, "HTTP Proxy"},
          {uint16_t{3222}, "GLBP"},
          {uint16_t{3260}, "iSCSI Target"},
          {uint16_t{3306}, "MySQL"},
          {uint16_t{3389}, "RDP"},
          {uint16_t{3689}, "DAAP"},
          {uint16_t{3690}, "SVN"},
          {uint16_t{3724}, "World of Warcraft"},
          {uint16_t{3784}, "Ventrilo"},
          {uint16_t{4333}, "mSQL"},
          {uint16_t{4444}, "Blaster Worm"},
          {uint16_t{4500}, "IPSec NAT Traversal"},
          {uint16_t{4664}, "Google Desktop"},
          {uint16_t{4672}, "eMule"},
          {uint16_t{4899}, "Radmin"},
          {uint16_t{5000}, "UPnP"},
          {uint16_t{5001}, "iperf"},
          {uint16_t{5004}, "RTP"},
          {uint16_t{5050}, "Yahoo! Messenger"},
          {uint16_t{5060}, "SIP"},
          {uint16_t{5061}, "SIP over TLS"},
          {uint16_t{5190}, "AIM/ICQ"},
          {uint16_t{5222}, "XMPP"},
          {uint16_t{5223}, "XMPP over SSL"},
          {uint16_t{5353}, "MDNS"},
          {uint16_t{5432}, "PostgreSQL"},
          {uint16_t{5554}, "Sasser"},
          {uint16_t{5631}, "pcAnywhere"},
          {uint16_t{5800}, "VNC over HTTP"},
          {uint16_t{5900}, "VNC"},
          {uint16_t{6000}, "X11"},
          {uint16_t{6112}, "Diablo"},
          {uint16_t{6129}, "DameWare"},
          {uint16_t{6257}, "WinMX"},
          {uint16_t{6346}, "Gnutella"},
          {uint16_t{6379}, "Redis"},
          {uint16_t{6500}, "GameSpy"},
          {uint16_t{6566}, "SANE"},
          {uint16_t{6588}, "AnalogX"},
          {uint16_t{6665}, "IRC"},
          {uint16_t{6679}, "IRC over SSL"},
          {uint16_t{6699}, "Napster"},
          {uint16_t{6881}, "BitTorrent"},
          {uint16_t{6891}, "Windows Live Messenger"},
          {uint16_t{6970}, "Quicktime"},
          {uint16_t{7000}, "Cassandra"},
          {uint16_t{7001}, "Cassandra SSL"},
          {uint16_t{7199}, "Cassandra JMX"},
          {uint16_t{7648}, "CU-SeeMe"},
          {uint16_t{8000}, "Internet Radio"},
          {uint16_t{8080}, "HTTP Proxy"},
          {uint16_t{8086}, "Kaspersky AV"},
          {uint16_t{8087}, "Kaspersky AV"},
          {uint16_t{8118}, "Privoxy"},
          {uint16_t{8200}, "VMware Server"},
          {uint16_t{8222}, "VMware Server"},
          {uint16_t{8500}, "Adobe ColdFusion"},
          {uint16_t{8767}, "Teamspeak"},
          {uint16_t{8866}, "Bagle.B"},
          {uint16_t{9042}, "Cassandra"},
          {uint16_t{9100}, "PDL Data Stream"},
          {uint16_t{9101}, "Bacula"},
          {uint16_t{9119}, "MXit"},
          {uint16_t{9800}, "WebDAV"},
          {uint16_t{9898}, "Dabber Worm"},
          {uint16_t{9999}, "Urchin"},
          {uint16_t{10000}, "Network Data Management Protocol"},
          {uint16_t{10113}, "NetIQ"},
          {uint16_t{10114}, "NetIQ Qcheck"},
          {uint16_t{10115}, "NetIQ Endpoint"},
          {uint16_t{10116}, "NetIQ VoIP Assessor"},
          {uint16_t{10161}, "SNMP-agents (encrypted)"},
          {uint16_t{10162}, "SNMP-trap (encrypted)"},
          {uint16_t{11371}, "OpenPGP HTTP Keyserver"},
          {uint16_t{12345}, "NetBus"},
          {uint16_t{13720}, "NetBackup"},
          {uint16_t{14567}, "Battlefield"},
          {uint16_t{15118}, "Dipnet/Oddbob"},
          {uint16_t{19226}, "AdminSecure"},
          {uint16_t{19638}, "Ensim"},
          {uint16_t{20000}, "Usermin"},
          {uint16_t{24800}, "Synergy"},
          {uint16_t{25999}, "Xfire"},
          {uint16_t{27015}, "Half-Life"},
          {uint16_t{27017}, "MongoDB"},
          {uint16_t{27374}, "Sub7"},
          {uint16_t{28960}, "Call of Duty"},
          {uint16_t{31337}, "Back Orifice"},
          {uint16_t{33434}, "traceroute"},
      } {}

std::string ServiceRegistry::getServiceByPort(std::uint16_t port) const {
  if (auto it = portToService_.find(port); it != portToService_.end()) {
    return it->second;
  }
  return "Unknown";
}

std::unordered_set<std::string> ServiceRegistry::getUniqueServices() const {
  std::unordered_set<std::string> services;
  for (const auto &[port, name] : portToService_) {
    services.insert(name);
  }
  return services;
}

std::string
ServiceRegistry::resolveApplication(std::uint16_t filterSrcPort,
                                    std::uint16_t filterDstPort,
                                    std::uint16_t packetDstPort) const {
  if (filterDstPort != 0) {
    return getServiceByPort(filterDstPort);
  }
  if (filterSrcPort != 0) {
    return getServiceByPort(filterSrcPort);
  }
  if (packetDstPort != 0) {
    return getServiceByPort(packetDstPort);
  }
  return "Unknown";
}

} // namespace nids::core
