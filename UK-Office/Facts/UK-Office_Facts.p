attackGoal(compromisedVPNClient('intergalactic-hacker','alpine-3.18-openvpn-1')).


dataFlow('uk-site-internet', 'internet', _FlowName, _Direction).
dataFlow('intergalactic-vpn-gw-internet', 'internet', _FlowName, _Direction).
dataFlow('intergalactic-hacker-internet', 'internet', _FlowName, _Direction).
dataFlow('Core-Switch', 'MainRouter', _FlowName, _Direction).
dataFlow('Core-Switch', 'VoIP-Switch', _FlowName, _Direction).
dataFlow('Core-Switch', 'HP-2560A', _FlowName, _Direction).
dataFlow('Core-Switch', 'ADMIN', _FlowName, _Direction).
dataFlow('Core-Switch', 'PAXTON', _FlowName, _Direction).
dataFlow('MainRouter', 'uk-site-internet', _FlowName, _Direction).
dataFlow('VoIP-Switch', 'AP-Controller', _FlowName, _Direction).
dataFlow('AP-Controller', 'DEV3', _FlowName, _Direction).
dataFlow('AP-Controller', 'FLE4N', _FlowName, _Direction).
dataFlow('FLE4N', 'alpine-3.18-openvpn-1', _FlowName, _Direction).
dataFlow('FLE4N', 'storage-server-1', _FlowName, _Direction).
dataFlow('intergalactic-vpn-gw-internet', 'intergalactic-vpn', _FlowName, _Direction).
dataFlow('intergalactic-hacker-internet', 'intergalactic-hacker', _FlowName, _Direction).
dataFlow('PC1-1', 'HP-2560A', _FlowName, _Direction).
dataFlow('PC1-4', 'HP-2560A', _FlowName, _Direction).
dataFlow('PC3-6', 'HP-2650D', _FlowName, _Direction).
dataFlow('PC2-2', 'HP-2650D1', _FlowName, _Direction).
dataFlow('PC3-3', 'HP-2650D', _FlowName, _Direction).
dataFlow('PC1-5', 'HP-2560A', _FlowName, _Direction).
dataFlow('HP-2560A', 'HP-2650D1', _FlowName, _Direction).
dataFlow('HP-2560A', 'PC1-3', _FlowName, _Direction).
dataFlow('HP-2560A', 'PC1-6', _FlowName, _Direction).
dataFlow('HP-2560A', 'PC1-2', _FlowName, _Direction).
dataFlow('HP-2560A', 'PC1-8', _FlowName, _Direction).
dataFlow('HP-2560A', 'PC1-9', _FlowName, _Direction).
dataFlow('HP-2560A', 'PC1-10', _FlowName, _Direction).
dataFlow('HP-2560A', 'PC1-7', _FlowName, _Direction).
dataFlow('HP-2650D1', 'HP-2650D', _FlowName, _Direction).
dataFlow('HP-2650D1', 'PC2-4', _FlowName, _Direction).
dataFlow('HP-2650D1', 'PC2-3', _FlowName, _Direction).
dataFlow('HP-2650D1', 'PC2-6', _FlowName, _Direction).
dataFlow('HP-2650D1', 'PC2-1', _FlowName, _Direction).
dataFlow('HP-2650D1', 'PC2-5', _FlowName, _Direction).
dataFlow('HP-2650D1', 'PC2-7', _FlowName, _Direction).
dataFlow('HP-2650D1', 'PC2-8', _FlowName, _Direction).
dataFlow('HP-2650D1', 'PC2-9', _FlowName, _Direction).
dataFlow('HP-2650D1', 'PC2-10', _FlowName, _Direction).
dataFlow('HP-2650D', 'PC3-5', _FlowName, _Direction).
dataFlow('HP-2650D', 'PC3-4', _FlowName, _Direction).
dataFlow('HP-2650D', 'PC3-2', _FlowName, _Direction).
dataFlow('HP-2650D', 'PC3-1', _FlowName, _Direction).
dataFlow('HP-2650D', 'OpenvSwitch-Servers', _FlowName, _Direction).
dataFlow('HP-2650D', 'PC3-7', _FlowName, _Direction).
dataFlow('HP-2650D', 'PC3-8', _FlowName, _Direction).
dataFlow('HP-2650D', 'PC3-9', _FlowName, _Direction).
dataFlow('HP-2650D', 'PC3-10', _FlowName, _Direction).
dataFlow('OpenvSwitch-Servers', 'wordpress', _FlowName, _Direction).
dataFlow('OpenvSwitch-Servers', 'devStorage', _FlowName, _Direction).
dataFlow('OpenvSwitch-Servers', 'devPC1', _FlowName, _Direction).
dataFlow('OpenvSwitch-Servers', 'devPC2', _FlowName, _Direction).
dataFlow('OpenvSwitch-Servers', 'devPC3', _FlowName, _Direction).
dataFlow('OpenvSwitch-Servers', 'devPC4', _FlowName, _Direction).
dataFlow('OpenvSwitch-Servers', 'devPC5', _FlowName, _Direction).
isInSubnet('Core-Switch', 'MainRouter').
isInSubnet('Core-Switch', 'VoIP-Switch').
isInSubnet('VoIP-Switch', 'Core-Switch').
isInSubnet('Core-Switch', 'HP-2560A').
isInSubnet('HP-2560A', 'Core-Switch').
isInSubnet('Core-Switch', 'ADMIN').
isInSubnet('Core-Switch', 'PAXTON').
isInSubnet('VoIP-Switch', 'AP-Controller').
isInSubnet('AP-Controller', 'VoIP-Switch').
isInSubnet('AP-Controller', 'DEV3').
isInSubnet('DEV3', 'AP-Controller').
isInSubnet('AP-Controller', 'FLE4N').
isInSubnet('FLE4N', 'AP-Controller').
isInSubnet('FLE4N', 'alpine-3.18-openvpn-1').
isInSubnet('FLE4N', 'storage-server-1').
isInSubnet('HP-2560A', 'PC1-1').
isInSubnet('HP-2560A', 'PC1-4').
isInSubnet('HP-2650D', 'PC3-6').
isInSubnet('HP-2650D1', 'PC2-2').
isInSubnet('HP-2650D', 'PC3-3').
isInSubnet('HP-2560A', 'PC1-5').
isInSubnet('HP-2560A', 'HP-2650D1').
isInSubnet('HP-2650D1', 'HP-2560A').
isInSubnet('HP-2560A', 'PC1-3').
isInSubnet('HP-2560A', 'PC1-6').
isInSubnet('HP-2560A', 'PC1-2').
isInSubnet('HP-2560A', 'PC1-8').
isInSubnet('HP-2560A', 'PC1-9').
isInSubnet('HP-2560A', 'PC1-10').
isInSubnet('HP-2560A', 'PC1-7').
isInSubnet('HP-2650D1', 'HP-2650D').
isInSubnet('HP-2650D', 'HP-2650D1').
isInSubnet('HP-2650D1', 'PC2-4').
isInSubnet('HP-2650D1', 'PC2-3').
isInSubnet('HP-2650D1', 'PC2-6').
isInSubnet('HP-2650D1', 'PC2-1').
isInSubnet('HP-2650D1', 'PC2-5').
isInSubnet('HP-2650D1', 'PC2-7').
isInSubnet('HP-2650D1', 'PC2-8').
isInSubnet('HP-2650D1', 'PC2-9').
isInSubnet('HP-2650D1', 'PC2-10').
isInSubnet('HP-2650D', 'PC3-5').
isInSubnet('HP-2650D', 'PC3-4').
isInSubnet('HP-2650D', 'PC3-2').
isInSubnet('HP-2650D', 'PC3-1').
isInSubnet('HP-2650D', 'OpenvSwitch-Servers').
isInSubnet('OpenvSwitch-Servers', 'HP-2650D').
isInSubnet('HP-2650D', 'PC3-7').
isInSubnet('HP-2650D', 'PC3-8').
isInSubnet('HP-2650D', 'PC3-9').
isInSubnet('HP-2650D', 'PC3-10').
isInSubnet('OpenvSwitch-Servers', 'wordpress').
isInSubnet('OpenvSwitch-Servers', 'devStorage').
isInSubnet('OpenvSwitch-Servers', 'devPC1').
isInSubnet('OpenvSwitch-Servers', 'devPC2').
isInSubnet('OpenvSwitch-Servers', 'devPC3').
isInSubnet('OpenvSwitch-Servers', 'devPC4').
isInSubnet('OpenvSwitch-Servers', 'devPC5').
malicious('attacker').
malicious('hacker').
dataBind(Flow, 'intergalactic-vpn', Path1).
dataBind(Flow, 'intergalactic-hacker', Path1).
dataBind(Flow, 'intergalactic-vpn-internet', Path1).
dataBind(Flow, 'intergalactic-hacker-internet', Path1).
dataBind(Flow, 'uk-site-internet', Path1).
dataBind(Flow, 'MainRouter', Path1).
dataBind(Flow, 'Core-Switch', Path1).
dataBind(Flow, 'PAXTON', Path1).
dataBind(Flow, 'ADMIN', Path1).
dataBind(Flow, 'VoIP-Switch', Path1).
dataBind(Flow, 'HP-2560A', Path1).
dataBind(Flow, 'HP-2650D1', Path1).
dataBind(Flow, 'HP-2650D', Path1).
dataBind(Flow, 'AP-Controller', Path1).
dataBind(Flow, 'DEV3', Path1).
dataBind(Flow, 'FLE4N', Path1).
dataBind(Flow, 'alpine-3.18-openvpn-1', Path1).
dataBind(Flow, 'storage-server-1', Path1).
maliciousInteraction('intergalactic-vpn', _, 'intergalactic-web-ui').
maliciousInteraction('AP-Controller', _, _).
maliciousInteraction('ADMIN', _, _).
maliciousInteraction('PAXTON', _, _).
maliciousInteraction('alpine-3.18-openvpn-1', _, _).
maliciousInteraction('storage-server-1', _, _).
dataFlow('intergalactic-vpn', 'alpine-3.18-openvpn-1').
dataFlow('alpine-3.18-openvpn-1', 'intergalactic-vpn').
isInSubnet('vpn', 'alpine-3.18-openvpn-1').
isInSubnet('vlan', 'storage-server-1').

hacl('Core-Switch', _, _, _).
hacl('MainRouter', _, _, _).
hacl('uk-site-internet', _, _, _).
hacl('VoIP-Switch', _, _, _).
hacl('AP-Controller', _, _, _).
hacl('FLE4N', _, _, _).
hacl('intergalactic-vpn-gw-internet', _, _, _).
hacl('intergalactic-vpn', _, _, _).
hacl('intergalactic-hacker-internet', _, _, _).
hacl('alpine-3.18-openvpn-1', _, _, _).
hacl('storage-server-1', _, _, _).
hacl('intergalactic-hacker', _, _, _).
hacl('PC1-1', _, _, _).
hacl('PC1-4', _, _, _).
hacl('PC3-6', _, _, _).
hacl('PC2-2', _, _, _).
hacl('PC3-3', _, _, _).
hacl('PC1-5', _, _, _).
hacl('HP-2560A', _, _, _).
hacl('HP-2650D1', _, _, _).
hacl('HP-2650D', _, _, _).
hacl('PC1-3', _, _, _).
hacl('PC3-1', _, _, _).
hacl('PC2-3', _, _, _).
hacl('PC1-6', _, _, _).
hacl('PC1-2', _, _, _).
hacl('PC3-2', _, _, _).
hacl('PC3-5', _, _, _).
hacl('PC3-4', _, _, _).
hacl('PC2-5', _, _, _).
hacl('PC2-4', _, _, _).
hacl('PC2-1', _, _, _).
hacl('PC2-6', _, _, _).
hacl('PAXTON', _, _, _).
hacl('ADMIN', _, _, _).
hacl('DEV3', _, _, _).
hacl('OpenvSwitch-Servers', _, _, _).
hacl('wordpress', _, _, _).
hacl('devPC1', _, _, _).
hacl('devStorage', _, _, _).
hacl('devPC2', _, _, _).
hacl('devPC3', _, _, _).
hacl('devPC4', _, _, _).
hacl('devPC5', _, _, _).
hacl('PC1-7', _, _, _).
hacl('PC1-8', _, _, _).
hacl('PC1-10', _, _, _).
hacl('PC1-9', _, _, _).
hacl('PC2-7', _, _, _).
hacl('PC2-9', _, _, _).
hacl('PC2-8', _, _, _).
hacl('PC2-10', _, _, _).
hacl('PC3-7', _, _, _).
hacl('PC3-10', _, _, _).
hacl('PC3-8', _, _, _).
hacl('PC3-9', _, _, _).
networkService('intergalactic-vpn', 'intergalactic-web-ui', 'http', '80', 'root').
networkService('intergalactic-vpn', 'openVPN', 'udp', '1194', 'root').
networkService('alpine-3.18-openvpn-1', 'open-ssh', 'tcp', '22', 'user-account').
networkService('storage-server-1', 'sftpd', 'tcp', '22', 'user-storage-server-1-account').
networkService('intergalactic-vpn', 'open-ssh', 'tcp', '22', 'root').
networkService('intergalactic-hacker', 'open-ssh', 'tcp', '22', 'hacker').
networkService('intergalactic-hacker', 'intergalactic-web-ui', 'udp', '1194', 'hacker').
networkService('alpine-3.18-openvpn-1', 'intergalactic-web-ui', 'udp', '1194', 'alice').
networkService('MainRouter', 'fwMgmtUI', 'tcp', '443', 'fwAdmin').
networkService('Core-Switch', 'open-ssh', 'tcp', '22', 'coreAdmin').
networkService('HP-2560A', 'open-ssh', 'tcp', '22', 'hpAdmin').
networkService('HP-2650D1', 'open-ssh', 'tcp', '22', 'hpAdmin').
networkService('HP-2650D', 'open-ssh', 'tcp', '22', 'hpAdmin').
networkService('VoIP-Switch', 'open-ssh', 'tcp', '443', 'voipAdmin').
networkService('AP-Controller', 'open-ssh', 'tcp', '80', 'apcAdmin').
networkService('AP-Controller', 'open-ssh', 'tcp', '443', 'apcAdmin').
networkService('ADMIN', 'open-ssh', 'tcp', '22', 'localAdmin').
networkService('PAXTON', 'open-ssh', 'tcp', '22', 'paxUser').
networkService('storage-server-1', 'sftpd', 'tcp', '22', 'user-storage-server-1-account').
hacl('alpine-3.18-openvpn-1', 'intergalactic-vpn', 'udp', '1194').
hacl('intergalactic-hacker', 'intergalactic-vpn', 'udp', '1194').
hacl('intergalactic-hacker', 'intergalactic-vpn', 'open-ssh', '22').
hacl('MainRouter', 'uk-site-internet', 'http', '80').
hasAccount('root', 'intergalactic-vpn', 'operating-system-administration-account').
hasAccount('alice', 'alpine-3.18-openvpn-1', 'user-account').
hasAccount('alice', 'storage-server-1', 'user-storage-server-1-account').
hasAccount('hacker', 'intergalactic-hacker', 'user-account').
hasAccess(_, 'intergalactic-hacker', 'intergalactic-vpn', 'udp', '1194').
hasAccess(_, 'intergalactic-hacker', 'intergalactic-vpn', 'http', '80').
hasAccess('alice', 'alpine-3.18-openvpn-1', 'intergalactic-vpn', 'udp', '1194').
located('intergalactic-vpn-internet', 'outsideNet', 'External/WAN').
located('intergalactic-hacker-internet', 'outsideNet', 'External/WAN').
located('intergalactic-hacker', 'outsideNet', 'External/WAN').
located('uk-site-internet', 'outsideNet', 'External/WAN').
located('MainRouter', 'outsideNet', 'WAN-Link').
located('MainRouter', 'insideNet', 'DMZ/Perimeter').
located('Core-Switch', 'insideNet', 'LAN').
located('Core-Switch', 'insideNet', 'LAN/Core').
located('HP-2560A', 'hpNet', 'LAN/AccessEdge').
located('HP-2650D1', 'hpNet', 'LAN/AccessEdge').
located('HP-2650D', 'hpNet', 'LAN/AccessEdge').
located('VoIP-Switch', 'voiceNet', 'VoiceVLAN').
located('AP-Controller', 'wifiCtrlNet', 'WirelessControl').
located('DEV3', 'wifiNet', 'WirelessClient').
located('FLE4N', 'wifiNet', 'WirelessClient').
located('alpine-3.18-openvpn-1', 'labNet', 'LabNetwork').
located('storage-server-1', 'labNet', 'LabNetwork').
located('ADMIN', 'insideNet', 'LAN/Workstation').
located('PAXTON', 'insideNet', 'LAN/Workstation').
fileOwner('intergalactic-vpn', './etc/shr', 'root').
fileOwner('intergalactic-vpn', 'intergalactic-web-ui', 'root').
fileOwner('intergalactic-vpn', 'intergalactic-web-ui', 'hacker').
fileOwner('intergalactic-vpn', './etc/shr', 'hacker').
fileOwner('alpine-3.18-openvpn-1', './etc/shr', 'alice').
fileOwner('alpine-3.18-openvpn-1', './etc/shr', 'alice-storage-server-1').
fileOwner('AP-Controller', _, 'root').
fileOwner('ADMIN', _, 'root').
fileOwner('PAXTON', _, 'root').
fileOwner('storage-server-1', _, 'root').
ownerAccessible('intergalactic-vpn', 'read', './etc/shr').
ownerAccessible('intergalactic-vpn', 'write', './etc/shr').
ownerAccessible('intergalactic-vpn', 'read', 'intergalactic-web-ui').
ownerAccessible('intergalactic-vpn', 'write', 'intergalactic-web-ui').
ownerAccessible('intergalactic-vpn', 'read', './etc/shr').
ownerAccessible('alpine-3.18-openvpn-1', 'read', './etc/shr').
ownerAccessible('alpine-3.18-openvpn-1', 'write', './etc/shr').
ownerAccessible('AP-Controller', 'read', _).
ownerAccessible('ADMIN', 'read', _).
ownerAccessible('PAXTON', 'read', _).
ownerAccessible('storage-server-1', 'read', _).
allows('intergalactic-vpn', 'hacker', _, _, '200').
allows('intergalactic-vpn', 'alice', _, _, '200').
setUIDProgram('intergalactic-vpn', 'intergalactic-web-ui', _).
installed('intergalactic-vpn', 'intergalactic-web-ui', '0.1.0rc0').
canInvoke('intergalactic-web-ui', _, 'keylogging').
accessFile('root', 'intergalactic-vpn', 'write', _).
isNameResolver(_, 'intergalactic-vpn', 'intergalactic-hacker').
isNameResolver(_, 'intergalactic-hacker', 'intergalactic-vpn').
vulE2EProtocol('intergalactic-vpn', _, 'dnsCachePoisoning', 'DNSProt', 'remoteExploit', 'nameresolverCachePoisoned').
localService('intergalactic-vpn', 'intergalactic-vpn', _).
deviceOnline('Core-Switch', _Platform).
deviceOnline('MainRouter', _Platform).
deviceOnline('uk-site-internet', _Platform).
deviceOnline('VoIP-Switch', _Platform).
deviceOnline('AP-Controller', _Platform).
deviceOnline('FLE4N', _Platform).
deviceOnline('intergalactic-vpn-gw-internet', _Platform).
deviceOnline('intergalactic-vpn', _Platform).
deviceOnline('intergalactic-hacker-internet', _Platform).
deviceOnline('alpine-3.18-openvpn-1', _Platform).
deviceOnline('storage-server-1', 'ubuntu').
deviceOnline('intergalactic-hacker', _Platform).
deviceOnline('PC1-1', _Platform).
deviceOnline('PC1-4', _Platform).
deviceOnline('PC3-6', _Platform).
deviceOnline('PC2-2', _Platform).
deviceOnline('PC3-3', _Platform).
deviceOnline('PC1-5', _Platform).
deviceOnline('HP-2560A', _Platform).
deviceOnline('HP-2650D1', _Platform).
deviceOnline('HP-2650D', _Platform).
deviceOnline('PC1-3', _Platform).
deviceOnline('PC3-1', _Platform).
deviceOnline('PC2-3', _Platform).
deviceOnline('PC1-6', _Platform).
deviceOnline('PC1-2', _Platform).
deviceOnline('PC3-2', _Platform).
deviceOnline('PC3-5', _Platform).
deviceOnline('PC3-4', _Platform).
deviceOnline('PC2-5', _Platform).
deviceOnline('PC2-4', _Platform).
deviceOnline('PC2-1', _Platform).
deviceOnline('PC2-6', _Platform).
deviceOnline('PAXTON', _Platform).
deviceOnline('ADMIN', _Platform).
deviceOnline('DEV3', _Platform).
deviceOnline('OpenvSwitch-Servers', _Platform).
deviceOnline('wordpress', _Platform).
deviceOnline('devPC1', _Platform).
deviceOnline('devStorage', _Platform).
deviceOnline('devPC2', _Platform).
deviceOnline('devPC3', _Platform).
deviceOnline('devPC4', _Platform).
deviceOnline('devPC5', _Platform).
deviceOnline('PC1-7', _Platform).
deviceOnline('PC1-8', _Platform).
deviceOnline('PC1-10', _Platform).
deviceOnline('PC1-9', _Platform).
deviceOnline('PC2-7', _Platform).
deviceOnline('PC2-9', _Platform).
deviceOnline('PC2-8', _Platform).
deviceOnline('PC2-10', _Platform).
deviceOnline('PC3-7', _Platform).
deviceOnline('PC3-10', _Platform).
deviceOnline('PC3-8', _Platform).
deviceOnline('PC3-9', _Platform).

residesOn('intergalactic-vpn', 'intergalactic-web-ui', '0.1.0rc0').
residesOn('intergalactic-vpn', 'openVPN', '2.4.12').
residesOn('alpine-3.18-openvpn-1', 'open-ssh', 'v1.0').
residesOn('storage-server-1', 'sftpd', 'v1.0').
vulExists('cve-2023-27524', 'intergalactic-web-ui', '0.1.0rc0', 'network', 'ca_loss', 'critical').
vulExists('cve-zero-day-web-ui-execute-code-1337', 'intergalactic-web-ui', '0.1.0rc0', 'local', 'privilege_escalation', 'critical').



located(_SrcHost, _SrcSubnet, _SubnetType).
located(_DstHost, _DstSubnet, _SubnetType).
located(_DstHost, _DstSubnet, _SubnetType).
located(_SrcHost, _SrcSubnet, _SubnetType).
located(_SrcHost, _Subnet, _SubnetType).
located(_DstHost, _Subnet, _SubnetType).
hasAccess(_User, _AttackSrc, _Host, _Protocol, _Port).
dataFlow(_Host1, _Host2, _FlowName, _Direction).
networkService(_DstHost, _Software, _Prot, _Port, _NetServiceAccount).
vulExists(_CveId, _Software, _Version, _LocalNetwork, _lose_types, 'critical').
malicious(_User).
networkService(_DstHost, _Software, _Prot, _Port, _NetServiceAccount).
residesOn(_Host, _Software, _Version).
vulExists(_CveId, _Software, _Version, _LocalNetwork, _lose_types, 'critical').
malicious(_User).
localService(_Host, _Software, _Account).
vulExists(_CveId, _Software, _Version, _LocalNetwork, _lose_types, 'critical').
malicious(_User).
dataBind(_Flow, _SrcHost, _Path1).
dataFlow(_SrcHost, _DstHost, _Flow, _Direction).
dataBind(_Flow, _DstHost, _Path2).
fileOwner(_Host, _Path, root).
ownerAccessible(_Host, read, _Path).
vulExists(_CveId, _Software, _Version, _LocalNetwork, _lose_types, critical).
deviceOnline(_Host, _Platform).
residesOn(_Host, _Software, _Version).
vulExists(_CveId, _Software, _Version, _RemoteNetwork, _lose_types, 'critical').
maliciousInteraction(_Host, _User, _Software).
networkService(_TargetHost, _Software, _Protocol, _Port, _Account).
residesOn(_TargetHost, _Software, _Version).
hasAccount(_User, _TargetHost, _Account).
isInSubnet(_Subnet, _IntermediateVPNHost).
isInSubnet(_Subnet, _TargetHost).
isInSubnet('vlan', _TargetHost).
networkService(_TargetHost, _Software, _Protocol, _Port, _Account).
residesOn(_TargetHost, _Software, _Version).
hasAccount(_User, _TargetHost, _Account).
networkService(_TargetHost, _Software, _Protocol, _Port, _Account).
residesOn(_TargetHost, _Software, _Version).
vulExists(_cve_id, _Software, _Version, _Network, _Lose_types, _Severity).
residesOn(_TargetHost, _Software, _Version).
hasAccount('root', _TargetHost, _Account).
vulExists(_cve_id, _Software, _Version, _LocalNetwork, _PrivilegeEscalation, _Severity).
residesOn(_TargetHost, 'intergalactic-web-ui', _Version).
isInSubnet('vpn', _TargetVPNHost).
networkService(_Host, _Software, _Protocol, _Port, _Account).
fileOwner(_Host, _Path, _Account).
ownerAccessible(_Host, 'read', _Path).
fileOwner(_Host, _Path, _Account).
ownerAccessible(_Host, 'write', _Path).
hasAccount(_Victim, _Host, _Account).
malicious(_Attacker).
residesOn(_Host, _Software, _Version).
vulExists(_CveId, _Software, _Version, _LocalNetwork, _lose_types, 'critical').
hacl(_SrcHost, _Host, _Protocol, _DestPort).
maliciousInteraction(_Host, _, _Software).
allows(_Host, _Attacker, _Operation, _Url, _Response).
malicious(_Attacker).
residesOn(_Host, _Software, _Version).
vulExists(_CveId, _Software, _Version, _LocalNetwork, _lose_types, critical).
installed(_Host, _Software, _Version).
isInSubnet(_Subnet, _Host).
setuidProgram(_Host, _Software, _Account).
malicious(_User).
installed(_Host, _Software, _Version).
setuidProgram(_Host, _Software, _Account).
installed(_Host, 'intergalactic-web-ui', _Version).
canInvoke('intergalactic-web-ui', _Software2, 'keylogging').
setuidProgram(_Host, 'intergalactic-web-ui', _Account).

