/******************************************************/
/****         Predicates Declaration              *****/
/******************************************************/

primitive(located(_srcHost, _srcSubnet, _subnetType)).
primitive(malicious(_user)).
primitive(localService(_host, _software, _account)).
primitive(dataBind(_flow, _srcHost, _path)).
primitive(dataFlow(_srcHost, _dstHost, _flow, _direction)).
primitive(deviceOnline(_host, _platform)).
primitive(maliciousInteraction(_host, _user, _software)).
primitive(vulE2EProtocol(_fooledHost, _nameResolver, _dnsAttackType, _protocol, _exploitRange, _loseTypes)).
primitive(isNameResolver(_nameResolver, _fooledHost, _impersonatedHost)).
primitive(fileOwner(_host, _path, _owner)).
primitive(vulExists(_cveId, _software, _version, _access_vector, _lose_types, _severity)).
primitive(ownerAccessible(_host, _permission, _path)).
primitive(hasAccount(_user, _host, _account)).
primitive(hacl(_src, _dst, _protocol, _port)).
primitive(allows(_host, _user, _operation, _url, _response)).
primitive(installed(_host, _software, _version)).
primitive(isInSubnet(_subnet, _host)).
primitive(setuidProgram(_host, _software, _account)).
primitive(networkService(_host, _software, _protocol, _port, _account)).
primitive(vulLinkProtocol(_wirelessRange, _vulID, _protocol, _exploitRange, _exploitConsequence)).
primitive(belongTo(_subnet, _virtualPort)).
primitive(canInvoke(_software1, _software2, _method)).
primitive(hasAccess(_user, _attackSrc, _host, _protocol, _port)).
primitive(residesOn(_host, _software, _version)).


derived(aclNW(_srcHost, _dstHost, _protocol, _port)).
derived(netAccessACL(_user, _srcHost, _dstHost, _protocol, _port)).
derived(netAccess(_user, _attHost, _host, _protocol, _port)).
derived(localAccess(_user, _dstHost, _account)).
derived(dataInject(_user, _dstHost, _path1, _path2)).
derived(accessFile(_user, _host, _permission, _path)).
derived(localFileProtection(_host, _account, _permission, _path)).
derived(execCode(_user, _host, _account)).
derived(compromised(_host)).
derived(accessFile(_user, _host, _permission, _path)).
derived(localFileProtection(_host, _account, _permission, _path)).
derived(principalCompromised(_victim, _host, _attacker)).
derived(leakInfo(_host, _file)).
derived(logInService(_host, _protocol, _port)).
derived(canAccessHost(_user, _host)).
derived(webShell(_software, _host, _attacker, _permission)).
derived(fileDeletion(_host, _software, _subnet, _attacker)).
derived(canDeleteDoc(_software, _victim, _host, _attacker)).
derived(archiveviaUtility(_software, _host, _account, _path)).
derived(keylogging(_host, _software1, _software2, _account)).
derived(disableorModifyTools(_user, _host, _software, _path, _permission, _account)).

derived(compromisedVPNClient(_hackerHost, _targetHost)).
derived(softwareCompromisedRemotely(_hackerHost, _targetHost)).
derived(softwareCompromisedLocally(_targetHost)).
derived(canCreateValidVPNCertificate(_hackerHost, _targetHost)).
derived(canAccessVPN(_hackerHost, _targetHost)).
derived(lateralMovementVPN(_hackerHost, _vpnServer, _targetVPNHost)).


meta(attackGoal(_)).

/******************************************************/
/****         Tabling Predicates                  *****/
/*   All derived predicates should be tabled          */
/******************************************************/

:- table aclNW/4.
:- table localAccess/3.
:- table netAccess/5.
:- table netAccessACL/5.
:- table dataInject/4.
:- table accessFile/4.
:- table localFileProtection/4.
:- table execCode/3.
:- table compromised/1.
:- table accessFile/4.
:- table localFileProtection/4.
:- table principalCompromised/3.
:- table leakInfo/2.
:- table logInService/3.
:- table canAccessHost/2.
:- table webShell/4.
:- table fileDeletion/4.
:- table canDeleteDoc/4.
:- table archiveviaUtility/4.
:- table keylogging/4.
:- table disableorModifyTools/6.

:- table compromisedVPNClient/2.
:- table softwareCompromisedRemotely/2.
:- table softwareCompromisedLocally/1.
:- table canCreateValidVPNCertificate/2.
:- table softwareCompromisedLocally/2.
:- table canAccessVPN/2.
:- table lateralMovementVPN/3.

/******************************************************/
/****         Interaction Rules                   *****/
/******************************************************/

/* Interaction Rules for T1021 - Remote Services: */
interaction_rule(
   (aclNW(SrcHost, DstHost, Prot, Port) :-
     located(SrcHost, SrcSubnet, SubnetType),
     located(DstHost, DstSubnet, SubnetType),
     aclNW(SrcSubnet, DstSubnet, Prot, Port)),
    rule_desc('Connectivity inter subnets', 1.0)).

interaction_rule(
   (aclNW(SrcHost, DstHost, Prot, Port) :-
     located(DstHost, DstSubnet, SubnetType),
     aclNW(SrcHost, DstSubnet, Prot, Port)),
    rule_desc('Connectivity from host to subnet', 1.0)).

interaction_rule(
   (aclNW(SrcHost, DstHost, Prot, Port) :-
     located(SrcHost, SrcSubnet, SubnetType),
     aclNW(SrcSubnet, DstHost, Prot, Port)),
    rule_desc('Connectivity from subnet to host', 1.0)).

interaction_rule(
   (aclNW(SrcHost, DstHost, _prot, _port) :-
     located(SrcHost, Subnet, SubnetType),
     located(DstHost, Subnet, SubnetType)),
    rule_desc('connectivity within a subnet', 1.0)).

interaction_rule(
   (netAccessACL(User, SrcHost, DstHost, Prot, Port) :-
     localAccess(User, SrcHost, _SrcAccount),
     aclNW(SrcHost, DstHost, Prot, Port)),
    rule_desc('', 1.0)).

interaction_rule(
  (netAccess(User, AttackSrc, Host, Protocol, Port) :-
    hasAccess(User, AttackSrc, Host, Protocol, Port)),
  rule_desc('Net direct access', 1.0)).

interaction_rule(
  (netAccess(User, AttackSrc, Host2, Protocol, Port) :-
    netAccess(User, AttackSrc, Host2, Protocol, Port),
    dataFlow(Host1, Host2, _FlowName, _Direction)),
  rule_desc('Net access hop', 1.0)).


interaction_rule(
   (localAccess(User, DstHost, NetServiceAccount) :-
     netAccess(User, SrcHost, DstHost, Protocol, Port),
     networkService(DstHost, Software, Prot, Port, NetServiceAccount),
     vulExists(CveId, Software, Version, LocalNetwork, _lose_types, 'critical'),
     malicious(User)),
    rule_desc('', 1.0)).

interaction_rule(
   (localAccess(User, DstHost, NetServiceAccount) :-
     netAccessACL(User, SrcHost, DstHost, Protocol, Port),
     networkService(DstHost, Software, Prot, Port, NetServiceAccount),
     residesOn(Host, Software, Version),
     vulExists(CveId, Software, Version, LocalNetwork, _lose_types, 'critical'),
     malicious(User)),
    rule_desc('', 1.0)).

interaction_rule(
   (localAccess(User, Host, Root) :-
     localService(Host, Software, Account),
     vulExists(CveId, Software, Version, LocalNetwork, _lose_types, 'critical'),
     malicious(User),
     localAccess(User, Host, Account)),
    rule_desc('', 1.0)).
    
/* Interaction Rules for T1055 - Process Injection: */

interaction_rule(
   (dataInject(User, DstHost, Path1, Path2) :-
     accessFile(User, SrcHost, write, Path1),
     dataBind(Flow, SrcHost, Path1),
     dataFlow(SrcHost, DstHost, Flow, _Direction),
     dataBind(Flow, DstHost, Path2)),
    rule_desc('', 1.0)).
    
/* Interaction Rules for T1005 - Data from Local System: */

interaction_rule(
   (accessFile(User, Host, Permission, Path) :-
     execCode(User, Host, Account),
     localFileProtection(Host, Account, Permission, Path)),
    rule_desc('', 1.0)).

interaction_rule(
   (localFileProtection(Host, root, read, Path) :-
     fileOwner(Host, Path, root),
     ownerAccessible(Host, read, Path)),
    rule_desc('Valid file protection mechanism', 1.0)).
    
/* Interaction Rules for T1059 - Command and Scripting Interpreter: */

interaction_rule(
   (execCode(User, Host, Account) :-
     compromised(Host),
     vulExists(CveId, Software, Version, LocalNetwork, _lose_types, critical)),
    rule_desc('Can access to the local file  on  the host', 1.0)).

interaction_rule(
   (compromised(Host) :-
     deviceOnline(Host, Platform),
     residesOn(Host, Software, Version),
     vulExists(CveId, Software, Version, RemoteNetwork, _lose_types, 'critical'),
     maliciousInteraction(Host, User, Software)),
    rule_desc('', 1.0)).


/* ----------------------------This is a trial section for compromise a device but from VPN connectivity ---------------------- */

interaction_rule(
   (compromisedVPNClient(HackerHost, TargetHost) :-
     softwareCompromisedRemotely(HackerHost, TargetHost)),
    rule_desc('Host compromised.', 1.0)).


interaction_rule(
   (compromisedVPNClient(HackerHost, TargetHost) :-
     lateralMovementVPN(HackerHost, VPNServer, IntermediateVPNHost),
     networkService(TargetHost, Software, Protocol, Port, Account),
     residesOn(TargetHost, Software, Version),
     hasAccount(_User, TargetHost, Account),
     isInSubnet(Subnet, IntermediateVPNHost),
     isInSubnet(Subnet, TargetHost),
     isInSubnet('vlan', TargetHost)),
    rule_desc('Using compromised hosts credentials to login to other VLAN hosts via same subnet.', 1.0)).


interaction_rule(
   (compromisedVPNClient(HackerHost, TargetVPNHost) :-
     lateralMovementVPN(HackerHost, VPNServer, TargetVPNHost),
     networkService(TargetHost, Software, Protocol, Port, Account),
     residesOn(TargetHost, Software, Version),
     hasAccount(_User, TargetHost, Account)),
    rule_desc('Host compromised using known credentials over VPN lateral movement.', 1.0)).

interaction_rule(
   (softwareCompromisedRemotely(HackerHost, TargetHost) :-
     netAccess(Account, HackerHost, TargetHost, Protocol, Port),
     networkService(TargetHost, Software, Protocol, Port, _Account),
     residesOn(TargetHost, Software, Version),
     vulExists(_cve_id, Software, Version, Network, _Lose_types, _Severity)),
    rule_desc('Software compromised via remote vulnerability.', 1.0)).

interaction_rule(
   (softwareCompromisedLocally(TargetHost) :-
     compromisedVPNClient(_HackerHost, TargetHost),
     residesOn(TargetHost, Software, Version),
     hasAccount('root', TargetHost, _Account),
     vulExists(_cve_id, Software, Version, LocalNetwork, PrivilegeEscalation, _Severity)),
    rule_desc('Privilege escalation due to locally compromised software.', 1.0)).

interaction_rule(
   (canCreateValidVPNCertificate(HackerHost, TargetHost) :-
     residesOn(TargetHost, 'intergalactic-web-ui', _Version),
     softwareCompromisedLocally(TargetHost)),
    rule_desc('Can create/forge intergalactic-web-ui certificate.', 1.0)).

interaction_rule(
   (canAccessVPN(HackerHost, TargetHost) :-
     netAccess(_Account, HackerHost, TargetHost, 'udp', '1194'),
     canCreateValidVPNCertificate(HackerHost, TargetHost)),
    rule_desc('VPN network access.', 1.0)).

interaction_rule(
   (lateralMovementVPN(HackerHost, VPNServer, TargetVPNHost) :-
     isInSubnet('vpn', TargetVPNHost),
     canAccessVPN(HackerHost, VPNServer)),
    rule_desc('Lateral movement over VPN network.', 1.0)).


/* ---------------------------------------------------------------------------------------------------------------------------- */


/* Interaction Rules for T1005 - Data from Local System: */

interaction_rule(
  (logInService(Host, Protocol, Port) :-
    networkService(Host, Software, Protocol, Port, Account)),
  rule_desc('Login with ssh/another software', 1.0)).

interaction_rule(
  (canAccessHost(User, Host) :-
    logInService(Host, Protocol, Port),
    netAccess(User, AttackSrc, Host, Protocol, Port)),
  rule_desc('Access a host through login service and net access', 1.0)).

interaction_rule(
   (accessFile(User, Host, Permission, Path) :-
     canAccessHost(User, Host),
     execCode(User, Host, Account),
     localFileProtection(Host, Account, Permission, Path)),
    rule_desc('', 1.0)).

interaction_rule(
   (localFileProtection(Host, Account, 'read', Path) :-
     fileOwner(Host, Path, Account),
     ownerAccessible(Host, 'read', Path)),
    rule_desc('Valid file protection mechanism', 1.0)).

interaction_rule(
   (localFileProtection(Host, Account, 'write', Path) :-
     fileOwner(Host, Path, Account),
     ownerAccessible(Host, 'write', Path)),
    rule_desc('Valid file protection mechanism', 1.0)).

/* Interaction Rules for T1003 - OS Credential Dumping: */

interaction_rule(
   (principalCompromised(Victim, Host, Attacker) :-
     hasAccount(Victim, Host, Account),
     execCode(Attacker, Host, 'root'),
     leakInfo(Host, File),
     malicious(Attacker)),
    rule_desc('Device compromised via OS credential dumping', 1.0)).

interaction_rule(
   (leakInfo(Host, File) :-
     execCode(Attacker, Host, Account),
     accessFile(Attacker, Host, Permission, File),
     localFileProtection(Host, 'root', 'read', File)),
    rule_desc('Credential dumping via access to sensitive files', 1.0)).


/* Interaction Rules for T1505.003		Server Software Component Web Shell: */

interaction_rule(
   (webShell(Software, Host, Attacker, Permission) :-
     netAccess(Attacker, SrcHost, DstHost, Protocol, Port),
     accessFile(Attacker, Host, Permission, Path),
     execCode(Attacker, Host, Account),
     residesOn(Host, Software, Version),
     vulExists(CveId, Software, Version, LocalNetwork, _lose_types, 'critical'),
     hacl(SrcHost, Host, Protocol, DestPort),
     maliciousInteraction(Host, _, Software),
     allows(Host, Attacker, Operation, Url, Response),
     malicious(Attacker)),
    rule_desc('', 1.0)).


/* Interaction Rules for T1070.004		Indicator Removal File Deletion: */

interaction_rule(
   (fileDeletion(Host, Software, Subnet, Attacker) :-
     localFileProtection(Host, Account, Permission, Path),
     residesOn(Host, Software, Version),
     vulExists(CveId, Software, Version, LocalNetwork, _lose_types, critical),
     canDeleteDoc(Software, Victim, Host, Attacker),
     installed(Host, Software, Version),
     isInSubnet(Subnet, Host),
     setuidProgram(Host, Software, Account),
     malicious(User)),
    rule_desc('', 1.0)).

interaction_rule(
   (canDeleteDoc(Software, Victim, Host, Attacker) :-
     principalCompromised(Victim, Host, Attacker)),
    rule_desc('', 1.0)).


/* Interaction Rules for T1560.001		Archive Collected Data Archive via Utility: */

interaction_rule(
   (archiveviaUtility(Software, Host, Account, Path) :-
     localFileProtection(Host, Account, Permission, Path),
     installed(Host, Software, Version)),
    rule_desc('', 1.0)).


/* Interaction Rules for T1056.001		Input Capture Keylogging: */

interaction_rule(
   (keylogging(Host, 'intergalactic-web-ui', Software2, Account) :-
     setuidProgram(Host, Software, Account),
     installed(Host, 'intergalactic-web-ui', Version),
     canInvoke('intergalactic-web-ui', Software2, 'keylogging')),
    rule_desc('', 1.0)).


/* Interaction Rules for T1562.001		Impair Defenses Disable or Modify Tools: */

interaction_rule(
   (disableorModifyTools(User, Host, 'intergalactic-web-ui', Path, Permission, Account) :-
     localFileProtection(Host, Account, Permission, Path),
     setuidProgram(Host, 'intergalactic-web-ui', Account),
     accessFile(User, Host, Permission, Path)),
    rule_desc('', 1.0)).