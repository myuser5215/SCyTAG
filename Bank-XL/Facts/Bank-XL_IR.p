/******************************************************/
/****         Predicates Declaration              *****/
/******************************************************/

primitive(hasAccount(_user, _host, _account)).
primitive(hasAccess(_user, _attackSrc, _host, _protocol, _port)).
primitive(isInSubnet(_subnet, _host)).
primitive(dataFlow(_src, _dst, _flowName, _direction)).
primitive(dataBind(_flow, _srcHost, _path)).
primitive(networkService(_host, _program, _protocol, _port, _permission)).
primitive(hacl(_src, _dst, _protocol, _port)).
primitive(residesOn(_host, _software, _version)).
primitive(vulExists(_cveId, _software, _version, _access_vector, LoseTypes, _severity)).
primitive(malicious(_attacker)).
primitive(fileOwner(_host, _path, _owner)).
primitive(ownerAccessible(_host, _permission, _path)).
primitive(deviceOnline(_host, _platform)).
primitive(maliciousInteraction(_host, _user, _software)).
primitive(isNameResolver(_host1, _host2, _resolver)).
primitive(vulE2EProtocol(_fooled, _resolver, _dns_attack_type, _dns, _protocol, _exploitRange, _loseTypes)).


derived(deviceCompromised(_attacker, _host, _account)).
derived(canAccessHost(_user, _host)).
derived(arpSpoofed(_victim, _host,_attacker)).
derived(logInService(_host, _protocol, _port)).
derived(netAccess(_user, _attackSrc, _host, _protocol, _port)).
derived(attackerLocated(_subnet)).
derived(localAccess(_user, _dst, _account)).
derived(accessFile(_user, _host, _account, _permission, _path)).
derived(localFileProtection(_host, _account, _permission, _path)).
derived(principalCompromised(_victim, _host, _attacker)).
derived(leakInfo(_host, _file)).
derived(execCode(_user, _host, _account)).
derived(credentialsAccessInFiles(_software, _host)).
derived(compromised(_host)).
derived(ingressToolTransfer(_software, _user, _host, _file, _port)).
derived(dataInject(_user, _host, _path1, _path2, _port)).
derived(spoofE2EHost(_user, _impersonated, _fooled, _attacker, _protocol, _port, _trafficTheft)).
derived(mitmE2E(_user, _attacker, _fooled, _spoofing, _protocol, _port)).
derived(execDelegatedCode(_user, _srcHost, _dstHost, _account)).
derived(fullCampaign(_user, _start, _middle, _end)).

meta(attackGoal(_)).

/******************************************************/
/****         Tabling Predicates                  *****/
/*   All derived predicates should be tabled          */
/******************************************************/

:- table deviceCompromised/3.
:- table canAccessHost/2.
:- table arpSpoofed/3.
:- table logInService/3.
:- table netAccess/5.
:- table attackerLocated/1.
:- table localAccess/3.
:- table accessFile/5.
:- table localFileProtection/4.
:- table principalCompromised/3.
:- table leakInfo/2.
:- table execCode/3.
:- table compromised/1.
:- table credentialsAccessInFiles/2.
:- table ingressToolTransfer/5.
:- table dataInject/5.
:- table spoofE2EHost/7.
:- table mitmE2E/6.
:- table execDelegatedCode/4.
:- table fullCampaign/4.

/******************************************************/
/****         Interaction Rules                   *****/
/******************************************************/


/* Interaction Rules for T1557.002 - ARP Cache Poisoning */
interaction_rule(
   (deviceCompromised(Attacker, Host, Account) :-
     arpSpoofed(Victim, Host, Attacker),
     hasAccount(Victim, Host, Account),
     principalCompromised(Victim, Host, Attacker),
     canAccessHost(Attacker, Host)),
   rule_desc('Device compromised after ARP spoofing', 1.0)).

interaction_rule(
  (canAccessHost(User, Host) :-
    logInService(Host, Protocol, Port),
    netAccess(User, AttackSrc, Host, Protocol, Port)),
  rule_desc('Access a host through login service and net access', 1.0)).

interaction_rule(
  (arpSpoofed(Victim, Host, Attacker) :-
    hasAccount(Victim, Host, Account),
    attackerLocated(Subnet),
    isInSubnet(Subnet, Host),
    networkService(Host, 'arpd', Protocol, Port, Account),
    residesOn(Host, 'arpd', Version),
    vulExists('arpSpoofVuln', 'arpd', Version, LocalNetwork, LoseTypes, 'critical')),
  rule_desc('ARP spoofing', 1.0)).

interaction_rule(
  (logInService(Host, Protocol, Port) :-
    networkService(Host, 'sshd', Protocol, Port, Account)),
  rule_desc('Login with sshd', 1.0)).

interaction_rule(
  (logInService(Host, Protocol, Port) :-
    networkService(Host, 'ftpd', Protocol, Port, Account)),
  rule_desc('Login with ftpd', 1.0)).

interaction_rule(
  (logInService(Host, Protocol, Port) :-
    networkService(Host, 'arpd', Protocol, Port, Account)),
  rule_desc('Login with arpd', 1.0)).

interaction_rule(
  (netAccess(User, AttackSrc, Host, Protocol, Port) :-
    hasAccess(User, AttackSrc, Host, Protocol, Port)),
  rule_desc('Net direct access', 1.0)).

interaction_rule(
  (netAccess(User, AttackSrc, Host2, Protocol, Port) :-
    netAccess(User, AttackSrc, Host1, Protocol, Port),
    dataFlow(Host1, Host2, FlowName, Direction)),
  rule_desc('Net access hop', 1.0)).

interaction_rule(
  (attackerLocated(Subnet) :-
    localAccess(User, DstHost, NetServiceAccount),
    isInSubnet(Subnet, Host),
    hacl(Host1, Host, Protocol, Port),
    residesOn(Host, Software, Version),
    vulExists(CveId, Software, Version, RemoteNetwork, LoseTypes, 'critical')),
  rule_desc('Vul. with remote access-vector in a host connected to Internet', 1.0)).

/* Interaction Rules for T1548 - Abuse Elevation Control Mechanism */
interaction_rule(
   (localAccess(User, DstHost, NetServiceAccount) :-
     netAccess(User, SrcHost, DstHost, Protocol, Port),
     networkService(DstHost, Software, Protocol, Port, NetServiceAccount),
     vulExists(CveId, Software, Version, 'network', LoseTypes, 'critical'),
     malicious(User)), 
   rule_desc('Privilege escalation using setuid program', 1.0)).
   
/* Interaction Rules for T1003 - OS Credential Dumping */
interaction_rule(
   (accessFile(User, Host, Account, Permission, Path) :-
     execCode(User, Host, Account),
     localFileProtection(Host, Path, Account, Permission)),
   rule_desc('', 1.0)).

interaction_rule(
   (localFileProtection(Host, Path, Account, Permission) :-
     fileOwner(Host, Path, Account),
     ownerAccessible(Host, Permission, Path)),
   rule_desc('Valid file protection mechanism', 1.0)).

/* Additional Rules for Credential Dumping */
interaction_rule(
   (principalCompromised(Victim, Host, User) :-
     hasAccount(Victim, Host, Account),
     execCode(User, Host, Account),
     leakInfo(Host, Path),
     malicious(User)),
   rule_desc('Device compromised via OS credential dumping', 1.0)).

interaction_rule(
   (leakInfo(Host, Path) :-
     execCode(User, Host, Account),
     accessFile(User, Host, Account, Permission, Path),
     localFileProtection(Host, Path, Account, Permission)),
   rule_desc('Credential dumping via access to sensitive files', 1.0)).

/* */
/* Interaction Rules for T1552.001 - Unsecured Credentials */
interaction_rule(
   (credentialsAccessInFiles('ssh', Host) :-
     accessFile(_, Host, root, read, '/etc/shadow')),
    rule_desc('Credentials extracted from files', 1.0)).

/* Interaction Rules for T1059 - Command and Scripting Interpreter: */

interaction_rule(
   (execCode(User, Host, Account) :-
     compromised(Host),
     residesOn(Host, Software, Version),
     vulExists(_, Software, Version, _, _, 'critical'),
     hasAccount(User, Host, Account)),
    rule_desc('Arbitrary code execution after host compromise', 1.0)).

interaction_rule(
   (compromised(Host) :-
     deviceOnline(Host, Platform),
     residesOn(Host, Software, Version),
     vulExists(CveId, Software, Version, RemoteNetwork, LoseTypes, 'critical'),
     maliciousInteraction(Host, User, Software)),
    rule_desc('Host compromised via vulnerability exploitation', 1.0)).

interaction_rule(
   (compromised(Host) :-
     execCode(_, Host, _)),
    rule_desc('Host compromised via code execution', 1.0)).

/* Interaction Rules for T1105 - Ingress Tools */
interaction_rule(
   (ingressToolTransfer('ssh', User, Host, '/tmp/splunkd', 22) :-
     credentialsAccessInFiles('ssh', _),
     attackerLocated(_),
     hacl(_, Host, tcp, 22),
     hasAccount(User, Host, user)),
    rule_desc('Tool transferred using stolen SSH credentials', 1.0)).

/* Interaction Rules for T1055 - Process Injection: */

interaction_rule(
   (dataInject(User, DstHost, Path1, Path2, Port) :-
     accessFile(User, SrcHost, Account, Permission, Path1),
     dataBind(Flow, SrcHost, Path1),
     dataFlow(SrcHost, DstHost, Flow, _Direction),
     dataBind(Flow, DstHost, Path2)),
    rule_desc('', 1.0)).

interaction_rule(
   (dataInject(User, DstHost, Path1, Path2, Port) :-
     accessFile(User, DstHost, Account, Permission, Path1),
     netAccess(User, SrcHost, DstHost, Protocol, Port)),
    rule_desc('', 1.0)).


/* T1071.004 - Application Layer Protocol DNS: */

interaction_rule(
   (spoofE2EHost(User, ImpersonatedHost, FooledHost, AttackerHost, Prot, Port, TrafficTheft):-
     isNameResolver(FooledHost, ImpersonatedHost, AttackerHost),
     vulE2EProtocol(FooledHost, AttackerHost, DNSCachePoisoning, DNS, DNSProt, RemoteExploit, NameresolverCachePoisoned),
     netAccess(User, AttackerHost, FooledHost, DNS, DNSPort)),
    rule_desc('The attacker spoofs as the name server and provides malicious binding for legitimate requests', 1.0)).

interaction_rule(
   (spoofE2EHost(User, ImpersonatedHost, FooledHost, AttackerHost, Prot, Port, TrafficTheft):-
     isNameResolver(ImpersonatedHost, FooledHost, AttackerHost),
     vulE2EProtocol(ImpersonatedHost, AttackerHost, DNSCachePoisoning, DNS, DNSProt, RemoteExploit, NameresolverCachePoisoned),
     netAccess(User, AttackerHost, ImpersonatedHost, DNS, DNSPort)),
    rule_desc('The attacker spoofs as the name server and provides malicious binding for legitimate requests', 1.0)).

interaction_rule(
   (spoofE2EHost(User, ImpersonatedHost, FooledHost, AttackerHost, Prot, Port, TrafficTheft):-
     isNameResolver(ImpersonatedHost, FooledHost, NameResolver),
     localAccess(User, NameResolver, Permission),
     netAccess(User2, FooledHost, AttackerHost, Prot, Port),
     localAccess(User, AttackerHost, Account)),
    rule_desc('The attacker can log in using local access to the DNS server and modify the DNS records to associate the attacker host with a naming of his/hers choice', 1.0)).

interaction_rule(
   (mitmE2E(User, ImpersonatedHost, FooledHost, SpoofingHost, Prot, Port):-
     spoofE2EHost(User, SpoofingHost, FooledHost, ImpersonatedHost, Prot, Port, TrafficTheft),
     spoofE2EHost(User, FooledHost, SpoofingHost, ImpersonatedHost, Prot, Port, TrafficTheft)),
    rule_desc('MITM attack in the end-to-end layer in which only a specific application layer protocol is routed through the attacker host', 1.0)).

interaction_rule(
   (execDelegatedCode(User, SrcHost, DstHost, root) :-
     compromised(SrcHost),
     hacl(SrcHost, DstHost, tcp, 22),
     hasAccount(User, DstHost, root)),
    rule_desc('Lateral movement with delegated execution', 1.0)).

interaction_rule(
   (compromised(DstHost) :-
     execDelegatedCode(_, _, DstHost, _)),
    rule_desc('Destination host compromised via delegated code execution', 1.0)).

/* Final IR */
interaction_rule(
   (fullCampaign(User, StartHost, MiddleHost, EndHost) :-
     credentialsAccessInFiles('ssh', StartHost),
     ingressToolTransfer('ssh', User, MiddleHost, '/tmp/splunkd', 22),
     execDelegatedCode(User, MiddleHost, EndHost, root)),
    rule_desc('End-to-end Caldera campaign execution', 1.0)).