import traceback
import csv

from pyhavoc.core  import *
from pyhavoc.ui    import *
from pyhavoc.agent import *
from os.path       import exists, dirname, basename
from io            import StringIO

CURRENT_DIR  = dirname( __file__ )
CACHE_OBJECT = False

##
## this are some util functions and the SAObjectTaskBase 
## base object which every SA object command will inherit 
##

def file_read( path: str ) -> bytes:
    handle    = open( path, 'rb' )
    obj_bytes = handle.read()
    handle.close()
    return obj_bytes

class SAObjectTaskBase( HcKaineCommand ):

    def __init__( self, *args, **kwargs ):
        super().__init__( *args, **kwargs )

        self.capture_output = False

        name = self.command()

        self.bof_path = f"{dirname(__file__)}/{name}/{name}.{self.agent().agent_meta()['arch']}.o"
        self.key_id   = f'obj-sa-handle.{name}'

    async def execute( self, args ):    
        return await self.execute_object()

    async def execute_object( self, *args, argv: bytes = None, description = '' ):
        if exists( self.bof_path ) is False:
            self.log_error( f"object file not found: {self.bof_path}" )
            return
        
        #
        # execute the already loaded object file if we 
        # have it loaded + CACHE_OBJECT is still enabled 
        if self.key_id in self.agent().key_store and CACHE_OBJECT:
            task = self.agent().object_invoke( 
                self.agent().key_store[ self.key_id ], 
                'go', 
                *args,
                object_argv  = argv, 
                flag_capture = self.capture_output 
            )
        else:
            task = self.agent().object_execute( 
                file_read( self.bof_path ), 
                'go',
                *args,
                object_argv  = argv, 
                flag_cache   = CACHE_OBJECT,
                flag_capture = self.capture_output
            )

        uuid    = format( task.task_uuid(), 'x' )
        message = description

        #
        # this displays the informational message of the task being created 
        # by either using the given execute_object description or use the 
        # registered command descritpion
        if len( message ) == 0:
            message = self.description()
            if CACHE_OBJECT:
                message += ' (with caching enabled)'

            task.set_description( message )

        self.log_info( f'({uuid}) {message}' )

        #
        # now invoke and issue the task to the agent and wait for it to finish 
        try:
            result = await task.result()

            if CACHE_OBJECT and self.key_id not in self.agent().key_store:
                #
                # looks like we are not in the store meaning that the previously send
                # out task should be cachhing the object into memory and return us the handle   
                handle, output = result
                message        = f'(handle: 0x{handle:x})'

                self.agent().key_store[ self.key_id ] = handle
            else:
                #
                # normally wait for the object file to finish!
                message = ''
                handle, output = 0, ''

                if len( result ) == 1: 
                    output = result
                elif len( result ) == 2:
                    handle, output = result
            if len( output ) > 0 and self.capture_output:
                self.process_output( output, task.task_uuid() )
            elif self.capture_output: 
                self.log_warn( f'{self.command()} has sent no output back!', task_id = task.task_uuid() )
        except Exception as e:
            self.log_error( f"({uuid}) failed to execute {self.command()}: {e}", task_id = task.task_uuid() )
            print( traceback.format_exc() )
            if str( e ) == 'STATUS_NOT_FOUND':
                self.log_warn( f'removing key store entry of {self.command()}' ) 
                del self.agent().key_store[ self.key_id ]
            return

        self.log_success( f"({uuid}) successfully executed {self.command()} {message}", task_id = task.task_uuid() )

    def process_output( self, output: str, task_id: int ):
        self.log_success( f'received output from {self.command()} [{len(output)} bytes]:', task_id = task_id )
        self.log_raw( output.decode(), task_id = task_id )
        return

@KnRegisterCommand( command     = 'sa-objects', 
                    description = 'control situational awareness object files', 
                    group       = 'Situatinal Awareness Commands' )
class SAObjectControlTask( HcKaineCommand ):
    
    def __init__( self, *args, **kwargs ):
        super().__init__( *args, **kwargs )
        return

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "example usage:\n"
            "  sa-objects enable-caching\n"
            "  sa-objects disable-caching\n"
            "  sa-objects status\n"
        )

        # create sub-parser
        sub_parsers = parser.add_subparsers( help='situational awareness commands', dest="_command", required = True )

        sub_parsers.add_parser( 'free-all', add_help=False, help='free all cached situational awareness object files' )
        sub_parsers.add_parser( 'enable-caching', add_help=False, help='enable the caching of the situational awareness files' )
        sub_parsers.add_parser( 'disable-caching', add_help=False, help='disable the caching of the situational awareness files' )
        sub_parsers.add_parser( 'status', add_help=False, help='show current caching status and the loaded object files' )
        
        return parser
    
    async def execute( self, args ):
        global CACHE_OBJECT

        if args._command == 'free-all':
            pass

        elif args._command == 'enable-caching':
            CACHE_OBJECT = True
            self.log_success( 'enabled situational awareness object file caching' ) 

        elif args._command == 'disable-caching':
            CACHE_OBJECT = False
            self.log_success( 'disasbled situational awareness object file caching' )

        elif args._command == 'status':
            
            information = (
                '\n'
                f'  Caching: {CACHE_OBJECT}\n'
            )

            self.log_info( 'display caching status and the loaded object files:' )
            self.log_raw( information )

##
## object file commands 
## 

@KnRegisterCommand( command     = 'whoami', 
                    description = 'list whoami /all', 
                    group       = 'Situatinal Awareness Commands' )
class ObjectWhoamiTask( SAObjectTaskBase ):
    pass


@KnRegisterCommand( command     = 'ipconfig', 
                    description = 'list IPv4 address, hostname, and DNS server', 
                    group       = 'Situatinal Awareness Commands' )
class ObjectIpconfigTask( SAObjectTaskBase ):
    pass


@KnRegisterCommand( command     = 'uptime', 
                    description = 'list system boot time and how long it has been running', 
                    group       = 'Situatinal Awareness Commands' )
class ObjectUptimeTask( SAObjectTaskBase ):
    pass


@KnRegisterCommand( command     = 'arp', 
                    description = 'list ARP table', 
                    group       = 'Situatinal Awareness Commands' )
class ObjectArpListTask( SAObjectTaskBase ):
    pass


@KnRegisterCommand( command     = 'driversigs', 
                    description = 'enumerate installed services imagepaths to check the signing cert against known AV/EDR vendors', 
                    group       = 'Situatinal Awareness Commands' )
class ObjectDriversigsTask( SAObjectTaskBase ):
    pass


@KnRegisterCommand( command     = 'env', 
                    description = 'list process environment variables', 
                    group       = 'Situatinal Awareness Commands' )
class ObjectEnvListTask( SAObjectTaskBase ):
    pass


@KnRegisterCommand( command     = 'netstat', 
                    description = 'list active TCP and UDP IPv4 connections', 
                    group       = 'Situatinal Awareness Commands' )
class ObjectNetstatTask( SAObjectTaskBase ):
    pass


@KnRegisterCommand( command     = 'locale', 
                    description = 'list system locale language, locale ID, date, time, and country', 
                    group       = 'Situatinal Awareness Commands' )
class ObjectLocaleTask( SAObjectTaskBase ):
    pass

@KnRegisterCommand( command     = 'get_dpapi_system', 
                    description = 'Print DPAPI_SYSTEM and boot key if able', 
                    group       = 'Situatinal Awareness Commands' )
class ObjectListPipesTask( SAObjectTaskBase ):
    pass


@KnRegisterCommand( command     = 'listdns', 
                    description = 'list DNS cache entries. attempt to query and resolve each', 
                    group       = 'Situatinal Awareness Commands' )
class ObjectListDnsTask( SAObjectTaskBase ):
    pass


@KnRegisterCommand( command     = 'list_firewall_rules', 
                    description = 'list windows firewall rules', 
                    group       = 'Situatinal Awareness Commands' )
class ObjectListFirewallRulesTask( SAObjectTaskBase ):
    pass


@KnRegisterCommand( command     = 'useridletime', 
                    description = 'displays how long the user has been idle', 
                    group       = 'Situatinal Awareness Commands' )
class ObjectUseridletimeTask( SAObjectTaskBase ):
    pass


@KnRegisterCommand( command     = 'resources', 
                    description = 'list memory usage and available disk space on the primary hard drive', 
                    group       = 'Situatinal Awareness Commands' )
class ObjectResourcestimeTask( SAObjectTaskBase ):
    
    @staticmethod
    def arguments( parser ):
        parser._add_help = False


@KnRegisterCommand( command     = 'aadjoininfo', 
                    description = 'retrieve azure AD/Entra ID join information', 
                    group       = 'Situatinal Awareness Commands' )
class ObjectAadJoinInfoTask( SAObjectTaskBase ):
    pass


@KnRegisterCommand( command     = 'adcs_enum', 
                    description = 'Enumerates CAs and templates in the AD using Win32 functions', 
                    group       = 'Situatinal Awareness Commands' )
class ObjectAdcsEnumTask( SAObjectTaskBase ):
    
    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   This command enumerates the certificate authorities and certificate\n"
            "   types (templates) in the Acitive Directory Certificate Services using\n"
            "   undocumented Win32 functions. It displays basic information as well\n" 
            "   as the CA cert, flags, permissions, and similar information for the\n" 
            "   templates.\n"
        )

        parser.add_argument( 'DOMAIN', nargs='?', default="", type=str, help="specified domain otherwise uses current domain" )

    async def execute( self, args ):
        return await self.execute_object( args.DOMAIN, description = 'Enumerates CAs and templates in the AD using Win32 functions' )
    

@KnRegisterCommand( command     = 'adcs_enum_com', 
                    description = 'Enumerates CAs and templates in the AD using ICertConfig COM object', 
                    group       = 'Situatinal Awareness Commands' )
class ObjectAdcsEnumComTask( SAObjectTaskBase ):
    
    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   This command enumerates the certificate authorities and certificate\n"
            "   types (templates) in the Acitive Directory Certificate Services using\n" 
            "   the ICertConfig, ICertRequest, and IX509CertificateTemplate COM \n"
            "   objects. It displays basic information as well as the CA cert, flags,\n" 
            "   permissions, and similar information for the templates.\n"
        )

    async def execute( self, args ):
        return await self.execute_object( description = 'Enumerates CAs and templates in the AD using ICertConfig COM object' )
    

@KnRegisterCommand( command     = 'adcs_enum_com2', 
                    description = 'Enumerates CAs and templates in the AD using IX509PolicyServerListManager COM object', 
                    group       = 'Situatinal Awareness Commands' )
class ObjectAdcsEnumComTask( SAObjectTaskBase ):
    
    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   This command enumerates the certificate authorities and certificate \n"
            "   types (templates) in the Acitive Directory Certificate Services using\n" 
            "   the IX509PolicyServerListManager, IX509PolicyServerUrl,\n" 
            "   IX509EnrollmentPolicyServer, ICertificationAuthority, and \n"
            "   IX509CertificateTemplate COM objects. It displays basic information as\n"
            "   well as the CA cert, flags, permissions, and similar information for\n"
            "   the templates.\n"
        )

    async def execute( self, args ):
        return await self.execute_object( description = 'Enumerates CAs and templates in the AD using IX509PolicyServerListManager COM object' )


@KnRegisterCommand( command     = 'vssenum', 
                    description = 'Enumerate snapshots on a remote machine', 
                    group       = 'Situatinal Awareness Commands' )
class ObjectVssEnumTask( SAObjectTaskBase ):
    
    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   If the target machine has volume snapshots this command will list there timestamps\n"
            "   This command will likely only work on windows server 2012 + with specific configurations\n"
            "   see https://techcommunity.microsoft.com/t5/storage-at-microsoft/vss-for-smb-file-shares/ba-p/425726 for more info\n"
        )

        parser.add_argument( 'HOSTNAME', type=str, help="target hostname" )
        parser.add_argument( 'SHARENAME', nargs='?', default='C$', type=str, help="sharename (default: C$)" )

    async def execute( self, args ):
        return await self.execute_object( 
            self.agent().to_unicode( args.HOSTNAME ), 
            self.agent().to_unicode( args.SHARENAME ), 
            
            description = 'Enumerate snapshots on a remote machine' )
    

@KnRegisterCommand( command     = 'get_password_policy', 
                    description = 'gets a server or DC\'s configured password policy', 
                    group       = 'Situatinal Awareness Commands' )
class ObjectGetPasswordPolicyTask( SAObjectTaskBase ):
    
    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   Basically re-implements net accounts excluding calling out Computer role\n"
            "   If you target a DC with this it will be domain policies, otherwise its the policy for that local server\n"
            "   target \"\" for the local computer\n"
        )

        parser.add_argument( 'HOSTNAME', type=str, help="target hostname" )

    async def execute( self, args ):
        return await self.execute_object( 
            self.agent().to_unicode( args.HOSTNAME ), 
            
            description = 'gets a server or DC\'s configured password policy' )
    

@KnRegisterCommand( command     = 'probe', 
                    description = 'Check if a port is open', 
                    group       = 'Situatinal Awareness Commands' )
class ObjectProbeTask( SAObjectTaskBase ):
    
    @staticmethod
    def arguments( parser ):
        parser.add_argument( 'HOST', type=str, help="host to check" )
        parser.add_argument( 'PORT', type=int, help="port to check" )

    async def execute( self, args ):

        if args.PORT < 1 or args.PORT > 65535:
            self.log_error( 'port number {args.PORT} is invalid: is out of range' )
            return

        return await self.execute_object( 
            args.HOST,
            args.PORT, 
            
            description = 'gets a server or DC\'s configured password policy' )


@KnRegisterCommand( command     = 'listmods', 
                    description = 'list process modules', 
                    group       = 'Situatinal Awareness Commands' )
class ObjectListModulesTask( SAObjectTaskBase ):
    
    @staticmethod
    def arguments( parser ):
        parser.add_argument( 'PID', nargs='?', default=0, type=int, help="process id to list modules" )

    async def execute( self, args ):
        description = 'list current process modules'
        if args.PID != 0: 
            description = f'list process modules of {args.PID}'
            
        return await self.execute_object( args.PID, description = description )


@KnRegisterCommand( command     = 'cacls', 
                    description = 'list user permissions for the specified file', 
                    group       = 'Situatinal Awareness Commands' )
class ObjectCaclsTask( SAObjectTaskBase ):
    
    @staticmethod
    def arguments( parser ): 
        parser.epilog = (
            "example usage:\n"
            "  cacls C:\\\\windows\\\\system32\\\\notepad.exe\n"
            "  cacls C:\\\\windows\\\\system32\n"
            "  cacls C:\\\\windows\\\\system32\\\\*"
        )

        parser.add_argument( 'PATH', type=str, help="path to list user permissions" )

    async def execute( self, args ):
        return await self.execute_object( self.agent().to_unicode( args.PATH ), description = f'list user permissions for {args.PATH}' )


@KnRegisterCommand( command     = 'dir', 
                    description = 'list files in a directory', 
                    group       = 'Situatinal Awareness Commands' )
class ObjectDirTask( SAObjectTaskBase ):
    
    @staticmethod
    def arguments( parser ): 
        parser.epilog = (
            "example usage:\n"
            "  dir C:\\\\windows\\\\system32\n"
            "  dir C:\\\\windows\\\\system32\\\\*"
        )

        parser.add_argument( 'PATH', nargs='?', default='.\\*', type=str, help="path to directory to list files" )
        parser.add_argument( '--recursive', action='store_true', help='recursively list directories' )

    async def execute( self, args ):
        return await self.execute_object( self.agent().acp_encode( args.PATH ), args.recursive, description = f'list files in {args.PATH}' )


@KnRegisterCommand( command     = 'ldapsearch', 
                    description = 'execute ldap queries', 
                    group       = 'Situatinal Awareness Commands' )
class ObjectLdapsearchTask( SAObjectTaskBase ):
    
    @staticmethod
    def arguments( parser ): 
        parser.epilog = (
            "Important - To add in ACLs so Bloodhound can draw relationships between objects (see external BofHound tool), add nTSecurityDescriptor in the attributes list, like so:\n"
            "    ldapsearch <query> --attributes *,ntsecuritydescriptor ...\n\n"
            "Useful queries (queries are just an example, edit where necessary to make it OPSEC safe):\n\n"
            " - query for Kerberoastable accounts:\n"
            "    ldapsearch (&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))\n\n"
            " - query for AS-REP Roastable:\n"
            "    ldapsearch (&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))\n\n"
            " - query for passwords stored with reversible encryption:\n"
            "    ldapsearch (&(objectClass=user)(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=128))\n"
            " - query domain controllers:\n"
            "    ldapsearch (&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))\n\n"
            " - query all domain admins:\n"
            "    ldapsearch (&(objectCategory=group)(name=Domain Admins))\n\n"
            " - query password policy:\n"
            "    ldapsearch (&(objectClass=msDS-PasswordSettings))\n\n"
            " - query password policy:\n"
            "    ldapsearch (&(objectClass=msDS-PasswordSettings))\n\n"
        )

        parser.add_argument( 'QUERY', nargs='*', type=str, help="path to directory to list files" )
        parser.add_argument( '--attributes', default='*', type=str, help='the attributes to retrieve (default: *)' )
        parser.add_argument( '--count', default=0, type=int, help='the result max size (default: None)' )
        parser.add_argument( '--scope', default="subtree", choices=["base", "level", "subtree"], help='the scope to use (default: subtree)' )
        parser.add_argument( '--hostname', default='', type=str, help='hostname or IP to perform the LDAP connection on (default: automatic DC resolution)' )
        parser.add_argument( '--dn', default='', type=str, help='the LDAP query base' )
        parser.add_argument( '--ldaps', action='store_true', help='use of ldaps' )
        
    async def execute( self, args ):
        scope = 3 # default is subtree 
        query = ' '.join( args.QUERY )
        if args.scope == 'base':
            scope = 1
        elif args.scope == 'level':
            scope = 2

        return await self.execute_object( 
            query, 
            args.attributes,
            args.count,
            scope,
            args.hostname, 
            args.dn,
            args.ldaps,
            
            description = f'execute ldap query: {query}' )
    
@KnRegisterCommand( command     = 'nonpagedldapsearch', 
                    description = 'execute ldap queries (non-paged)', 
                    group       = 'Situatinal Awareness Commands' )
class ObjectLdapsearchTask( SAObjectTaskBase ):
    
    @staticmethod
    def arguments( parser ): 
        parser.epilog = (
            "Important - To add in ACLs so Bloodhound can draw relationships between objects (see external BofHound tool), add nTSecurityDescriptor in the attributes list, like so:\n"
            "    nonpagedldapsearch <query> --attributes *,ntsecuritydescriptor ...\n\n"
            "Useful queries (queries are just an example, edit where necessary to make it OPSEC safe):\n\n"
            " - query for Kerberoastable accounts:\n"
            "    nonpagedldapsearch (&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))\n\n"
            " - query for AS-REP Roastable:\n"
            "    nonpagedldapsearch (&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))\n\n"
            " - query for passwords stored with reversible encryption:\n"
            "    nonpagedldapsearch (&(objectClass=user)(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=128))\n"
        )

        parser.add_argument( 'QUERY', nargs='*', type=str, help="path to directory to list files" )
        parser.add_argument( '--attributes', default='*', type=str, help='the attributes to retrieve (default: *)' )
        parser.add_argument( '--count', default=0, type=int, help='the result max size (default: None)' )
        parser.add_argument( '--hostname', default='', type=str, help='hostname or IP to perform the LDAP connection on (default: automatic DC resolution)' )
        parser.add_argument( '--domain', default='', type=str, help='the LDAP query base' )
        
    async def execute( self, args ):
        query = ' '.join( args.QUERY )

        return await self.execute_object( 
            query, 
            args.attributes,
            args.count,
            args.hostname, 
            args.domain,
            
            description = f'execute ldap query: {query}' )

@KnRegisterCommand( command     = 'netloggedon', 
                    description = 'Returns users logged on the local (or a remote) machine - administrative rights needed', 
                    group       = 'Situatinal Awareness Commands' )
class ObjectGetPasswordPolicyTask( SAObjectTaskBase ):
    
    @staticmethod
    def arguments( parser ):
        parser.add_argument( 'COMPUTERNAME', nargs='?', default='', type=str, help="computername" )

    async def execute( self, args ):
        return await self.execute_object( args.COMPUTERNAME )
    

@KnRegisterCommand( command     = 'netview', 
                    description = 'lists local workstations and servers', 
                    group       = 'Situatinal Awareness Commands' )
class ObjectGetPasswordPolicyTask( SAObjectTaskBase ):
    
    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            'hint: use netview_list if you want to map shares of a remote machine'
        )

        parser.add_argument( 'DOMAIN', nargs='?', default='', type=str, help="optional netbios domain name" )

    async def execute( self, args ):
        return await self.execute_object( self.agent().to_unicode( args.DOMAIN ) )
    
@KnRegisterCommand( command     = 'notepad', 
                    description = 'Searching for open notepad windows', 
                    group       = 'Situatinal Awareness Commands' )
class ObjectGetPasswordPolicyTask( SAObjectTaskBase ):
    pass


@KnRegisterCommand( command     = 'netshares', 
                    description = 'list shares on local or remote computer', 
                    group       = 'Situatinal Awareness Commands' )
class ObjectGetPasswordPolicyTask( SAObjectTaskBase ):
    
    @staticmethod
    def arguments( parser ):
        parser.add_argument( 'COMPUTERNAME', type=str, default='' )
        parser.add_argument( '--admin', action='store_true', help = 'list shares on local or remote computer and gets more info then standard netshares (requires admin)' )

    async def execute( self, args ):
        return await self.execute_object( self.agent().to_unicode( args.COMPUTERNAME ), args.admin )
    
@KnRegisterCommand( 
    command     = 'netgroup', 
    description = 'list the groups of the current domain or list members of a specified group', 
    group       = 'Situatinal Awareness Commands' 
)
class ObjectNetGroupTask( SAObjectTaskBase ):
    
    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "Examples:\n"
            "  netgroup --domain TESTLAB\n"
            "  netgroup --group \"Domain Admins\"\n"
            "  netgroup --group \"Domain Admins\" --domain TESTLAB\n\n"
            "If --group is omitted, this lists domain groups.\n"
            "If --group is provided, this lists the members of that group."
        )

        parser.add_argument(
            '--domain', 
            type=str, 
            default='', 
            help='optional domain name'
        )

        parser.add_argument(
            '--group', 
            type=str, 
            default='', 
            help='optional group name (if provided, lists group members)'
        )

    async def execute( self, args ):
        if args.group == "":
            type_value = 0
            group      = ""
            description = f"list groups for domain '{args.domain}'"

            if args.domain == '':
                description = 'list groups for current domain'
        else:
            type_value = 1 
            group      = args.group
            description = f"list members of group '{group}'"
            if args.domain != '':
                description += f'in domain {args.domain}'

        domain = args.domain

        return await self.execute_object(
            argv        = bof_pack( 'sZZ', type_value, domain, group ),
            description = description
        )


@KnRegisterCommand(
    command     = "netlocalgroup",
    description = "List local groups or list members of a specific local group",
    group       = "Situational Awareness Commands"
)
class ObjectNetLocalGroupTask( SAObjectTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "Examples:\n"
            "  netlocalgroup\n"
            "  netlocalgroup --server WIN10BOX\n"
            "  netlocalgroup --members \"Administrators\"\n"
            "  netlocalgroup --members \"Administrators\" --server WIN10BOX\n\n"
            "If --members is omitted, this lists local groups.\n"
            "If --members is provided, this lists the members of that group."
        )

        parser.add_argument(
            "--server",
            type=str,
            default="",
            help="Optional server name (blank means the current machine)"
        )

        parser.add_argument(
            "--members",
            type=str,
            default="",
            help="Optional group name (if provided, lists the group's members)"
        )

    async def execute( self, args ):
        #
        # Determine type:
        #   0 = list groups
        #   1 = list group members
        #
        if args.members == "":
            type_value  = 0   # list groups
            group       = ""
            server      = args.server
            description = f"list local groups on server '{server}'" \
                if server else "list local groups on current machine"
        else:
            type_value  = 1   # list group members
            group       = args.members
            server      = args.server
            description = f"list members of local group '{group}'"
            if server:
                description += f" on server '{server}'"

        #
        # Pack arguments for BOF:
        # Matches CNA: bof_pack($1, "sZZ", $type, $server, $group)
        #
        argv = bof_pack(
            "sZZ",
            type_value,
            server,
            group
        )

        return await self.execute_object(
            argv        = argv,
            description = description
        )

@KnRegisterCommand(
    command     = "schtasksquery",
    description = "Query a specific scheduled task on the local or target machine",
    group       = "Situational Awareness Commands"
)
class ObjectSchTasksQueryTask(SAObjectTaskBase):

    @staticmethod
    def arguments(parser):
        parser.epilog = (
            "Examples:\n"
            "  schtasksquery --taskname 'TaskName'\n"
            "  schtasksquery --server WIN10BOX --taskname 'TaskName'\n\n"
            "If --server is omitted, the current machine is queried."
        )

        parser.add_argument(
            "--server",
            type=str,
            default="",
            help="Optional target server (blank = current machine)"
        )

        parser.add_argument(
            "--taskname",
            type=str,
            required=True,
            help="Name of the scheduled task to query"
        )

    async def execute(self, args):
        # Validate usage (taskname is required)
        if not args.taskname:
            raise ValueError("Invalid usage: --taskname is required")

        server = args.server
        taskname = args.taskname
        description = f"Query scheduled task '{taskname}'"
        if server:
            description += f" on server '{server}'"

        # Pack arguments for BOF
        argv = bof_pack("ZZ", server, taskname)

        return await self.execute_object(
            argv=argv,
            description=description
        )


@KnRegisterCommand(
    command     = "schtasksenum",
    description = "Enumerates all scheduled tasks on the local or target machine",
    group       = "Situational Awareness Commands"
)
class ObjectSchTaskEnumTask(SAObjectTaskBase):

    @staticmethod
    def arguments(parser):
        parser.epilog = (
            "Examples:\n"
            "  schtasksenum\n"
            "  schtasksenum --server WIN10BOX\n\n"
            "If --server is omitted, the current machine is enumerated."
        )

        parser.add_argument(
            "--server",
            type=str,
            default="",
            help="Optional target server (blank = current machine)"
        )

    async def execute(self, args):
        server = args.server
        description = f"Enumerate all scheduled tasks"
        if server:
            description += f" on server '{server}'"

        # Pack arguments for BOF
        argv = bof_pack("Z", server)

        return await self.execute_object(
            argv=argv,
            description=description
        )


class SAServiceTaskBase(SAObjectTaskBase):
    @staticmethod
    def common_args(parser, require_service=False):
        parser.add_argument(
            "--hostname",
            type=str,
            default="",
            help="Optional target hostname (default = local machine)"
        )
        if require_service:
            parser.add_argument(
                "--service",
                type=str,
                required=True,
                help="Service name to query"
            )
        else:
            parser.add_argument(
                "--service",
                type=str,
                default="",
                help="Optional service name (if omitted, enumerates all services)"
            )

@KnRegisterCommand(
    command="sc_query",
    description="Query a service's status",
    group="Situational Awareness Commands"
)
class ObjectSCQueryTask(SAServiceTaskBase):

    @staticmethod
    def arguments(parser):
        SAServiceTaskBase.common_args(parser, require_service=False)

    async def execute(self, args):
        hostname = args.hostname.strip() or ""
        service = args.service.strip() or ""
        argv = bof_pack("zz", hostname, service)
        description = f"Query service '{service or 'ALL'}' on host '{hostname or 'local'}'"
        return await self.execute_object(argv=argv, description=description)

@KnRegisterCommand(
    command="sc_qc",
    description="Query a service's configuration",
    group="Situational Awareness Commands"
)
class ObjectSCQCTask(SAServiceTaskBase):

    @staticmethod
    def arguments(parser):
        SAServiceTaskBase.common_args(parser, require_service=True)

    async def execute(self, args):
        hostname = args.hostname.strip() or ""
        service = args.service.strip()
        argv = bof_pack("zz", hostname, service)
        description = f"Query configuration for service '{service}' on host '{hostname or 'local'}'"
        return await self.execute_object(argv=argv, description=description)


@KnRegisterCommand(
    command="sc_qdescription",
    description="Query a service's description",
    group="Situational Awareness Commands"
)
class ObjectSCQDescriptionTask(SAServiceTaskBase):

    @staticmethod
    def arguments(parser):
        SAServiceTaskBase.common_args(parser, require_service=True)

    async def execute(self, args):
        hostname = args.hostname.strip() or ""
        service = args.service.strip()
        argv = bof_pack("zz", hostname, service)
        description = f"Query description for service '{service}' on host '{hostname or 'local'}'"
        return await self.execute_object(argv=argv, description=description)

@KnRegisterCommand(
    command="sc_qfailure",
    description="List service failure actions",
    group="Situational Awareness Commands"
)
class ObjectSCQFailureTask(SAServiceTaskBase):

    @staticmethod
    def arguments(parser):
        SAServiceTaskBase.common_args(parser, require_service=True)

    async def execute(self, args):
        hostname = args.hostname.strip() or ""
        service = args.service.strip()
        argv = bof_pack("zz", hostname, service)
        description = f"List failure actions for service '{service}' on host '{hostname or 'local'}'"
        return await self.execute_object(argv=argv, description=description)

@KnRegisterCommand(
    command="sc_qtriggerinfo",
    description="List service triggers",
    group="Situational Awareness Commands"
)
class ObjectSCQTriggerInfoTask(SAServiceTaskBase):

    @staticmethod
    def arguments(parser):
        SAServiceTaskBase.common_args(parser, require_service=True)

    async def execute(self, args):
        hostname = args.hostname.strip() or ""
        service = args.service.strip()
        argv = bof_pack("zz", hostname, service)
        description = f"List triggers for service '{service}' on host '{hostname or 'local'}'"
        return await self.execute_object(argv=argv, description=description)

@KnRegisterCommand(
    command="sc_enum",
    description="Enumerate all service configs in depth",
    group="Situational Awareness Commands"
)
class ObjectSCEnumTask(SAServiceTaskBase):

    @staticmethod
    def arguments(parser):
        parser.add_argument(
            "--hostname",
            type=str,
            default="",
            help="Optional target hostname (default = local machine)"
        )

    async def execute(self, args):
        hostname = args.hostname.strip() or ""
        argv = bof_pack("z", hostname)
        description = f"Enumerate all services on host '{hostname or 'local'}'"
        return await self.execute_object(argv=argv, description=description)


@KnRegisterCommand(
    command     = 'reg_query',
    description = 'query a registry key or value (optionally recursive)',
    group       = 'Situational Awareness Commands'
)
class ObjectRegQueryTask( SAObjectTaskBase ):

    RE_GHIVES = {
        "HKLM": 2,
        "HKCU": 1,
        "HKU":  3,
        "HKCR": 0,
    }

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "Usage:\n"
            "  reg_query <opt:hostname> <hive> <path> <opt:value> [--recursive]\n\n"
            "Hive must be one of:\n"
            "  HKLM, HKCU, HKU, HKCR\n\n"
            "If <value> is omitted, the key will be enumerated.\n"
            "If --recursive is specified, the key is queried recursively."
        )

        parser.add_argument(
            'arg1',
            type=str,
            help="hostname or hive"
        )

        parser.add_argument(
            'arg2',
            type=str,
            help="hive if arg1 is hostname, else path"
        )

        parser.add_argument(
            'arg3',
            type=str,
            nargs='?',
            default='',
            help="path or value depending on argument structure"
        )

        parser.add_argument(
            'arg4',
            type=str,
            nargs='?',
            default='',
            help="optional registry value name"
        )

        parser.add_argument(
            '--recursive',
            action='store_true',
            help="query the key recursively"
        )

    async def execute( self, args ):

        if args.arg1.upper() in self.RE_GHIVES:
            hostname = None
            hive_str = args.arg1.upper()
            path     = args.arg2
            key      = args.arg3
        else:
            hostname = "\\\\" + args.arg1
            hive_str = args.arg2.upper()
            path     = args.arg3
            key      = args.arg4

        if hive_str not in self.RE_GHIVES:
            raise ValueError(f"Invalid hive '{hive_str}', must be one of: HKLM, HKCU, HKU, HKCR")

        hive = self.RE_GHIVES[hive_str]

        if hostname:
            description = f"query registry: host={hostname}, hive={hive_str}, path={path}, value={key}, recursive={args.recursive}"
        else:
            description = f"query local registry: hive={hive_str}, path={path}, value={key}, recursive={args.recursive}"

        argv = bof_pack(
            'zizzi',
            hostname,
            hive,
            path,
            key,
            1 if args.recursive else 0
        )

        return await self.execute_object(
            argv        = argv,
            description = description
        )
    

@KnRegisterCommand(
    command     = 'wmi_query',
    description = 'run a general WMI query on a local or remote system',
    group       = 'Situational Awareness Commands'
)
class ObjectWmiQueryTask( SAObjectTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "Arguments:\n"
            "  query      - WQL query string\n"
            "  system     - optional remote system; omit or use '.' for local\n"
            "  namespace  - optional namespace (default: root\\cimv2)\n\n"
            "Examples:\n"
            "  wmi_query \"SELECT * FROM Win32_ComputerSystem\"\n"
            "  wmi_query \"SELECT * FROM Win32_Process\" SERVER01\n"
            "  wmi_query \"SELECT * FROM Win32_Service\" SERVER01 root\\cimv2"
        )

        parser.add_argument(
            'query',
            type=str,
            help='the WQL query to execute'
        )

        parser.add_argument(
            'system',
            type=str,
            nargs='?',
            default='.',
            help='optional remote system'
        )

        parser.add_argument(
            'namespace',
            type=str,
            nargs='?',
            default='root\\cimv2',
            help='optional WMI namespace'
        )

        parser.add_argument(
            '--raw-csv',
            action = 'store_true',
            help   = 'print the raw csv without processing it'
        )

    async def execute( self, args ):

        query     = args.query
        system    = args.system if args.system != '' else '.'
        namespace = args.namespace if args.namespace != '' else 'root\\cimv2'
        resource  = f"\\\\{system}\\{namespace}"

        description = (
            f"run WMI query '{query}' on "
            f"{'local system' if system == '.' else system} "
            f"in namespace {namespace}"
        )

        argv = bof_pack(
            'ZZZZ',
            system,
            namespace,
            query,
            resource
        )

        if not args.raw_csv:
            self.capture_output = True

        return await self.execute_object(
            argv        = argv,
            description = description
        )
    
    # NOTE: it is possible to capture the output and format it into a "pretty" table (please disable 'Console Wrap Text' in the client GUI) 
    #
    def process_output( self, output, task_id ):
        self.log_info( 'received wmi query output:', task_id = task_id )
        self.log_raw( '<br>' + self.format_csv_table( output.decode() ) + '<br>', is_html = True, task_id = task_id )
    
    def format_csv_table( self, csv_text: str ) -> str:
        html_output = []
        html_space = '&nbsp;'

        reader = list( csv.reader( StringIO( csv_text ) ) )

        if not reader:
            return HcTheme.console().foreground( 'No data available', bold = True )

        headers = reader[ 0  ]
        rows    = reader[ 1: ] 

        col_widths = [ len( h ) for h in headers ]

        for row in rows:
            if len( row ) > len( col_widths ):
                col_widths.extend( [ 0 ] * ( len( row ) - len( col_widths ) ) )
            for i, col in enumerate(row):
                col_widths[ i ] = max( col_widths[ i ], len( col ) )

        header_line = ''
        for i, h in enumerate( headers ):
            header_line += f'{h:<{col_widths[ i ]}}  '
        html_output.append( HcTheme.console().foreground( header_line.replace( ' ', html_space ), bold = True ) )

        divider_line = ''
        for w in col_widths:
            divider_line += f'{"-" * w}  '
        html_output.append( HcTheme.console().foreground( divider_line.replace( ' ', html_space ) ) )

        for row in rows:
            row_line = ''
            for i, col in enumerate( row ):
                row_line += f'{col:<{col_widths[ i ]}}  '
            html_output.append( HcTheme.console().foreground( row_line.replace( ' ', html_space ) ) )

        return '<br>'.join( html_output )


@KnRegisterCommand(
    command     = 'get-netsession',
    description = 'list sessions on server',
    group       = 'Situational Awareness Commands'
)
class ObjectNetSessionTask(SAObjectTaskBase):

    @staticmethod
    def arguments(parser):
        parser.epilog = (
            "Examples:\n"
            "  netsession --computer SERVER01\n\n"
            "This command lists sessions on the specified server."
        )

        parser.add_argument(
            '--computer',
            type=str,
            default='',
            help='Target computer to list sessions from'
        )

    async def execute(self, args):
        hostname = args.computer if args.computer else ''
        description = f"Listing sessions on server '{hostname}'" if hostname else "Listing sessions on local server"

        return await self.execute_object(
            argv        = bof_pack('Z', hostname),
            description = description
        )


@KnRegisterCommand(
    command     = 'get-netsession2',
    description = 'list sessions on server. Output is compatible with bofhound',
    group       = 'Situational Awareness Commands'
)
class ObjectNetSession2Task(SAObjectTaskBase):

    @staticmethod
    def arguments(parser):
        parser.epilog = (
            "Usage:\n"
            "  netsession2 --computer SERVER01 --method 1 --dnsserver 8.8.8.8\n\n"
            "Resolution methods:\n"
            "  1 = DNS (Default)\n"
            "  2 = NetWkstaGetInfo\n\n"
            "Note: Output from this BOF is compatible with bofhound"
        )

        parser.add_argument(
            '--computer',
            type=str,
            default='',
            help='Target computer to list sessions from'
        )

        parser.add_argument(
            '--method',
            type=int,
            choices=[1, 2],
            default=1,
            help='Resolution method: 1=DNS, 2=NetWkstaGetInfo'
        )

        parser.add_argument(
            '--dnsserver',
            type=str,
            default='',
            help='Optional DNS server for resolution'
        )

    async def execute( self, args ):
        hostname  = args.computer
        method    = args.method
        dnsserver = args.dnsserver

        description = f"Listing sessions on server '{hostname}' using method {method}"
        if dnsserver:
            description += f" with DNS server {dnsserver}"

        return await self.execute_object(
            argv        = bof_pack( 'Zsz', hostname, method, dnsserver ),
            description = description
        )


@KnRegisterCommand(
    command     = 'enum_filter_driver',
    description = 'Lists filter drivers on the system',
    group       = 'Situational Awareness Commands'
)
class ObjectEnumFilterDriverTask(SAObjectTaskBase):

    @staticmethod
    def arguments(parser):
        parser.epilog = (
            "Usage:\n"
            "  enum_filter_driver --system SERVER01\n\n"
            "Summary:\n"
            "  This command displays a list of filter drivers installed on the system.\n"
            "  The results are returned in CSV format with the type, name, and altitude number.\n\n"
            "Note:\n"
            "  You must have a valid login token for the system specified if not local."
        )

        parser.add_argument(
            '--system',
            type=str,
            default='',
            help='Optional. Target system to enumerate filter drivers from'
        )

    async def execute(self, args):
        system = args.system if args.system else ''
        description = f"Retrieving list of filter drivers on system '{system}'" if system else "Retrieving list of filter drivers on local system"

        return await self.execute_object(
            argv        = bof_pack('z', system),
            description = description
        )
    

@KnRegisterCommand(
    command     = 'netuptime',
    description = 'Returns information about the boot time on the local (or a remote) machine',
    group       = 'Situational Awareness Commands'
)
class ObjectNetUptimeTask(SAObjectTaskBase):

    @staticmethod
    def arguments(parser):
        parser.epilog = (
            "Usage:\n"
            "  netuptime --computer SERVER01\n\n"
            "Summary:\n"
            "  Returns information about the boot time on the local or a remote machine."
        )

        parser.add_argument(
            '--computer',
            type=str,
            default='',
            help='Optional. Target computer to query boot time from'
        )

    async def execute(self, args):
        name        = args.computer if args.computer else ''
        description = f"Retrieving boot time for computer '{name}'" if name else "Retrieving boot time for local machine"

        return await self.execute_object(
            argv        = bof_pack('Zi', name, 0),
            description = description
        )
   

@KnRegisterCommand(
    command     = 'nettime',
    description = 'Returns information about the current time on a remote (or local) machine',
    group       = 'Situational Awareness Commands'
)
class ObjectNetTimeTask(SAObjectTaskBase):

    @staticmethod
    def arguments(parser):
        parser.epilog = (
            "Usage:\n"
            "  nettime --target SERVER01\n"
            "  nettime --target target.domain.local\n"
            "  nettime\n\n"
            "Summary:\n"
            "  Displays the current time on a remote host.\n"
            "  If no target is specified, the local system time is returned."
        )

        parser.add_argument(
            '--target',
            type=str,
            default='',
            help='Optional. Target computer to query current time from'
        )

    async def execute(self, args):
        name        = args.target if args.target else ''
        description = f"Retrieving current time for target '{name}'" if name else "Retrieving current time for local system"

        return await self.execute_object(
            argv        = bof_pack('Z', name),
            description = description
        )
    

@KnRegisterCommand(
    command     = 'regsession',
    description = 'Returns users logged on the local (or a remote) machine via the registry - administrative rights needed. Output is compatible with bofhound',
    group       = 'Situational Awareness Commands'
)
class ObjectRegSessionTask(SAObjectTaskBase):

    @staticmethod
    def arguments(parser):
        parser.epilog = (
            "Usage:\n"
            "  regsession --computer SERVER01\n"
            "  regsession --computer target.domain.local\n"
            "  regsession\n\n"
            "Note:\n"
            "  Output from this BOF is compatible with bofhound.\n"
            "  Administrative rights are required to query remote systems via the registry."
        )

        parser.add_argument(
            '--computer',
            type=str,
            default='',
            help='Optional. Target computer to query logged-on users from'
        )

    async def execute(self, args):
        name        = args.computer if args.computer else ''
        description = f"Retrieving registry session info for '{name}'" if name else "Retrieving registry session info for local system"

        return await self.execute_object(
            argv        = bof_pack('z', name),
            description = description
        )


@KnRegisterCommand(
    command     = 'get_session_info',
    description = 'Returns the auth package, logon server, and current session ID of the user you are operating as',
    group       = 'Situational Awareness Commands'
)
class ObjectGetSessionInfoTask(SAObjectTaskBase):

    @staticmethod
    def arguments(parser):
        parser.epilog = (
            "Usage:\n"
            "  get_session_info\n\n"
            "Summary:\n"
            "  Retrieves the authentication package, logon server, and session ID of the current user."
        )

    async def execute(self, args):
        description = "Retrieving current session information"

        return await self.execute_object(
            argv        = None,
            description = description
        )


@KnRegisterCommand(
    command     = 'sha256',
    description = 'Returns the SHA-256 hash of the selected file for integrity checks',
    group       = 'Situational Awareness Commands'
)
class ObjectSha256Task(SAObjectTaskBase):

    @staticmethod
    def arguments(parser):
        parser.epilog = (
            "Usage:\n"
            "  sha256 <filename>\n\n"
            "Summary:\n"
            "  Computes the SHA-256 hash of the specified file."
        )

        parser.add_argument(
            'filename',
            type=str,
            help='Path to the file to hash'
        )

    async def execute(self, args):
        filename    = args.filename
        description = f"Computing SHA-256 hash for file '{filename}'"

        return await self.execute_object(
            argv        = bof_pack('z', filename),
            description = description
        )


##
## Thses are just examples and documentation on how to fully use and ulize some features 
##

#
# NOTE: example on how to capture a object file output 
#       and process them further in process_output!
#  
# @KnRegisterCommand( command = 'cacls', description = 'list user permissions for the specified file' )
# class ObjectCaclsTask( SAObjectTaskBase ):    
#     def __init__(self, *args, **kwargs):
#         super().__init__(*args, **kwargs)
#         #
#         # allow us to capture the object file output for further processing! 
#         self.capture_output = True

#     @staticmethod
#     def arguments( parser ): 
#         parser.epilog = (
#             "example usage:\n"
#             "  cacls C:\\\\windows\\\\system32\\\\notepad.exe\n"
#             "  cacls C:\\\\windows\\\\system32\n"
#             "  cacls C:\\\\windows\\\\system32\\\\*"
#         )
#         parser.add_argument( 'PATH', type=str, help="path to list user permissions" )
#     async def execute( self, args ):
#         return await self.execute_object( self.agent().to_unicode( args.PATH ), description = f'list user permissions for {args.PATH}' )

#     def process_output( self, output: str ):
#         self.log_success( f'successfully captured output of {self.command()}: ' )
#         self.log_raw( output.decode() )
#         return