#!/usr/bin/perl

use Net::LDAP;

my $ldapBind="cn=users,ou=read,ou=Administration,o=sample";
my $ldapPass="";
my $ldapBase="ou=Users,o=sample";
my $fieldUser="uid";
my $fieldPass="userPassword";

use Unix::Syslog qw(:macros :subs);

sub ldap_connect {
do { sleep 2; $ldap = new Net::LDAP ( 'ldap://127.0.0.1', version=>3, verify=>'none') while not $ldap;
$ldap->bind ("$ldapBind", password => $ldapPass);
}

sub ldap_disconnect {
$ldap->unbind;
$ldap->disconnect;
}

ldap_connect;

while(1){
my $buf = "";
syslog LOG_INFO,"waiting for packet";
my $nread = sysread STDIN,$buf,2;
do { syslog LOG_INFO,"port closed"; exit; } unless $nread == 2;
my $len = unpack "n",$buf;
my $nread = sysread STDIN,$buf,$len;

my ($op,$user,$domain,$password) = split /:/,$buf;

# Filter dangerous characters
$user =~ s/[\n\r]//g;
$password =~ s/[\n\r]//g;
$domain =~ s/[\n\r]//g;

my $jid = "$user\@$domain";
my $result;
my $res;

syslog(LOG_INFO,"request (%s)", $op);
if (length $user > 128 or length $user > 128 or length $domain > 128){
my $out = pack "nn",2,0;
syswrite STDOUT,$out;
next;
}
SWITCH:
{
$op eq 'auth' and do
{
$res = $ldap->search (
base => "$ldapBase",
filter => "(&($fieldUser=$user)($fieldPass=$password)(accountStatus=active))"
);
$code=$res->code();
if($code != 0){
ldap_disconnect;
ldap_connect;
$res = $ldap->search (
base => "$ldapBase",
filter => "(&($fieldUser=$user)($fieldPass=$password)(accountStatus=active))"
);
}
$result = $res->count();
},last SWITCH;

$op eq 'setpass' and do
{
$result = 0;
},last SWITCH;
$op eq 'isuser' and do
{
# password is null. Return 1 if the user $user\@$domain exitst.
$result = 0;
$res = $ldap->search (
base => "$ldapBase",
filter => "($fieldUser=$user)"
);
$code=$res->code();
if($code != 0){
ldap_disconnect;
ldap_connect;
$res = $ldap->search (
base => "$ldapBase",
filter => "($fieldUser=$user)"
);
}
$result = $res->count();
#syslog(LOG_INFO,"ejabberd_mysql_ext_auth: Executing is_user: %s",$orden);
},last SWITCH;
};
$result = 0 if $domain ne "sample";
my $out = pack "nn",2,$result ? 1 : 0;
syswrite STDOUT,$out;
}

ldap_disconnect;

closelog;
