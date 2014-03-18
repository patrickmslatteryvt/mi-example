#!/usr/bin/perl

## This is an example of an 'auth-check' trigger used by Perforce (2005.2) to 
## authenticate a user against an Active Directory server.
##
## The password is sent to this trigger <stdin> with an argument list of
## host (hostname of ldap server), port (port of ldap server), domain, user
##
## e.g. ldap.mycompany.com 389 WIDGETCO joeb 
##
## The Perforce trigger definition would look something like this:
##
## example auth-check auth /p4/common/triggers/auth/p4auth_ad.pl wvt2012r2stdco.devdmz.mywebgrocer.com 389 DEVDMZ %user%
##

use strict;
use Net::LDAP;

## Perforce requires messages on stdout
##
open(STDERR, ">&STDOUT") or die "Can't dup stdout";

## check argument count
##
my $argc = scalar(@ARGV);

if( $argc != 4 ) {
    die "wrong number of arguments!\n";
}

## assign arguments
##
my $host = shift @ARGV;
my $port = shift @ARGV;
my $domain = shift @ARGV;
my $user = shift @ARGV;

## read the password from <stdin> and truncate the newline
##
my $password = <STDIN>;
$password =~ s/\n//;

## make a standard connection to Active Directory
##
my $ldap = Net::LDAP->new( $host, port => $port ) or die "$@";

## bind
##
my $result = $ldap->bind( "$domain\\$user", password => $password ) or die "$@";

## check result, report errors
##
if( $result->code ){
    die "LDAP bind failure!\n";
}
