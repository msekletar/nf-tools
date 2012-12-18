# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Net-IP-LPM.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test::More tests => 3;
BEGIN { use_ok('Net::IP::LPM') };

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

my $lpm = Net::IP::LPM->new();

isa_ok($lpm, 'Net::IP::LPM', 'Constructor');

# list of prefixes to test
my @prefixes = ( 
		'0.0.0.0/0', 
		'147.229.3.1', '147.229.3.2/32', '147.229.3.0/24', '147.229.0.0/16',
		'::/0',
		'2001:67c:1220:f565::1234', '2001:67c:1220:f565::1235/128', 
		'2001:67c:1220:f565::/64', '2001:67c:1220::/32'
		);


foreach (@prefixes) {
	$lpm->add($_, $_);
}

$lpm->rebuild();

#use DB_File;
#my $x = $lpm->{DB};
#my $value = undef;
#my $key = undef;
#for ($st = $x->seq($key, $value, R_FIRST) ; $st == 0 ; $st = $x->seq($key, $value, R_NEXT) ) {
#    diag sprintf "%s  -> $value\n", unpack("H*", $key);
#}

my %tests = ( 
		'147.229.3.0'	=> '147.229.3.0/24',
		'147.229.3.1'	=> '147.229.3.1',
		'147.229.3.2'	=> '147.229.3.2/32',
		'147.229.3.3'	=> '147.229.3.0/24',
		'147.229.3.10'	=> '147.229.3.0/24',
		'147.229.3.254'	=> '147.229.3.0/24',
		'147.229.3.255'	=> '147.229.3.0/24',
		'147.229.4.0'	=> '147.229.0.0/16',
		'147.229.4.1'	=> '147.229.0.0/16',
		'147.228.255.255'	=> '0.0.0.0/0',
		'147.229.0.0'	=> '147.229.0.0/16',
		'147.229.255.255'	=> '147.229.0.0/16',
		'147.230.0.0'	=> '0.0.0.0/0',
		'147.230.0.1'	=> '0.0.0.0/0',
		'0.0.0.0'		=> '0.0.0.0/0',
		'0.0.0.1'		=> '0.0.0.0/0',
		'255.255.255.254'	=> '0.0.0.0/0',
		'255.255.255.255'	=> '0.0.0.0/0',
		'2001:67c:1220::1'			=> '2001:67c:1220::/32',
		'2001:67c:1220:f565::1234'	=> '2001:67c:1220:f565::1234',
		'2001:67c:1220:f565::'		=> '2001:67c:1220:f565::/64',
		'2001:67c:1220:f565::1'		=> '2001:67c:1220:f565::/64',
		'2001:67c:1220:f565:FFFF:FFFF:FFFF:FFFF'	=> '2001:67c:1220:f565::/64',
		'2001:67c:1220:f566::'	=> '2001:67c:1220::/32',
		'2001:67c:1220:f566::1'	=> '2001:67c:1220::/32',
		'2001:67c:2325:f566::1'	=> '2001:67c:1220::/32',
		'2001:67b:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF'	=> '::/0',
		'2001:67d::1'			=> '::/0',
		'2001::1'				=> '::/0',
		'FFFF:FFFF:FFFF:FFF:FFFF:FFFF:FFFF:FFFF'	=> '::/0',
		'FFFF:FFFF:FFFF:FFF:FFFF:FFFF:FFFF:FFFE'	=> '::/0',
		'::0.0.0.0'	=> '0.0.0.0/0',
		'0001::'	=> '::/0',
		'2001::1'	=> '::/0',
		);

my %results = ();
diag "\n";
while ( my ($a, $p) = each %tests ) {
	my $res = $lpm->lookup($a);
	if ($p ne $res) {
		diag sprintf "FAIL %s \t-> \t%s =%s %s\n", $a, $p, $p eq $res ? '=' : '!', $res;
	}
	$results{$a} = $res;
}

# test speed 
my $cnt = 500000;
diag "Testing performance on full Internet BGP";
diag "tables ($cnt lookups on 500 000 prefixes)";
diag "please wait... ";
my $lpm2 = Net::IP::LPM->new("t/asns.db");
my $t1 = time();
for (my $x = 0; $x < $cnt; $x++ ) {
	my $a = $x % 250; 	
	my $addr = "$a.10.$a.20";
	my $val = $lpm2->lookup($addr);
}

my $t2 = time() - $t1;
diag sprintf "SPED: %d lookups in %d secs, %f.2 lookups/s", $cnt, $t2, $cnt/$t2;

ok( eq_hash(\%tests, \%results) );
