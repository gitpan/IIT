# Tests the IIT::Auth module

use Test::More;

plan tests => 8;

# Test 1: Try to load it
#BEGIN{
my $loaded = use_ok('IIT::Auth');
#}
$ENV{REMOTE_ADDR}='192.0.0.1'; # To keep CGI::Session::Secure happy
#Tests 2-7: Try to create a new session
SKIP:{
	skip "Environment variables 'AUTH_USERNAME', 'AUTH_PASSWORD', 'AUTH_SERVER' not set or module not loaded", 7
		unless (defined $ENV{AUTH_USERNAME} and defined $ENV{AUTH_PASSWORD} and defined $ENV{AUTH_SERVER} and $loaded);
	my $username = $ENV{AUTH_USERNAME};
	my $password = $ENV{AUTH_PASSWORD};
	my $server = $ENV{AUTH_SERVER};

	my $auth = new IIT::Auth (
		Username => $username,
		Password => $password,
		AuthServers => [$server]);
	# Test 2: The object was created
	my $continue = isa_ok($auth, 'IIT::Auth', '2 - check new object');

	SKIP: {
		skip "Cannot continue since Test 2 failed", 6 unless ($continue && $auth->status);
		my $session_id;
		
		# Test 3: Get the session id
		ok ($session_id = $auth->auth_id, '3 - check id');

		# Test 4: Get the hidden field
		my $hidden_field = '<input type="hidden" name="iitauthid" value="'.$session_id.'"/>';
		ok ($hidden_field eq $auth->auth_field, '4 - check hidden field');

		my $newAuth = new IIT::Auth (
			AuthID => $session_id
		);
		
		# Test 5: Create a new session
		isa_ok ($newAuth, 'IIT::Auth', '5 - check second object');

		# Test 6: Compare the session id
		ok ($session_id eq $newAuth->auth_id, '6 - compare session ids');

		# Test 7: Compare username
		ok ($username eq $newAuth->username, '7 - compare usernames');
		
		# Test 8: Logout
		ok ($newAuth->logout, '8 - logout');
	}
}



		


