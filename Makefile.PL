use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME         => 'IIT',
    VERSION      => '0.1',
    AUTHOR       => 'Prasad Ullal (prasad.ullal@iit.edu)',
    ABSTRACT     => 'A Simple IIT Authentication Module',
	CONFIGURE	 => sub {
	print <<_MESSAGE_;
IIT Modules:

Some test scripts require environment variables to be set. Please provide
values for the following varialbes:

AUTH_USERNAME: Username to use for the tests.
AUTH_PASSWORD: Password for the above username.
AUTH_SERVER: POP3 server against which to authenticate the above username
    password.

_MESSAGE_
	return {};},
    PREREQ_PM	 => {
		'Net::POP3' => 0,
		'CGI::Session::Secure'	=> 0
		}
);

