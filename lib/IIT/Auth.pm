package IIT::Auth;
########################################### main pod documentation begin ##
# Documentation for IIT::Auth
=pod

=head1 NAME

IIT::Auth - A Simple IIT Authentication Module

=head1 SYNOPSIS


  use IIT::Auth;
  
  # Create new IIT::Auth object and log a user in using the supplied
  # $username and $password.
  my $auth = new IIT::Auth (Username => $username,  # Username
                            Password => $password,  # Password
                            SessionDir => '/tmp');  # Session Directory

  # Get the session id
  my $authid = $auth->auth_id;

  # Open an existing session using a $knownid
  my $auth = new IIT::Auth (AuthID => $knownid,
                            SessionDir => '/tmp');  # Session Directory

  # Get the session id as a hidden form field
  my $auth_field = $auth->auth_field;

  # Get the current user's username
  my $username = $auth->username;

  # Get the auth status. Returns 1 for a valid login and 0 for
  # invalid login. This is here for future development.
  my $status = $auth->status;


=head1 DESCRIPTION


This module can be used in conjunction with a POP3 server to authenticate
users. 

To create a new authenticated session, the module must be provided
I<at least> a username and a password. Once a user has been sucessfully
authenticated with the POP3 server, his or her credentials are saved to
a file on the server. The contents of this file are encrypted (this is
done via the L<CGI::Session::Secure|CGI::Session::Secure> module). A unique
authenticated session id is generated for this session.

To activate an existing session the module must be provided a I<valid>
session id (previously authenticated). The module will reload the saved
session using this session id.

=head1 PREREQUISITS


The IIT::Auth module requires the following modules to function correctly:

=over 4

=item *

L<CGI::Session::Secure|CGI::Session::Secure> - To create secure persistent sessions

=item *

L<Net::POP3|Net::POP3> - To connect and authenticate against a POP3 server

=back

B<Note>: At the time that this documentation was completed, the module 
L<CGI::Session::Secure|CGI::Session::Secure> was not a standard CPAN module.
It should be downloaded from the author of this module.

=cut

use CGI::Session::Secure;
use strict;
use vars qw($VERSION $errstr);
$VERSION = '0.2';

=pod

=head1 METHODS

=head2 Public Methods

These methods are open to be used by the programmer.

=over 4

=item B<C<new(%options)>>

The IIT::Auth constructor may be called with the following arguments:

=over 2

=item AuthID

This is an existing authenticated session id. It can be retrieved using
the C<L<auth_id>> method. This id will be used to open an existing session
that has been saved on the server. This argument will override the 
B<L<Username|Username>> and B<L<Password|Password>> arguments if they are
provided.

=item Username

The username to be used for authentication. The username is I<NOT> an email
address. In most cases it will be what is I<before> the '@' in an email
address.

=item Password

The password corresponding to the above B<L<Username|Username>>.

=item SessionDir (Optional)

This is the directory where the sessions will be saved. This argument is 
passed as the B<Directory> argument to the 
L<CGI::Session::Secure|CGI::Session::Secure> module. It defaults to the
system's temporary directory.

=item AuthType (Options)

This is the type of the person being authenticated. It may be either one of
the strings 'Staff', 'Student' or 'Both'. Internally, these strings 
correspond to the pop3 server against which the user is to be authenticated.
This value defaults to 'Both'.

=item AuthServers (Option)

A reference to a list of pop3 servers against which authentication should be
attempted. If B<L<AuthType|AuthType>> is provided, then the servers 
corresponding to the specified type will be appended to this list.

=back

=cut
sub new
{
	my $this = shift;
	my %options = @_;
	my $class = ref($this) || $this;
	my $self={};
	bless $self, $class;
	
	my %valid_types = ('Student' => 1,'Staff' => 1);		# Valid Types
	my %valid_servers = ('Student' => ['student.iit.edu'],
						 'Staff' => ['email.iit.edu'],
						 'Both' => ['student.iit.edu',
									'email.iit.edu'] );		# Valid Servers

	$self->{_authid} = $options{'AuthID'} || undef;			# Default authid
	$self->{_servers} = [];
	$self->{_directory} = $options{'SessionDir'} || '/tmp'; # Default directory
	$self->{_type} = (defined $options{'AuthType'} &&
		defined$valid_types{$options{'AuthType'}}) ? 
		$options{'AuthType'} : 'Both';	# try both by default

	push (@{$self->{_servers}}, @{$options{'AuthServers'}})
		if (defined $options{'AuthServers'});

	push (@{$self->{_servers}}, @{$valid_servers{$self->{_type}}})
		if (defined $options{'AuthType'} || !defined $options{'AuthServers'});

	
	$self->{_status} = 0;	# Is not logged in

	if (defined $self->{_authid}) {
		$self->_initold() || return $self;
	}else{
		$self->_initnew(%options) || return $self;
	}
	$self->{_status} = 1;
	return $self;
}

=pod

=item B<C<username>>

This method returns the username of the currently authenticated user. This
value is saved to the authenticated session and can be retrieved when a 
session is activated using the B<L<AuthID|AuthID>>.

  my $username = $auth->username;

=cut
sub username
{
	my $self = shift;
	$self->status and return $self->{_username};
}

=pod

=item B<C<originator>>

This method is I<experimental>. It returns the name of the program that
created the session. It will not change once a session has been created.

  my $program = $auth->originator;

=cut

sub originator
{
	my $self = shift;
	$self->status and return $self->{_originator};
}

=pod

=item B<C<auth_field>>

This method returns a hidden field to be included in an HTML form. This 
field holds the authenticated session id and can be used to retrieve a 
previously authenticated session.

  my $hidden_field = $auth->auth_field;

=cut

sub auth_field
{
	my $self = shift;
	my $_authid = $self->{_authid};
	$self->status and return '<input type="hidden" name="iitauthid" value="'.$_authid.'"/>';
}

=pod

=item B<C<auth_id>>

This method returns the authenticated session id.

  my $authid = $auth->auth_id;

=cut

sub auth_id
{
	my $self = shift;
	$self->status and return $self->{_authid};
}

=pod

=item B<C<status>>

This method returns the current login status. A true (1) value indicates
that the session is valid. A false (0) values indicates that the session is
invalid.

  my $status = $auth->status;

=cut

sub status
{
	my $self = shift;
	return $self->{_status};
}

=pod

=item B<C<logout>>

This method logs the current user out. This involves deleting the session
file and resetting the status.

  $auth->logout;

=back

=cut


sub logout
{
	my $self = shift;
	# Remove the session file and reset status;
	my $_session = new CGI::Session::Secure ($self->{_authid}, {Directory => $self->{_directory}});
	$_session->delete;
	$self->{_status}=0;
	return !$self->status; # Just to make sure...
}



=pod

=head2 Private Methods

These methods should I<NOT> be used by your program. They are for internal
use by the module

=over 4

=item B<C<_initnew>>

Initializes a new session and creates a new session id.

=cut

sub _initnew
{
	my $self = shift;
	my %options = @_;
	my $_username = $options{'Username'};
	my $_password = $options{'Password'};
	my $_success = 0;
	my $_session = new CGI::Session::Secure ($self->{_authid}, {Directory => $self->{_directory}});
	$_username =~ s/^(\w+)\@*.*$/$1/;	# Strip everything after the '@' sign
	$_session->expires('15m');
	
	return if (length($_username)==0);
	return if (length($_password)==0);
	$self->{_username} = $_username;
	$_session->param('user.username', $_username);
	$self->{_originator} = 'debug';
	$_session->param('user.originator', 'debug');
	$self->{_authid} = $_session->id();

	# Since username and password are given, let's try to connect to a server.
	use Net::POP3;		# Load it only if i need it
	foreach my $server (@{$self->{_servers}}){
		my $pop = Net::POP3->new($server, Timeout => 10) || next;
		$pop->login($_username, $_password) || next;
		return $self;
	}
	$errstr = 'Could not authenticate user';
	return;
}

=pod

=item B<C<_initold>>

Initializes an old authenticated session.

=back

=cut
sub _initold
{
	my $self = shift;
	my $_session = new CGI::Session::Secure ($self->{_authid}, {Directory => $self->{_directory}});
	if (!defined $_session->param('user.username') ||
		!defined $_session->param('user.originator')) {
		# Not a valid user so do it the traditional way...
		$errstr = 'Could not find a user matching the provided session id';
		return undef;
	}
	$_session->expires('15m');
	$self->{_username} = $_session->param('user.username');
	$self->{_originator} = $_session->param('user.originator');
	$self->{_authid} = $_session->id();
	return $self;
}

sub DESTROY{
	return 1;
}
=pod

=head1 BUGS

None to report so far..

=head1 AUTHOR

	Prasad Ullal
	CPAN ID: None yet
	prasad.ullal@iit.edu

=head1 COPYRIGHT

Copyright (c) 2002 Prasad Ullal. All rights reserved.
This program is free software; you can redistribute
it and/or modify it under the same terms as Perl itself.

The full text of the license can be found in the
LICENSE file included with this module.

=head1 SEE ALSO

L<CGI::Session::Secure|CGI::Session::Secure>, L<Net::POP3|Net::POP3>

=cut

1; #this line is important and will help the module return a true value
__END__


