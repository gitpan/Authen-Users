package Authen::Users;

require 5.004;

use strict;
use warnings;
use Carp;
use vars qw($VERSION);
$VERSION = '0.02';
use DBI;
use Digest::SHA1 qw(sha1_base64);

=head1 NAME

Authen::Users

=head1 DESCRIPTION

General password authentication using DBI-capable databases. Currently supports
MySQL and SQLite databases.

Default is to use a SQLite database to store and access user information. 

This module is not an authentication protocol. For that see something such as
Authen::AuthenDBI.

=head1 SYNOPSIS

use Authen::Users qw(:SQLite);

my $authen = new Athen::Users(dbtype => 'SQLite', dbname => 'mydbname');

my $a_ok = $authen->authenticate($group, $user, $password);

my $result = $authen->add_user(
	$group, $user, $password, $fullname, $email, $question, $answer);

=head1 METHODS

=over 4

=item B<new>

Create a new Authen::Users object:

my $authen = new Authen::Users( { dbtype => 'SQLite', dbname => 'authen.db', create => 1,
	authen_table => 'authen_table' } );

or,

my $authen = new Authen::Users( dbtype => 'MySQL', dbname => 'authen.db', 
	dbpass => 'myPW', authen_table => 'authen_table', 
	dbhost => 'mysql.server.org' );

Takes a hash of arguments:

=over 4

=item B<dbtype>

The type of database. Currently supports 'SQLite' and 'MySQL'. Defaults to SQLite.

=item B<dbname>

The name of the database. Required for all database types.

=item B<authen_table>

The name of the table containing the user data. 

NOTE: If this is omitted, defaults to a table called 'authentication' in the
database. If the argument 'create' is passed with a true value, and the 
authen_table argument is omitted, then a new empty table called 'authentication' 
will be created in the database. 

The SQL compatible table is currently as follows:

groop VARCHAR(15)        Group of the user
user VARCHAR(30)         User name
password VARCHAR(60)     Password, as SHA1 digest
fullname VARCHAR(40)     Full name of user
email VARCHAR(40)        User email
question VARCHAR(120)    Challenge question
answer VARCHAR(80)       Challenge answer
creation VARCHAR(12)     Internal use: row insertion timestamp
modified VARCHAR(12)     Internal use: row modification timestamp
gukey VARCHAR (46)		 Internal use: key made of user and group--kept unique

For convenience, the database has fields to store for each user an email address
and a question and answer for user verification if a password is lost.

=item B<create>

If true in value, causes the named authen_table to be created if it was not 
already present when the database was opened.

=item B<dbpass>

The password for the account. Not used by SQLite. Generally needed otherwise.

=item B<dbhost>

The name of the host for the database. Not used by SQLite. Needed if the database
is hosted on a remote server.

=back

=cut

sub new {
	my ($proto, %args) = @_;
	my $class = ref($proto) || $proto;
	my $self = {};
	bless ($self, $class);    
	foreach( qw( dbtype dbname create dbuser dbpass dbhost authen_table ) ) {
		if($args{$_}) { $self->{$_} = $args{$_} }
	}
	$self->{dbname} or croak "Cannot set up Auth::Users without a dbname: $self->{dbname}.";
	$self->{dbtype} = 'SQLite' unless $self->{dbtype};
	$self->{authentication} =  $self->{authen_table} || 'authentication';
	$self->{sqlparams} = { PrintError => 0, RaiseError => 1, AutoCommit => 1 };
	if($self->{dbtype} =~ /^MySQL/i) {
		# MySQL
		$self->{dsn} = "dbi:mysql:$self->{dbname}";
    	$self->{dsn} .= ";host=$self->{dbhost}" if $self->{dbhost};
		$self->{dbh} = DBI->connect($self->{dsn}, $self->{dbuser},
			$self->{dbpass}, $self->{sqlparams})
			or croak "Can't connect to MySQL database as $self->{dsn} with " .
				"user $self->{dbuser} and given password and $self->{sqlparams}: " .
				 DBI->errstr;
	}
	else { 
		# SQLite is the default
		$self->{dsn} = "dbi:SQLite:dbname=$self->{dbname}";
		$self->{dbh} = DBI->connect($self->{dsn}, $self->{sqlparams})
			or croak "Can't connect to SQLite database as $self->{dsn} with " .
				"$self->{sqlparams}: " . DBI->errstr;	
	}
	# check if table exists
	my $sth_tab = $self->{dbh}->table_info('', '', '%', '');
	my $need_table = 1;
print "sth_tab is", $sth_tab->rows, "\n";
	while(my $tbl = $sth_tab->fetchrow_hashref) {
		$need_table = 0 if $tbl->{TABLE_NAME} eq $self->{authentication};
	}
	if($need_table) {
		# try to create the table
		#carp "Had to create the table";
		my $ok_create = $self->{dbh}->do(<<ST_H);
CREATE TABLE $self->{authentication} 
( groop VARCHAR(15), user VARCHAR(30), password VARCHAR(60), 
fullname VARCHAR(40), email VARCHAR(40), question VARCHAR(120),
answer VARCHAR(80), created VARCHAR(12), modified VARCHAR(12), 
gukey VARCHAR (46) UNIQUE )
ST_H
		carp("Could not make table") unless $ok_create;
	}
	return $self;
}

=item B<authenticate>

Authenticate a user. Users may have the same user name as long as they are not 
also in the same authentication group. Therefore, the user's group should be 
included in all calls to authenticate the user by password. Passwords are
stored as SHA1 digests, so the authentication is of the digests.

=cut

sub authenticate {
	my($self, $group, $user, $password) = @_;
	my $password_sth = $self->{dbh}->prepare(<<ST_H);
SELECT password FROM $self->{authentication} WHERE groop = ? AND user = ? 
ST_H
	$password_sth->execute($group, $user);
	my $stored_pw_digest = $password_sth->fetchrow_arrayref->[0];
	my $user_pw_digest = sha1_base64($password);
	return ($user_pw_digest eq $stored_pw_digest) ? 1 : 0;
}

=item B<add_user>

Add a user to the database.

The arguments are as follows:

$authen->add_user($group, $user, $password, $fullname, $email, $question, $answer);

=over 4

=item B<group>
Scalar. The group of users. Used to classify authorizations, etc. 
User names may be the same if the groups are different, but in any given group 
the users must have unique names.

=item B<user>

Scalar. User name.

=item B<password>

Scalar. SHA1 digest of user's password.

=item B<fullname>

Scalar. The user's 'real' or full name.

=item B<email>

Scalar. User's email address.

=item B<question>

Scalar. A question used, for example,  for identifying the user if they lose their password.

=item B<answer>

Scalar. The correct answer to $question.

=back

Note: it is up to the user of the module to determine how the fields after group, user, and 
password fields are used, or if they are used at all.

=cut 
	
sub add_user {
	my($self, $group, $user, $password, $fullname, $email, $question, $answer) = @_;
	$self->not_in_table($group, $user) or return;
	my $insert_sth = $self->{dbh}->prepare(<<ST_H);
INSERT INTO $self->{authentication} 
(groop, user, password, fullname, email, question, answer, created, modified, gukey)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) 
ST_H
	my $t = time;
	my $r = $insert_sth->execute( $group, $user, sha1_base64($password),	
		$fullname, $email, $question, $answer, $t, $t, g_u_key($group, $user) );
	return ( $r and $r == 1 ) ? 1 : 0;
}

=item <update_user_all>

Update all fields for a given group and user:

$authen->update_user_all($group, $user, $password, $fullname, $email, $question, $answer)
	or die "Could not update $user: " . $authen->errstr();

=cut

sub update_user_all {
	my($self, $group, $user, $password, $fullname, $email, $question, $answer) = @_;
	my $update_all_sth = $self->{dbh}->prepare(<<ST_H);
UPDATE $self->{authentication} SET password = ?, fullname = ?, 
email = ?, question = ?, answer = ? , modified = ?, gukey = ?
WHERE groop = ? AND user = ? 
ST_H
	my $t = time;
	return ( $update_all_sth->execute( sha1_base64( $password), $fullname, 
		$email, $question, $answer, $t, $group, $user, g_u_key($group, $user) ) 
		? 1 : 0 );
}

=item B<update_user_password>

$authen->update_user_password($group, $user, $password) 
	or die "Cannot update password for group $group and user $user: $authen->errstr";

Update the password. 

=cut

sub update_user_password {
	my($self, $group, $user, $password) = @_;
	my $update_pw_sth = $self->{dbh}->prepare(<<ST_H);
UPDATE $self->{authentication} SET password = ?, modified = ?,
WHERE groop = ? AND user = ? 
ST_H
	my $t = time;
	return ( $update_pw_sth->execute( 
		sha1_base64($password),	$t, $group, $user) ? 1 : 0 );
}

=item B<update_user_fullname>

$authen->update_user_fullname($group, $user, $fullname) 
	or die "Cannot update fullname for group $group and user $user: $authen->errstr";

Update the full name. 

=cut

sub update_user_fullname {
	my($self, $group, $user, $fullname) = @_;
	my $update_fullname_sth = $self->{dbh}->prepare(<<ST_H);
UPDATE $self->{authentication} SET fullname = ?, modified = ?,
WHERE groop = ? AND user = ? 
ST_H
	my $t = time;
	return ( $update_fullname_sth->execute($fullname, $t, $group, $user) 
		? 1 : 0 );
}

=item B<update_user_email>

$authen->update_user_email($group, $user, $email) 
	or die "Cannot update email for group $group and user $user: $authen->errstr";

Update the email address. 

=cut

sub update_user_email {
	my($self, $group, $user, $email) = @_;
	my $update_email_sth = $self->{dbh}->prepare(<<ST_H);
UPDATE $self->{authentication} SET email = ? , modified = ?,
WHERE groop = ? AND user = ? 
ST_H
	my $t = time;	
	return ( $update_email_sth->execute($email,	$t, $group, $user) ? 1 : 0 );
}

=item B<update_user_question_answer>

$authen->update_user_question_answer($group, $user, $question, $answer) 
	or die "Cannot update question and answer for group $group and user $user: $authen->errstr";

Update the challenge question and its answer. 

=cut

sub update_user_question_answer {
	my($self, $group, $user, $question, $answer) = @_;
	my $update_additional_sth = $self->{dbh}->prepare(<<ST_H);
UPDATE $self->{authentication} SET question = ?, answer = ? , 
modified = ? WHERE groop = ? AND user = ? 
ST_H
	my $t = time;
	return ( $update_additional_sth->execute($question, $answer, $t, $group, $user)
		? 1 : 0 );
}

=item B<delete_user>

$authen->delete_user($group, $user) 
	or die "Cannot delete user in group $group with username $user: $authen->errstr";

Delete the user entry. 

=cut

sub delete_user {
	my($self, $group, $user) = @_;
	my $delete_sth = $self->{dbh}->prepare(<<ST_H);
DELETE FROM $self->{authentication} WHERE groop = ? AND user = ? 
ST_H
	return ( $delete_sth->execute( $group, $user ) ? 1 : 0 );	
}

=item B<count_group>

$authen->count_group($group) 
	or die "Cannot count group $group: $authen->errstr";

Return the number of entries in group $group. 

=cut

sub count_group {
	my ($self, $group) = @_;
	my $count_sth = $self->{dbh}->prepare(<<ST_H);
SELECT COUNT(password) FROM $self->{authentication} WHERE groop = ? 
ST_H
	$count_sth->execute($group);
	my $nrows = $count_sth->fetchrow_arrayref->[0];
print "rows: ", $nrows, "\n";
	$nrows = 0 if $nrows < 0;
	return $nrows;
}

=item B<get_group_members>

$authen->get_group_members($group) 
	or die "Cannot retrieve list of group $group: $authen->errstr";

Return a reference to a list of the user members of group $group. 

=cut

sub get_group_members {
	my ($self, $group) = @_;
	my($row, @members);
	my $members_sth = $self->{dbh}->prepare(<<ST_H);
SELECT user FROM $self->{authentication} WHERE groop = ? 
ST_H
	$members_sth->execute( $group );
	while($row = $members_sth->fetch) { push @members, $row->[0] }
	return \@members;
}

=item B<user_info>

$authen->user_info($group, $user) 
	or die "Cannot retrieve information about $user in group $group: $authen->errstr";

Return a reference to a list of the information about $user in $group. 

=cut

sub user_info {
	# returns an arrayref: 
	# [groop, user, password, fullname, email, question, answer, created, modified]
	my($self, $group, $user) = @_;
	my $user_sth = $self->{dbh}->prepare(<<ST_H);
SELECT * FROM $self->{authentication} WHERE groop = ? AND user = ? 
ST_H
	$user_sth->execute( $group, $user );
	return $user_sth->fetch;
}

=item B<user_info_hashref>

my $href = $authen->user_info_hashref($group, $user) 
	or die "Cannot retrieve information about $user in group $group: $authen->errstr";
print "The email for $user in $group is $href->{email}";

Return a reference to a hash of the information about $user in $group, with the field 
names as keys of the hash.

=cut

sub user_info_hashref {
	# returns a hashref: 
	# {groop => $group, user => $user, password => $password, etc. }
	my($self, $group, $user) = @_;
	my $user_sth = $self->{dbh}->prepare(<<ST_H);
SELECT * FROM $self->{authentication} WHERE groop = ? AND user = ? 
ST_H
	$user_sth->execute( $group, $user );
	return $user_sth->fetchrow_hashref;
}

=item B<get_user_fullname>

$authen->get_user_fullname($group, $user) 
	or die "Cannot retrieve full name of $user in group $group: $authen->errstr";

Return the user full name entry. 

=cut

sub get_user_fullname {
	my($self, $group, $user) = @_;
	my $row = $self->user_info($group, $user);
	if($row) { return $row->[3] } else { return }
}

=item B<get_user_email>

$authen->get_user_email($group, $user) 
	or die "Cannot retrieve email of $user in group $group: $authen->errstr";

Return the user email entry. 

=cut

sub get_user_email {
	my($self, $group, $user) = @_;
	my $row = $self->user_info($group, $user);
	if($row) { return $row->[4] } else { return }
}

=item B<get_user_question_answer>

$authen->get_user_question_answer($group, $user) 
	or die "Cannot retrieve question and answer for $user in group $group: $authen->errstr";

Return the user question and answer entries. 

=cut

sub get_user_question_answer {
	my($self, $group, $user) = @_;
	my $row = $self->user_info($group, $user);
	if($row) { return ($row->[5], $row->[6]) } else { return }
}

=item B<errstr>

Returns the last database error, if any.

=cut

sub errstr {
	my $self = shift;
	return $self->{dbh}->errstr;
}

# assistance functions

sub not_in_table {
	my($self, $group, $user) = @_;
	my $unique_sth = $self->{dbh}->prepare(<<ST_H);
SELECT password FROM $self->{authentication} WHERE gukey = ? 
ST_H
	$unique_sth->execute(g_u_key($group, $user));
	my @row = $unique_sth->fetchrow_array;
	return (@row) ? 0 : 1;
}

sub is_in_table {
	my($self, $group, $user) = @_;
	return $self->not_in_table($group, $user) ? 0 : 1;
}
# internal use--not for objects

sub g_u_key {
	my($group, $user) = @_;
	return $group . '|' . $user;
}

=back

=head1 AUTHOR

William Herrera (wherrera@skylightview.com)

=head1 SUPPORT

Questions, feature requests and bug reports should go to wherrera@skylightview.com

=head1 COPYRIGHT

     Copyright (C) 2004 William Hererra.  All Rights Reserved.

This module is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut


1;
