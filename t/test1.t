#!/usr/bin/perl

use Test::More tests => 15;

BEGIN { use_ok( 'Authen::Users' ); }

my @db_avail = ('SQLite', 'MySQL');

my $db_name = 'authen_test';
unlink $db_name if -e $db_name;

    # Test if we have Mysql
    SKIP:
    {
	    eval "require DBD::MySQL;";
        skip "No DBD::MySQL", 7 if $@;
        my $auth = new Authen::Users( dbtype => 'MySQL', 
        	dbname => $db_name, dbuser => 'user', dbpass => 'password', 
        	create => 1 );
		isa_ok ($auth, 'Authen::Users');
        ok($auth->add_user('test', 'user', 'pw', 'My User', 'user@sql.org', 'my dog?', 'Fido'),
        	"Add user");
        ok($auth->add_user('test', 'user2', 'pw2', 'My User', 'user@sql.org', 'my dog?', 'Fido'),
        	"Add second user");
        ok($auth->authenticate('test', 'user', 'pw'), "Authenticate user");
        ok($auth->count_group('test') == 2, 'Count group');
        ok($auth->delete_user('test', 'user2'), 'Delete user');
        ok($auth->count_group('test') == 1, 'Count group after delete');
    }
    
    # test SQLite also
    SKIP:
    {
	    eval "require DBD::SQLite;";
        skip "No DBD::SQLite", 8 if $@;
        my $auth = new Authen::Users( dbtype => 'SQLite', 
        	dbname => $db_name, create => 1 );
		isa_ok ($auth, 'Authen::Users');
        ok($auth->add_user('test', 'user', 'pw', 'My User', 'user@sql.org', 'my dog?', 'Fido'),
        	"Add user");
        ok($auth->add_user('test', 'user2', 'pwd2', 'My User', 'user@sql.org', 'my dog?', 'Fido'),
        	"Add second user");
        ok($auth->authenticate('test', 'user', 'pw'), "Authenticate user");
        ok($auth->count_group('test') == 2, 'Count group');
        ok($auth->delete_user('test', 'user2'), 'Delete user');
        ok($auth->count_group('test') == 1, 'Count group after delete');
    }
