use strict;
use warnings;

use Test::More tests => 7;

use_ok 'Text::Password::AutoMigration';               # 1
my $pwd = new_ok('Text::Password::AutoMigration');    # 2

my $m = $pwd->default;

my @ok = qw( fail ok );
my ( $raw, $hash, $flag );

( $raw, $hash ) = $pwd->generate();

note( 'generated hash strings with CORE::Crypt is ' . $hash );

subtest 'verify with CORE::Crypt 100 times' => sub {    # 3
    plan tests => 100;
    foreach ( 1 .. 100 ) {
        $flag = $pwd->verify( $raw, $hash );
        like $flag, qr|^\$6\$[!-~]{1,$m}\$[\w/\.]{86}$|, "verify: " . $ok[ defined $flag ];

    }
};

( $raw, $hash ) = $pwd->generate();

note( 'generated hash strings with MD5 is ' . $hash );

subtest 'verify with MD5 100 times' => sub {    # 4
    plan tests => 100;
    foreach ( 1 .. 100 ) {
        $flag = $pwd->verify( $raw, $hash );
        like $flag, qr|^\$6\$[!-~]{1,$m}\$[\w/\.]{86}$|, "verify: " . $ok[ defined $flag ];

    }
};

( $raw, $hash ) = $pwd->generate();
note( 'generated hash strings with SHA512 is ' . $hash );

subtest 'verify with SHA512 100 times' => sub {    # 5
    plan tests => 200;
    foreach ( 1 .. 100 ) {
        $flag = $pwd->verify( $raw, $hash );
        like $flag, qr|^\$6\$[!-~]{1,$m}\$[\w/\.]{86}$|, "verify: " . $ok[ defined $flag ];    # 5.1
        isnt $flag, $hash, "succeed to make new hash from same password";                      # 5.2

    }
};

my $longer = 16;
$pwd->default($longer);

( $raw, $hash ) = $pwd->generate();
is length($raw), $longer, "succeed to generate raw password with $longer length";    # 6

$pwd->migrate(0);                                                                    # force to return Boolean with verify()

$flag = $pwd->verify( $raw, $hash );
is $flag, 1, "verify: " . $ok[$flag];                                                # 7

done_testing;
