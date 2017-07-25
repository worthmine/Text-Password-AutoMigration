use strict;
use warnings;

use Test::More tests => 5;

use lib 'lib';

use Text::Password::CoreCrypt;
my $passwd = Text::Password::CoreCrypt->new();

my @ok = qw( fail ok );
my ( $raw, $hash, $flag );

my $nonce = $passwd->nonce();
like $nonce, qr/^[!-~]{8}$/, "make nonce automatically: $nonce";        # 1

$nonce = $passwd->nonce(4);
like $nonce, qr/^[!-~]{4}$/, "make nonce manually: $nonce";             # 2

subtest "generate with CORE::crypt" => sub {                            # 3
    plan tests => 4;
    ( $raw, $hash ) = $passwd->generate();
    like $raw, qr/^[!-~]{8}$/, "generated raw passwd: $raw";
    unlike $raw, qr/[0Oo1Il|!2Zz5sS\$6b9qCcKkUuVvWwXx.,:;~\-^'"`]/, "$raw is readable";
    like $hash, qr/^[!-~]{13}$/, "generated hash: $hash";
    $flag = $passwd->verify( $raw, $hash );
    is $flag, 1, "verify: " . $ok[$flag];

};

eval{ $passwd->verify( $raw, '$1$l1PMyqG!$mNPUHQnly7oLJjt/jb/m/.' ) };
like $@, qr/^CORE::crypt makes 13bytes hash strings. Your data must be wrong./i,
    "catch the error with invalid strings";                             # 4

( $raw, $hash ) = eval{ $passwd->generate(3) };
like $@ , qr/^Text::Password::CoreCrypt::generate requires at least 4 length/i, "fail to make too short password";                                                # 5

done_testing();
