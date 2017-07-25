use strict;
use warnings;

use Test::More;

use lib 'lib';

use Text::Password::SHA;
my $passwd = Text::Password::SHA->new();

my ( $raw, $hash ) = $passwd->generate();
like $raw, qr/^[!-~]{8}$/, "generated raw passwd: $raw";
unlike $raw, qr/[0Oo1Il|!2Zz5sS\$6b9qCcKkUuVvWwXx.,:;~\-^'"`]/, "is readable: $raw";
like $hash, qr/^[!-~]+$/, "generated hash: $hash";
is ($passwd->verify( $raw, $hash ), 1, "verified: $raw" );

done_testing;
