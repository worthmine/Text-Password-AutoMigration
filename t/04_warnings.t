use strict;
use warnings;

use Test::More tests => 3;

use Text::Password::AutoMigration;
my $pwd = Text::Password::AutoMigration->new;
my ( $raw, $hash ) = $pwd->generate;

is $pwd->verify( $raw, $pwd->nonce ), 0, "fail to verify with wrong hash";    # 1

local $SIG{__WARN__} = sub {
    like $_[0],

        qr/^Text::Password::AutoMigration doesn't allow any Wide Characters or white spaces/,
        "succeed to catch unvalid data.";                                     # 2

};
is $pwd->verify( $raw . "\n", $hash ), 0, "fail to verify with wrong hash";    # 3

done_testing;
