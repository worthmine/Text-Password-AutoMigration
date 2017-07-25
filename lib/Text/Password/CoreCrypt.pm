package Text::Password::CoreCrypt;
our $VERSION = "0.01";

use 5.008001;
use Moose;  # this module is NOT based on Moose but it need to succeed
__PACKAGE__->meta->make_immutable;
no Moose;

use Carp;
my @ascii = ( '!' .. '/', 0 .. 9, ':' .. '@', 'A'..'Z', '[' .. '`', 'a'..'z', '{' .. '~' );
our ( $Min, $Default ) = ( 4, 8 );	# minimum and default length which is allowed as a Password

=encoding utf-8

=head1 NAME

Text::Password::CoreCrypt - generate and verify Password with perl CORE::crypt()

=head1 SYNOPSIS

 my $pwd = Text::Password::CoreCrypt->new();
 my( $raw, $hash ) = $pwd->genarate();          # list context is required
 my $input = $req->body_parameters->{passwd};
 my $data = $pwd->encrypt($input);              # salt is made automatically
 my $flag = $pwd->verify( $input, $data );

=head1 DESCRIPTION

Text::Password::CoreCrypt is base module for Text::Password::AutoMigration.

B<DON'T USE> directly.

=head2 Constructor and initialization

=head3 new()

no arguments are required

=head2 Methods and Subroutines

=over

=item verify( $raw, $hash )

returns true if the verify is success

=cut

sub verify {
    my $self = shift;
    my ( $input, $data ) = @_;
    die __PACKAGE__. " doesn't allow any Wide Characters or white spaces\n"
    if $input !~ /[!-~]/ or $input =~ /\s/;
    croak "CORE::crypt makes 13bytes hash strings. Your data must be wrong."
    if $data !~ /^[!-~]{13}$/;

    return $data eq CORE::crypt( $input, $data );
}

=item nonce($length)

generate the strings with enough strength

default length is 8

=cut

sub nonce {
    my $self = shift;
    my $length = shift || 8;
    croak "unvalid length for nonce was set" unless $length =~ /^\d+$/ and $length >= 4;

    my $n;
    do {	# redo unless it gets enough strength
        $n = '';
        $n .= $ascii[ rand @ascii ] until length $n >= $length;
    }while( $n =~ /^\w+$/ or $n =~ /^\W+$/ or $n !~ /\d/ or $n !~ /[A-Z]/ or $n !~ /[a-z]/ );

    return $n;
}

=item encrypt($raw)

returns hash with CORE::crypt

salt will be made automatically

=cut

sub encrypt {
    my $self = shift;
    my $input = shift;
    croak __PACKAGE__ ." requires at least $Min length" if length $input < $Min;
    die __PACKAGE__. " doesn't allow any Wide Characters or white spaces\n"
    if $input !~ /[!-~]/ or $input =~ /\s/;
    carp __PACKAGE__ . " ignores the password with over 8bytes" unless $input =~ /^[!-~]{8}$/;

    my $salt = '';
    $salt .= $ascii[ rand @ascii ] until length $salt == 2;

    return CORE::crypt( $input, $salt );
}

=item generate($length)

genarates pair of new password and it's hash

not much readable characters(0Oo1Il|!2Zz5sS\$6b9qCcKkUuVvWwXx.,:;~\-^'"`) are fallen

default lebgth is 8

=back

=cut

sub generate {
    my $self = shift;
    my $length = shift || $Default;
    croak "unvalid length was set" unless $length =~ /^\d+$/;
    croak ref($self) . "::generate requires list context" unless wantarray;
    croak ref($self) . "::generate requires at least $Min length" if $length < $Min;

    my $raw;
    do {	# redo unless it gets enough readability
        $raw = $self->nonce($length);
    }while( $raw =~ /[0Oo1Il|!2Zz5sS\$6b9qCcKkUuVvWwXx.,:;~\-^'"`]/i );

    return $raw, $self->encrypt($raw);
}

1;

__END__

=head1 LICENSE

Copyright (C) Yuki Yoshida(worthmine).

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 AUTHOR

Yuki Yoshida(worthmine) E<lt>worthmine@gmail.comE<gt>
