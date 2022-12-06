package Text::Password::SHA;
our $VERSION = "0.16";

use Moo;
use Types::Standard qw(Int);
use constant Min => 4;

extends 'Text::Password::MD5';
has default => ( is => 'rw', isa => Int->where('$_ >= 10'), default => sub {10} );
use Carp;
use autouse 'Digest::SHA' => qw(sha1_hex);

use Crypt::Passwd::XS;

=encoding utf-8

=head1 NAME

Text::Password::SHA - generate and verify Password with SHA

=head1 SYNOPSIS

 my $pwd = Text::Password::SHA->new();
 my( $raw, $hash ) = $pwd->genarate();          # list context is required
 my $input = $req->body_parameters->{passwd};
 my $data = $pwd->encrypt($input);              # salt is made automatically
 my $flag = $pwd->verify( $input, $data );

=head1 DESCRIPTION

Text::Password::SHA is the part of Text::Password::AutoMigration.

=head2 Constructor and initialization

=head3 new()

No arguments are required. But you can set some parameters.

=over

=item default(I<Int>)

You can set default length with param 'default' like below:

 $pwd = Text::Pasword::AutoMiglation->new( default => 8 );

=item readablity(I<Bool>)

Or you can set default strength for password with param 'readablity'.

It must be a boolean, default is 1.

If it was set as 0, you can generate stronger passwords with generate().

$pwd = Text::Pasword::AutoMiglation->new( readability => 0 );

=back

=head2 Methods and Subroutines

=head3 verify( $raw, $hash )

returns true if the verification succeeds.

=cut

sub verify {
    my $self = shift;
    my $m    = $self->default;
    my ( $input, $data ) = @_;
    croak "Empty data strings" unless length $data;

    return $data eq Crypt::Passwd::XS::unix_sha512_crypt( $input, $data )
        if $data =~ /^\$6\$[!-~]{1,$m}\$[!-~]{86}$/;
    return $data eq Crypt::Passwd::XS::unix_sha256_crypt( $input, $data )
        if $data =~ /^\$5\$([!-~]{1,$m})\$[!-~]{43}$/;

    return $data eq sha1_hex($input) if $data =~ /^[0-9a-f]{40}$/i;
    return 0;
}

=head3 nonce(I<Int>)

generates the random strings with enough strength.

the length defaults to 10 || $self->default().

=head3 encrypt(I<Str>)

returns hash with unix_sha512_crypt().

salt will be made automatically.

=cut

sub encrypt {
    my $self  = shift;
    my $input = shift;
    croak ref($self) . " requires at least " . Min . " length" if length $input < Min;
    croak ref($self) . " doesn't allow any Wide Characters or white spaces\n" if $input =~ /[^ -~]/;
    return Crypt::Passwd::XS::unix_sha512_crypt( $input, $self->nonce );
}

1;

__END__

=head3 generate(I<Int>)

genarates pair of new password and it's hash.

less readable characters(0Oo1Il|!2Zz5sS$6b9qCcKkUuVvWwXx.,:;~-^'"`) are forbidden
unless $self->readability is 0.

the length defaults to 10 || $self->default().

=head1 LICENSE

Copyright (C) Yuki Yoshida(worthmine).

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 AUTHOR

Yuki Yoshida E<lt>worthmine@users.noreply.github.comE<gt>
