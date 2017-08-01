# NAME

Text::Password::SHA - generate and verify Password with SHA

# SYNOPSIS

    my $pwd = Text::Password::SHA->new();
    my( $raw, $hash ) = $pwd->genarate();          # list context is required
    my $input = $req->body_parameters->{passwd};
    my $data = $pwd->encrypt($input);              # salt is made automatically
    my $flag = $pwd->verify( $input, $data );

# DESCRIPTION

Text::Password::SHA is the part of Text::Password::AutoMigration.

## Constructor and initialization

### new()

no arguments are required

## Methods and Subroutines

- verify( $raw, $hash )

    returns true if the verify is success

- nonce($length)

    generate the strings with enough strength

    default length is 8

- encrypt($raw)

    returns hash with CORE::crypt

    salt will be made automatically

- generate($length)

    genarates pair of new password and it's hash

    not much readable characters(0Oo1Il|!2Zz5sS\\$6b9qCcKkUuVvWwXx.,:;~\\-^'"\`) are fallen

    default lebgth is 8

# LICENSE

Copyright (C) Yuki Yoshida(worthmine).

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

# AUTHOR

Yuki Yoshida(worthmine) <worthmine@gmail.com>
