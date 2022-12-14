[![Build Status](https://travis-ci.org/worthmine/Text-Password-AutoMigration.svg?branch=main)](https://travis-ci.org/worthmine/Text-Password-AutoMigration)
# NAME

Text::Password::AutoMigration - generate and verify Password with any contexts

# SYNOPSIS

    my $pwd = Text::Password::AutoMigration->new();
    my( $raw, $hash ) = $pwd->generate();          # list context is required
    my $input = $req->body_parameters->{passwd};
    my $data = $pwd->encrypt($input);              # you don't have to care about salt
    my $flag = $pwd->verify( $input, $data );

# DESCRIPTION

Text::Password::AutoMigration is a module for some lasy Administrators.

It would help you to migrate old hash what has vulnerability
such as encrypted by perl, MD5, SHA-1 or even if it was with SHA-256 to SHA-512.

The method _verify()_  automatically detects the algorithm which is applied to the hash
with **CORE::crypt**, **MD5**, **SHA-1 by hex**, **SHA-256** and of course **SHA-512**.

And every _verify()_ **returns a brand new hash** generated by using **with SHA-512**.

Therefore all you have to do is to replace the old hash with the new one on your Databases.

## Constructor and initialization

### new()

No arguments are required. But you can set some parameters.

- default( _Int_ )

    You can set default length with using 'default' argument like below:

        $pwd = Text::Pasword::AutoMiglation->new( default => 8 );

    It must be an Int, defaults to 10.

- readablity( _Bool_ )

    You can set default strength for password with usnig 'readablity' argument like below:

        $pwd = Text::Pasword::AutoMiglation->new( readability => 0 );

    It must be a Boolean, defaults to 1.

    If it was false, _generate()_ starts to return stronger passwords with charactors hard to read.

- migrate( _Bool_ )

    It must be a Boolean, defaults to 1.

    If you've already replaced all hash or started to make new applications with this module,

    you can call the constructor with _migrate =< 0_.

    Then _verify()_ would not return a new hash but always 1.

    It may help you a little faster without any change of your code.

## Methods and Subroutines

### verify( $raw, $hash )

To tell the truth, this is the most useful method of this module.

it Returns a true strings instead of boolean if the verification succeeds.

Every value is **brand new hash from SHA-512** because it is true anyway.

So you can replace hash in your Database easily like below:

    my $pwd = Text::Password::AutoMigration->new();
    my $dbh = DBI->connect(...);
    my $db_hash_ref = $dbh->fetchrow_hashref(...);

    my $param = $req->body_parameters;
    my $hash = $pwd->verify( $param->{passwd}, $db_hash_ref->{passwd} );
    if ($hash) { # you don't have to execute this every time
       my $sth = $dbh->prepare('UPDATE DB SET passwd=? WHERE uid =?') or die $dbh->errstr;
       $sth->excute( $hash, $param->{uid} ) or die $sth->errstr;
    }

New hash length is at least 100 if length of nonce . So you have to change your DB like below:

    ALTER TABLE User CHANGE passwd passwd VARCHAR(100);

### nonce( _Int_ )

generates the random strings with enough strength.

the length defaults to 10 or $self->default().

### encrypt( _Str_ )

returns hash with unix\_sha512\_crypt().

salt will be made automatically.

### generate( _Int_ )

generates pair of new password and its hash.

less readable characters(0Oo1Il|!2Zz5sS$6b9qCcKkUuVvWwXx.,:;~-^'"\`) are forbidden
unless $self->readability is 0.

the length defaults to 10 || $self->default().

**DON'T TRUST** this method.

According to [Password expert says he was wrong](https://www.usatoday.com/story/news/nation-now/2017/08/09/password-expert-says-he-wrong-numbers-capital-letters-and-symbols-useless/552013001/),
it's not a safe way. So, I will rewrite this method as soon as I find the better way.

# SEE ALSO

- [GitHub](https://github.com/worthmine/Text-Password-AutoMigration)
- [CPAN](http://search.cpan.org/perldoc?Text%3A%3APassword%3A%3AAutoMigration)
- [https://shattered.io/](https://shattered.io/)

# LICENSE

Copyright (C) Yuki Yoshida(worthmine).

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

# AUTHOR

Yuki Yoshida <worthmine@users.noreply.github.com>
