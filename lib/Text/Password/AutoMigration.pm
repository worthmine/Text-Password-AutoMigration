package Text::Password::AutoMigration;
our $VERSION = "0.01";

use 5.008001;
use Moose;
__PACKAGE__->meta->make_immutable;
no Moose;

use Carp;
use Digest::SHA qw( sha1_hex sha1_base64 sha256_base64 );
use Crypt::PasswdMD5;

my @ascii = ( '!' .. '/', 0 .. 9, ':' .. '@', 'A'..'Z', '[' .. '`', 'a'..'z', '{' .. '~' );


our ( $Min, $Default ) = ( 4, 8 );	# minimum and default length allowed as a Password

sub verify {
    my $class = shift;
    my ( $input, $data ) = @_;
     die __PACKAGE__. " doesn't allow any Wide Characters or white spaces\n"
    if $input !~ /[!-~]/ or $input =~ /\s/;

    return $data eq unix_md5_crypt( $input, $data ) if $data =~ m/^\$1\$/; with MD5
    return $data eq CORE::crypt( $input, $data ); # with crypt in Perl
}

sub nonce {
    my $class = shift;
    my $length = shift || 8;
    my $n;
    do {	# redo unless it gets enough strength
        $n = '';
        $n .= $ascii[ rand @ascii ] until length $n >= $length;
    }while( $n =~ /^\w+$/ or $n =~ /^\W+$/ or $n !~ /\d/ or $n !~ /[A-Z]/ or $n !~ /[a-z]/ );

    return $n;
}

sub encrypt {
    my $class = shift;
    my $input = shift;
    croak __PACKAGE__ ." requires at least $Min length" if length $input < $Min;
     die __PACKAGE__. " doesn't allow any Wide Characters or white spaces\n"
    if $input !~ /[!-~]/ or $input =~ /\s/;

    my $salt = shift || $class->nonce();
    carp "warning: short lengths salt is set. you don't have to." if length($salt) < 8;
    carp "warning: too many string lengths for salt. unix_md5_crypt() ignores more than 8." if $salt and length($salt) > 8;

    return unix_md5_crypt( $input, $salt );
}

sub generate {
    my $class = shift;
    my $length = shift || $Default;
    croak "unvalid length is set" if $length !~ /^\d+$/;

    croak __PACKAGE__ ."::generate requires list context" unless wantarray;
    croak __PACKAGE__ ."::generate requires at least $Min length" if $length < $Min;

    my $raw;
    do {	# redo unless it gets enough readability
        $raw = $class->nonce($length);
    }while( $raw =~ /[0Oo1Il|!2Zz5sS\$6b9qCcKkUuVvWwXx.,:;~\-^'"`]/ );


        return $raw, __PACKAGE__->encrypt($raw);
}

1;

__END__

=head1 NAME

 Password - unix_md5_crypt()によるパスワードの作成と認証の簡素化。

 =head1 VERSION

 This document refers to version 3.00 of Password, released May 31, 2013

 =head1 SYNOPSIS

 my( $pass, $cripted ) = generate Password(6);	# 新規作成

 my $input = $cgi->param('pass');				# フォームから読み取り
 my $data = Password->encrypt($input);			# 暗号強度の高いsaltを自動生成して暗号化
 my $flag = Password->verify( $input, $data );	# 認証

 =head1 DESCRIPTION

 =head2 Overview

 OOPライクな呼び出しに対応したパスワードの作成と認証の一元化。
 暗号化と認証はcrypt（認証のみ）とMD5によって実装。

 my( $pass, $encript ) = generate Password(6);	# セマンティクスな呼び出し
 my( $pass, $encript ) = Password->generate(6);	# OOPな呼び出し

 どちらも可能ですが
 B<オブジェクトを作りません。>
 これは継続してblessすべき適当なデータが見つからないためです。

 =head2 Constructor and initialization

 There is no constructor.

 =head2 Methods and Subroutines

 =over

 =item new B<（注：コンストラクタではありません。）>
 same as generate( is B<NOT> a constructor )

 =item generate
 新しいパスワードを作らせます。
 my( $pass, $cripted ) = generate Password(6);	# または Password->generate(6);

 指定長のランダム文字列を生成して暗号化文字列と共に返します。
 人間が誤読しやすい文字(0Oo1Il2Zz5sS6b9qCcKkUuVvWwXx.,:;~^'"{}[])を含まないように自動的に処理します。
 指定長の省略時は$Password::Defaultを使います。（変えなければ8）

 =item encrypt

 指定文字列を暗号化して返します。
 saltは暗号強度の高い文字列を自動生成して使用します。
 my $data = encrypt Password($input);		# または Password->encrypt($input);

 =item verify

 暗号認証して真偽値を返します。
 my $flag = verify Password( $input, $data );	# または Password->verify( $input, $data );

 =back

 =head1 SEE ALSO

 オブジェクト指向Perlマスターコース - ダミアン・コンウェイ pp187-190
 http://www.amazon.co.jp/exec/obidos/ASIN/4894713004/
 
 =head1 Copyright
 
 Copyright (c) since 2005, Yuki Yoshida All rights reserved.
 
 This Module is free software.
 It may be used, redistributed and/or modified under the same terms as Perl itself.


1;
__END__

=encoding utf-8

=head1 NAME

Text::Password::AutoMigration - It's new $module

=head1 SYNOPSIS

    use Text::Password::AutoMigration;

=head1 DESCRIPTION

Text::Password::AutoMigration is ...

=head1 LICENSE

Copyright (C) Yuki Yoshida.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 AUTHOR

Yuki Yoshida E<lt>worthmine@gmail.comE<gt>

=cut

