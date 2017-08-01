requires 'perl', '5.008001';

on 'test' => sub {
    requires 'Test::More', '0.98';
};

requires 'Crypt::Passwd::XS', 0.601;
requires 'Crypt::PasswdMD5', 1.40;

